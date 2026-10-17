using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using epoxide.utils;

namespace epoxide.tls;

/// <summary>
/// The read half when BoringSSL decrypts. Nothing runs in the background: a read decrypts whatever
/// ciphertext the connection has queued, and when that is not enough it parks on the connection and
/// decrypts what arrives. The connection therefore has a read armed only while the caller is
/// waiting, exactly as with <see cref="TcpConnectionPipeReader"/>.
///
/// That class is what a kTLS-RX connection uses - there the kernel has already decrypted, so
/// plaintext is in the connection's recv buffers and no owned buffer is needed at all. Here
/// plaintext does not exist in them, so it lands in a Pipe this owns, used purely as a buffer:
/// pooled segments and the consumed/examined bookkeeping a PipeReader owes its caller. The caller's
/// read IS that Pipe's read; this class only feeds it.
/// </summary>
/// <remarks>
/// Any thread, one reader at a time. The decrypt runs where the read does - on the caller's thread,
/// or where the connection completes a parked read, which is where the caller belongs - and the
/// caller resumes inline there. Disposal may come from another thread while a read is parked: the
/// buffer is ended under the session's lock, which every decrypt into it holds, so it never ends
/// in the middle of one.
/// </remarks>
public sealed class TlsDecryptingPipeReader : PipeReader, IAsyncDisposable
{
    private readonly TcpConnection _conn;
    private readonly TlsSession _session;
    private readonly Pipe _plain;

    // A parked connection read chains onto the connection's value-task source, as in
    // TcpConnectionPipeReader, so a read that waits allocates nothing.
    private ValueTaskAwaiter<RecvSnapshot> _pendingRecv;
    private readonly Action _onRecvReady;

    private bool _recvArmed;       // a connection read is parked with OnRecvReady behind it
    private bool _callerWaiting;   // the caller has a read on the buffer that nothing has completed yet
    private bool _ended;           // the buffer is complete: close_notify, a closed connection or a fault
    private bool _completed;       // the caller is done with this reader
    private bool _cancelRequested; // CancelPendingRead: the next read returns canceled

    public TlsDecryptingPipeReader(TcpConnection connection, TlsSession session)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _onRecvReady = OnRecvReady;

        // A buffer, not a channel: no pause threshold, because nothing is decrypted beyond what a
        // read asks for. Inline schedulers so the flush that delivers resumes the caller right
        // there, where its connection read completed - a Pipe defaults to PipeScheduler.ThreadPool,
        // which would move a caller off its reactor at the first read that waits.
        _plain = new Pipe(new PipeOptions(
            readerScheduler: PipeScheduler.Inline,
            writerScheduler: PipeScheduler.Inline,
            pauseWriterThreshold: 0,
            resumeWriterThreshold: 0,
            useSynchronizationContext: false));

        // The client's first request usually rides in with its Finished flight, so the handshake has
        // already decrypted it. Miss this and the first request is silently dropped, and the first
        // read waits for bytes that arrived before this reader existed.
        ReadOnlySpan<byte> initial = _session.DrainPlaintext();
        if (!initial.IsEmpty)
        {
            _plain.Writer.Write(initial);
            Publish();
        }
    }

    // The token is ignored, as on TcpConnectionPipeReader: honouring it would wake the caller on the
    // token's thread - a timer's - rather than where its read belongs.
    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (_cancelRequested)
        {
            _cancelRequested = false;
            _plain.Reader.CancelPendingRead();   // nothing is waiting, so the read below returns canceled
        }

        ValueTask<ReadResult> read = _plain.Reader.ReadAsync();

        // Everything decrypted so far has been examined: decrypt more. The read completes inside
        // the flush that delivers, which may already have happened by the time this returns.
        if (!read.IsCompleted)
        {
            _callerWaiting = true;
            Fill();
        }

        return read;
    }

    /// <remarks>
    /// Returns what has been decrypted already; like <see cref="TcpConnectionPipeReader"/>, it never
    /// takes anything off the connection.
    /// </remarks>
    public override bool TryRead(out ReadResult result) => _plain.Reader.TryRead(out result);

    public override void AdvanceTo(SequencePosition consumed) => _plain.Reader.AdvanceTo(consumed);

    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
        => _plain.Reader.AdvanceTo(consumed, examined);

    // Cancels the next read, never one already waiting, as on TcpConnectionPipeReader - so only the
    // connection's read ever wakes the caller, where it belongs.
    public override void CancelPendingRead() => _cancelRequested = true;

    public override void Complete(Exception? exception = null)
    {
        _completed = true;
        _plain.Reader.Complete(exception);
    }

    /// <summary>
    /// Ends the buffer, so a read still waiting on it sees the end of the stream. A connection read
    /// the caller left parked stays parked, and holds nothing: the handler letting go of the
    /// connection is what ends it, and the read then finds this reader done.
    /// </summary>
    /// <remarks>
    /// ioxide also marks the connection closed here, from its reactor thread, to release such a
    /// read. An epoxide connection whose handler has let go is drained and reaped by its reactor,
    /// parked read or not, and a closed mark is the reactor's to set - this may run on any thread.
    /// </remarks>
    public ValueTask DisposeAsync()
    {
        _completed = true;
        End(null);                   // a read still waiting on the buffer sees the end of the stream
        _plain.Reader.Complete();
        return default;
    }

    // The caller is waiting on the buffer: decrypt what the connection has queued, and while that
    // yields nothing - none queued, or half a record - park on the connection until it does.
    private void Fill()
    {
        while (!_recvArmed)
        {
            ValueTask<RecvSnapshot> recv = _conn.ReadAsync();

            if (!recv.IsCompletedSuccessfully)
            {
                _recvArmed = true;
                _pendingRecv = recv.GetAwaiter();
                _pendingRecv.UnsafeOnCompleted(_onRecvReady);
                return;
            }

            if (Ingest(recv.Result))
            {
                return;
            }
        }
    }

    // Completion of a parked connection read - inline on the reactor for a read armed there, and
    // where the caller came from otherwise (the connection decides).
    private void OnRecvReady()
    {
        _recvArmed = false;

        if (!Ingest(_pendingRecv.GetResult()) && _callerWaiting)
        {
            Fill();   // half a record: wait for the rest
        }
    }

    // Decrypt every buffer the snapshot carries into the buffer and publish it. Returns whether the
    // caller's read has been completed - by plaintext, by the end of the stream, or because nobody
    // is reading any more.
    //
    // A TLS fault ends the buffer WITH the exception, so every read from then on reports it:
    // completing cleanly would make a bad MAC or a truncated stream indistinguishable from the peer
    // hanging up politely, which is exactly what a truncation attack wants. close_notify is a clean
    // end of stream and a closed snapshot without one is the peer vanishing; both end it cleanly, and
    // the difference is left to the caller, which can still read TlsSession.Closed.
    private bool Ingest(in RecvSnapshot snapshot)
    {
        int produced = 0;
        Exception? fault = null;

        // End takes the same lock to set _ended, so a buffer ended from another thread is never
        // written into: the decrypt below either runs wholly before the end or not at all.
        lock (_session.Sync)
        {
            if (_ended || _completed)
            {
                return true;   // what is still queued goes back to the pool at recycle
            }

            try
            {
                produced = DecryptAvailable(snapshot, _plain.Writer);
            }
            catch (Exception e)
            {
                fault = e;
            }
        }

        // Outside the lock: publishing and ending resume the caller inline.
        if (fault is not null)
        {
            End(fault);
            return true;
        }

        bool closed = _session.Closed || snapshot.IsClosed;
        if (produced == 0 && !closed)
        {
            return false;
        }

        _callerWaiting = false;
        if (produced > 0)
        {
            Publish();
        }
        if (closed)
        {
            End(null);
        }
        return true;
    }

    // Make what was just decrypted readable. With no pause threshold this never waits, and on a
    // buffer another thread has just ended it is a no-op: the end committed these bytes.
    private void Publish()
    {
        ValueTask<FlushResult> flush = _plain.Writer.FlushAsync();
        Debug.Assert(flush.IsCompleted, "a buffer with no pause threshold flushed asynchronously");
        flush.GetAwaiter().GetResult();
    }

    private void End(Exception? fault)
    {
        lock (_session.Sync)
        {
            if (_ended)
            {
                return;
            }
            _ended = true;
        }

        _callerWaiting = false;
        _plain.Writer.Complete(fault);
    }

    // Decrypt every buffer this snapshot carries, straight into the buffer. Each one is returned to
    // the pool whatever happens: a decrypt that throws must not strand it.
    private unsafe int DecryptAvailable(in RecvSnapshot snapshot, PipeWriter writer)
    {
        int produced = 0;

        while (_conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            try
            {
                if (item.HasBuffer)
                {
                    produced += _session.DecryptInto(item.Ptr, item.Len, writer);
                }
            }
            finally
            {
                if (item.HasBuffer)
                {
                    _conn.ReturnBuffer(in item);
                }
            }
        }

        return produced;
    }
}
