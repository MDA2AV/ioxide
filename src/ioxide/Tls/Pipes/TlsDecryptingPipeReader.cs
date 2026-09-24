using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using ioxide.utils;

namespace ioxide.tls;

/// <summary>
/// The read half when OpenSSL decrypts. Nothing runs in the background: a read decrypts whatever
/// ciphertext the ring has queued for this connection, and when that is not enough it parks on the
/// connection and decrypts what arrives. The connection therefore has a read armed only while the
/// caller is waiting, exactly as with <see cref="TcpConnectionPipeReader"/>.
///
/// That class is what a kTLS-RX connection uses - there the kernel has already decrypted, so
/// plaintext is in ring memory and no owned buffer is needed at all. Here plaintext does not exist in
/// ring memory, so it lands in a Pipe this owns, used purely as a buffer: pooled segments and the
/// consumed/examined bookkeeping a PipeReader owes its caller. The caller's read IS that Pipe's
/// read; this class only feeds it.
/// </summary>
/// <remarks>Reactor thread only.</remarks>
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

    public TlsDecryptingPipeReader(TcpConnection connection, TlsSession session)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _onRecvReady = OnRecvReady;

        // A buffer, not a channel: no pause threshold, because nothing is decrypted beyond what a
        // read asks for, and nothing is decrypted anywhere but on the reactor. Inline schedulers so
        // the flush that delivers resumes the caller right there - a Pipe defaults to
        // PipeScheduler.ThreadPool, and with useSynchronizationContext:false that would hand the
        // connection to a pool thread nothing can post back from.
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

    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        ValueTask<ReadResult> read = _plain.Reader.ReadAsync(cancellationToken);

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

    // Completes a waiting read now, or the next one, with IsCanceled. A connection read it left
    // parked stays armed, and whatever that brings is kept for the next read.
    public override void CancelPendingRead()
    {
        _callerWaiting = false;
        _plain.Reader.CancelPendingRead();
    }

    public override void Complete(Exception? exception = null)
    {
        _completed = true;
        _plain.Reader.Complete(exception);
    }

    /// <summary>
    /// Ends the buffer and releases a connection read the caller left parked, if any - against a
    /// peer that stays quiet nothing else ever would. With no read parked the connection is left as
    /// it is: the handler letting go of it is what ends it.
    /// </summary>
    public ValueTask DisposeAsync()
    {
        _completed = true;
        End(null);                   // a read still waiting on the buffer sees the end of the stream
        _plain.Reader.Complete();

        if (_recvArmed)
        {
            _conn.MarkClosed();      // completes the parked read; OnRecvReady finds the reader done
        }

        return default;
    }

    // The caller is waiting on the buffer: decrypt what the ring has queued, and while that yields
    // nothing - none queued, or half a record - park on the connection until it does.
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

    // Completion of a parked connection read - runs inline on the reactor, inside the recv
    // completion that brought the bytes.
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
        if (_ended || _completed)
        {
            _conn.ResetRead();   // what is still queued goes back to the ring at recycle
            return true;
        }

        int produced;
        try
        {
            produced = DecryptAvailable(snapshot, _plain.Writer);
        }
        catch (Exception e)
        {
            _conn.ResetRead();
            End(e);
            return true;
        }

        // Before publishing: the caller resumes inline inside the flush and may read, and so arm the
        // connection, again straight away.
        _conn.ResetRead();

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

    // Make what was just decrypted readable. With no pause threshold this never waits.
    private void Publish()
    {
        ValueTask<FlushResult> flush = _plain.Writer.FlushAsync();
        Debug.Assert(flush.IsCompleted, "a buffer with no pause threshold flushed asynchronously");
        flush.GetAwaiter().GetResult();
    }

    private void End(Exception? fault)
    {
        if (_ended)
        {
            return;
        }

        _ended = true;
        _callerWaiting = false;
        _plain.Writer.Complete(fault);
    }

    // Decrypt every buffer this snapshot carries, straight into the buffer. Each one is returned to
    // the ring whatever happens: a decrypt that throws must not strand the kernel's buffer.
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
