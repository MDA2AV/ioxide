using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using ioxide.utils;

namespace ioxide.tls;

/// <summary>
/// The read half when BoringSSL decrypts. Nothing runs in the background: a read decrypts whatever
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
/// <remarks>A read from another thread takes what is already decrypted there; decrypting and disposal run on the connection's reactor.</remarks>
public sealed class TlsDecryptingPipeReader : PipeReader, IAsyncDisposable, IRecvListener
{
    private readonly TcpConnection _conn;
    private readonly TlsSession _session;
    private readonly Pipe _plain;

    // A read that waits parks this reader on the connection, as TcpConnectionPipeReader does, so it allocates nothing.
    private bool _recvArmed;       // a connection read is parked with OnRecvReady behind it
    private bool _ended;           // the buffer is complete: close_notify, a closed connection or a fault
    private bool _completed;       // the caller is done with this reader
    private bool _cancelRequested; // CancelPendingRead: the next read returns canceled

    public TlsDecryptingPipeReader(TcpConnection connection, TlsSession session)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _session = session ?? throw new ArgumentNullException(nameof(session));

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

    // The token is ignored, as on TcpConnectionPipeReader: it would wake the caller on the token's
    // thread, where disposing frees the session under a decrypt still running on the reactor.
    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (_cancelRequested)
        {
            _cancelRequested = false;
            _plain.Reader.CancelPendingRead();   // nothing is waiting, so the read below returns canceled
        }

        // On any thread: the Pipe takes its reader beside the reactor's writer.
        ValueTask<ReadResult> read = _plain.Reader.ReadAsync();

        // Everything decrypted so far has been examined: decrypt more. The read completes inside
        // the flush that delivers, which may already have happened by the time this returns.
        if (!read.IsCompleted)
        {
            if (!_conn.Reactor.OnReactorThread)
            {
                return FillOnReactor(read);
            }

            Fill();
        }

        return read;
    }

    // Decrypting is the reactor's: SSL_read must not overlap its SSL_write (#249), and the parked read is its own.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private async ValueTask<ReadResult> FillOnReactor(ValueTask<ReadResult> read)
    {
        await new ReactorSwitch(_conn.Reactor);

        if (!read.IsCompleted)
        {
            Fill();
        }

        return await read;
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
    // reactor ever wakes the caller.
    public override void CancelPendingRead() => _cancelRequested = true;

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
    public ValueTask DisposeAsync() => _conn.Reactor.OnReactorThread ? DisposeHere() : DisposeOnReactor();

    private ValueTask DisposeHere()
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

    [MethodImpl(MethodImplOptions.NoInlining)]
    private async ValueTask DisposeOnReactor()
    {
        try
        {
            await new ReactorSwitch(_conn.Reactor);
        }
        catch (ObjectDisposedException)
        {
            // The reactor has stopped, so nothing races the disposal: it goes on here.
        }
        await DisposeHere();
    }

    // The caller is waiting on the buffer: decrypt what the ring has queued, and while that yields
    // nothing - none queued, or half a record - park on the connection until it does.
    private void Fill()
    {
        while (!_recvArmed)
        {
            if (!_conn.TryReadOrPark(this, out RecvSnapshot snapshot))
            {
                return;
            }

            _recvArmed = false;   // served at once - also after OnParking, when a completion came while it ran

            if (Ingest(snapshot))
            {
                return;
            }
        }
    }

    // Set before the park is published: from then on the completion can run OnRecvReady before TryReadOrPark returns.
    void IRecvListener.OnParking() => _recvArmed = true;

    // Completion of a parked connection read - runs inline on the reactor, inside the recv
    // completion that brought the bytes.
    void IRecvListener.OnRecvReady(RecvSnapshot snapshot)
    {
        _recvArmed = false;

        if (!Ingest(snapshot))
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
            return true;   // what is still queued goes back to the ring at recycle
        }

        int produced;
        try
        {
            produced = DecryptAvailable(snapshot, _plain.Writer);
        }
        catch (Exception e)
        {
            End(e);
            return true;
        }

        bool closed = _session.Closed || snapshot.IsClosed;
        if (produced == 0 && !closed)
        {
            return false;
        }

        if (produced > 0)
        {
            Publish();
        }
        if (closed)
        {
            // An overflow dropped ciphertext: a truncation, so it ends the stream as an error.
            End(!_session.Closed && _conn.RecvOverflowed ? TcpConnection.RecvOverflowError() : null);
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
