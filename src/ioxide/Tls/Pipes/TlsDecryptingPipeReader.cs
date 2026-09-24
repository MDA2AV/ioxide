using System.Buffers;
using System.IO.Pipelines;
using ioxide.utils;

namespace ioxide.tls;

/// <summary>
/// The read half when OpenSSL decrypts: a pump reads ciphertext off the ring, decrypts into a Pipe
/// this owns, and the caller reads that Pipe.
///
/// The counterpart is <see cref="TcpConnectionPipeReader"/>, which is what a kTLS-RX connection
/// uses - there the kernel has already decrypted, so plaintext is in ring memory and no owned
/// buffer is needed at all. This class is the entire difference between the two worlds on the read
/// side.
///
/// Why a Pipe rather than decrypting in place: plaintext does not exist in ring memory, so the
/// zero-copy reader has nothing to hand out. It has to land somewhere ioxide owns, and the Pipe
/// supplies the destination, the backpressure and the consumed/examined bookkeeping.
/// </summary>
/// <remarks>Reactor thread only.</remarks>
public sealed class TlsDecryptingPipeReader : PipeReader, IAsyncDisposable
{
    private readonly TcpConnection _conn;
    private readonly TlsSession _session;
    private readonly Pipe _inbound;
    private readonly Task _pump;

    private bool _callerWaiting;   // parked on the pipe with nothing decrypted for it

    public TlsDecryptingPipeReader(TcpConnection connection, TlsSession session, PipeOptions? options = null)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _session = session ?? throw new ArgumentNullException(nameof(session));

        // Inline schedulers, so a read resumes on the thread that completed the write - the
        // reactor. A Pipe defaults to PipeScheduler.ThreadPool, and combined with
        // useSynchronizationContext:false that hands the connection to a pool thread with a NULL
        // SynchronizationContext, so nothing can post it back and the loop never returns. That is
        // why caller options contribute only their BUFFERING: the schedulers are not theirs to
        // choose, and honoring a PipeOptions built with the BCL defaults would wedge the connection.
        _inbound = new Pipe(options is null
            ? new PipeOptions(
                readerScheduler: PipeScheduler.Inline,
                writerScheduler: PipeScheduler.Inline,
                useSynchronizationContext: false)
            : new PipeOptions(
                pool: options.Pool,
                readerScheduler: PipeScheduler.Inline,
                writerScheduler: PipeScheduler.Inline,
                pauseWriterThreshold: options.PauseWriterThreshold,
                resumeWriterThreshold: options.ResumeWriterThreshold,
                minimumSegmentSize: options.MinimumSegmentSize,
                useSynchronizationContext: false));

        // The pump's read stays parked while the caller is busy, so the read clock runs only while
        // the caller waits. Before the pump starts: it parks its first read synchronously.
        _conn.SuspendReadTimeout();

        _pump = PumpInboundAsync();
    }

    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        ValueTask<ReadResult> read = _inbound.Reader.ReadAsync(cancellationToken);

        if (!read.IsCompleted && !_callerWaiting)
        {
            _callerWaiting = true;
            _conn.ResumeReadTimeout();
        }

        return read;
    }

    // Before the flush that delivers: the caller resumes inline inside it and may park again.
    private void CallerServed()
    {
        if (_callerWaiting)
        {
            _callerWaiting = false;
            _conn.SuspendReadTimeout();
        }
    }

    public override bool TryRead(out ReadResult result) => _inbound.Reader.TryRead(out result);

    public override void AdvanceTo(SequencePosition consumed) => _inbound.Reader.AdvanceTo(consumed);

    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
        => _inbound.Reader.AdvanceTo(consumed, examined);

    public override void CancelPendingRead()
    {
        CallerServed();
        _inbound.Reader.CancelPendingRead();
    }

    public override void Complete(Exception? exception = null) => _inbound.Reader.Complete(exception);

    /// <summary>
    /// Stops the pump and waits for it. This CLOSES the connection's I/O: a pump parked in
    /// <c>ReadAsync</c> has nothing else that will ever release it - the peer may stay open and
    /// quiet forever - so disposal marks the connection closed to wake it. Complete and flush the
    /// write side first; a flush after this point is a no-op.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        // Two ways a pump can be parked, and each needs its own release.
        //
        // Completing the reader releases one parked in the pipe's FlushAsync. Cancelling does NOT:
        // CancelPendingRead cancels a pending READ, and a writer held at the pause threshold is
        // waiting for the reader to consume, which only completion promises it never will. A
        // handler that stopped draining a large body and closed - an ordinary shape - parked the
        // pump there forever, so the await below never returned, the handler's DecRef never ran,
        // and the connection, its SSL and both BIOs were leaked for the life of the process.
        //
        // MarkClosed releases one parked in the connection's ReadAsync with a closed snapshot,
        // which is what a server-initiated close against a quiet peer needs.
        _inbound.Reader.Complete();
        _conn.MarkClosed();

        try
        {
            await _pump;
        }
        catch
        {
            // The pump reports faults through the pipe, so anything here is teardown noise.
        }
    }

    private async Task PumpInboundAsync()
    {
        PipeWriter writer = _inbound.Writer;
        Exception? failure = null;

        try
        {
            if (!await WriteHandshakePlaintextAsync(writer))
            {
                return;
            }

            while (true)
            {
                RecvSnapshot snapshot = await _conn.ReadAsync();
                int produced = DecryptAvailable(snapshot, writer);
                _conn.ResetRead();

                if (produced > 0)
                {
                    CallerServed();
                    FlushResult flush = await writer.FlushAsync();
                    if (flush.IsCompleted || flush.IsCanceled)
                    {
                        return;   // the reader is gone
                    }
                }

                // close_notify is a clean end of stream; a closed snapshot without one is the peer
                // vanishing. Both stop the pump, and the difference is left to the caller, which
                // can still read TlsSession.Closed.
                if (_session.Closed || snapshot.IsClosed)
                {
                    return;
                }
            }
        }
        catch (Exception e)
        {
            // Deliberately kept, not swallowed. Completing the pipe cleanly on a TLS fault would
            // make a bad MAC or a truncated stream indistinguishable from the peer hanging up
            // politely - which is exactly what a truncation attack wants it to look like.
            failure = e;
        }
        finally
        {
            await writer.CompleteAsync(failure);
        }
    }

    /// <summary>
    /// The client's first request usually rides in with its Finished flight, so the handshake has
    /// already decrypted it. Miss this and the first request is silently dropped, then the pump
    /// parks waiting for bytes that arrived before it started.
    /// </summary>
    private async ValueTask<bool> WriteHandshakePlaintextAsync(PipeWriter writer)
    {
        if (!WriteInitialPlaintext(writer))
        {
            return true;   // nothing rode in with the handshake
        }

        FlushResult flush = await writer.FlushAsync();
        return !flush.IsCompleted && !flush.IsCanceled;
    }

    private bool WriteInitialPlaintext(PipeWriter writer)
    {
        ReadOnlySpan<byte> initial = _session.DrainPlaintext();
        if (initial.IsEmpty)
        {
            return false;
        }

        writer.Write(initial);
        return true;
    }

    // Decrypt every buffer this snapshot carries, straight into the pipe. Each one is returned to
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
