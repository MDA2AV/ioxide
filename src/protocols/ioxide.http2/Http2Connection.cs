using System.Buffers;
using System.IO.Pipelines;

namespace ioxide.http2;

/// <summary>
/// Serves HTTP/2 over one accepted <see cref="TcpConnection"/>, in managed code end to end: frames,
/// HPACK and flow control are all here, with no native library involved.
///
/// <code>
/// reactor.TcpHandle = (r, conn) =>
///     new Http2Connection(conn).RunBufferedAsync(request => Http2Response.Text("hello"));
/// </code>
///
/// The default HTTP/2 here, and the one the features land on: streamed responses, streamed
/// request bodies and non-blocking dispatch are all this side. <c>ioxide.nghttp2</c> remains as
/// the battle-tested alternative - buffered only, and the reference implementation's coverage of
/// the protocol's darker corners.
///
/// It speaks to an <see cref="IDuplexPipe"/> and knows nothing about TLS: hand it a
/// <c>TcpConnectionDualPipe</c> for h2c or a <c>TlsConnectionDualPipe</c> for h2 over TLS, and the
/// protocol code is identical either way.
/// </summary>
/// <remarks>Reactor thread only.</remarks>
public sealed partial class Http2Connection : IDisposable
{
    private readonly IDuplexPipe _pipe;
    private readonly Http2Options _options;
    private readonly HpackDecoder _decoder;

    private readonly TcpConnection? _connection;   // when the pipe names it (ITcpConnectionPipe)
    private int _owed;                             // requests in whole and not yet answered

    // Inbound bytes accumulate here because a frame can straddle recv buffers - the ring hands out
    // whatever the kernel filled, which has nothing to do with frame boundaries.
    private byte[] _inbound = [];
    private int _inboundUsed;

    // Scratch for one header block's decoded literals. Reused per block; the request arena copies
    // out of it, so nothing here outlives the decode.
    private byte[] _headerScratch = new byte[16 * 1024];

    private readonly Dictionary<int, PendingRequest> _streams = new();
    private readonly List<PendingRequest> _ready = [];

    // Readers whose parked ReadAsync has something to hand over. Collected during parsing and
    // fired once it has unwound, so a resumed handler cannot re-enter the parser mid-frame.
    private readonly List<Http2BodyReader> _bodyWakes = [];

    // The header block of a stream refused for exceeding MaxConcurrentStreams: decoded to keep
    // HPACK in step with the peer, then thrown away. A block cannot interleave with another
    // stream's frames, so one of these is enough.
    private readonly PendingRequest _discardBlock = new();
    private int _discardingStream;

    private bool _prefaceSeen;
    private bool _disposed;
    private bool _failed;

    // The peer's flow-control windows, as WE must respect them when sending. 65535 until its
    // SETTINGS say otherwise, which is the RFC's default rather than a guess.
    private int _peerConnectionWindow = 65535;
    private int _peerInitialStreamWindow = 65535;
    private int _peerMaxFrameSize = 16384;

    /// <summary>
    /// Serve over an already-chosen transport. The pipe is the caller's to dispose.
    /// </summary>
    public Http2Connection(IDuplexPipe pipe, Http2Options? options = null)
    {
        _pipe = pipe;
        _options = options ?? new Http2Options();
        _decoder = new HpackDecoder();
        _connection = (pipe as ITcpConnectionPipe)?.Connection;
    }

    /// <summary>Convenience for cleartext h2c: wraps the connection in its own duplex pipe.</summary>
    public Http2Connection(TcpConnection connection, Http2Options? options = null)
        : this(new TcpConnectionDualPipe(connection), options)
    {
    }

    /// <summary>True once the connection can serve no more.</summary>
    public bool IsBroken => _failed || _disposed;

    /// <summary>Stop accepting new streams.</summary>
    public void Shutdown() => _failed = true;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        foreach (PendingRequest pending in _streams.Values)
        {
            pending.Dispose();
        }
        _streams.Clear();

        foreach (PendingRequest pending in _ready)
        {
            pending.Dispose();
        }
        _ready.Clear();
        _bodyWakes.Clear();
        _responseWindows.Clear();

        if (_inbound.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_inbound);
            _inbound = [];
        }

        if (_queued.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_queued);
            _queued = [];
        }
        _queuedUsed = 0;

        // A writer parked on its turn of the write pump has to wake into IsBroken, not hang: the
        // flush that would have completed its turn is never coming.
        _turnWaiter?.TrySetResult();
        _turnWaiter = null;
    }

    /// <summary>Serve until the peer goes away, answering each request with <paramref name="handler"/>.</summary>
    public Task RunBufferedAsync(Func<Http2Request, Http2Response> handler)
        => RunBufferedAsync(request => new ValueTask<Http2Response>(handler(request)));

    /// <summary>Serve until the peer goes away, with an asynchronous handler.</summary>
    public async Task RunBufferedAsync(Func<Http2Request, ValueTask<Http2Response>> handler)
    {
        try
        {
            // Our SETTINGS go out first; a peer that opened with the preface and a request is
            // already waiting on them.
            WriteSettings();
            await FlushAsync();

            while (!IsBroken)
            {
                ReadResult read = await _pipe.Input.ReadAsync();

                bool received = Accumulate(read.Buffer);
                _pipe.Input.AdvanceTo(read.Buffer.End);

                if (received)
                {
                    // A streamed writer that finishes inside this window needs no write of its own:
                    // the flush below carries it out together with every other response the pass
                    // produced.
                    _passFlushPending = true;
                    ParseAvailable();
                    await DispatchReadyAsync(handler);

                    // Body chunks reach their handlers here, inside the pass: the WINDOW_UPDATEs a
                    // read stages then ride the same flush as everything else, so credit gets back
                    // to the peer without a write of its own.
                    FireBodyWakes();

                    _passFlushPending = false;
                    await FlushAsync();
                }

                if (read.IsCompleted || read.IsCanceled)
                {
                    return;
                }
            }
        }
        catch (Exception)
        {
            // A malformed peer is not a server fault. Nothing here is recoverable - HPACK in
            // particular has no resync point once the tables diverge.
            _failed = true;
        }
        finally
        {
            // A writer parked on flow-control credit will never be woken by a dead connection.
            ReleaseAllCreditWaiters();
            Dispose();
        }
    }

    // Copy into the accumulator, because a frame can straddle segments AND reads, and the parser
    // wants one contiguous view. The pipe's memory is only valid until AdvanceTo.
    private bool Accumulate(in ReadOnlySequence<byte> buffer)
    {
        bool any = false;

        foreach (ReadOnlyMemory<byte> segment in buffer)
        {
            if (segment.Length > 0)
            {
                Append(segment.Span);
                any = true;
            }
        }

        return any;
    }

    private void Append(ReadOnlySpan<byte> data)
    {
        if (_inbound.Length - _inboundUsed < data.Length)
        {
            long size = Math.Max(16 * 1024, (long)_inbound.Length * 2);
            while (size < (long)_inboundUsed + data.Length)
            {
                size *= 2;
            }

            byte[] grown = ArrayPool<byte>.Shared.Rent((int)Math.Min(size, Array.MaxLength));
            _inbound.AsSpan(0, _inboundUsed).CopyTo(grown);
            if (_inbound.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_inbound);
            }
            _inbound = grown;
        }

        data.CopyTo(_inbound.AsSpan(_inboundUsed));
        _inboundUsed += data.Length;
    }

    private async ValueTask DispatchReadyAsync(Func<Http2Request, ValueTask<Http2Response>> handler)
    {
        if (_ready.Count == 0)
        {
            return;
        }

        PendingRequest[] ready = _ready.ToArray();
        _ready.Clear();

        foreach (PendingRequest pending in ready)
        {
            ValueTask<Http2Response> inFlight;

            try
            {
                Http2Request request = pending.Freeze();

                if (TryDispatchStreamed(request, pending))
                {
                    continue;   // the writer owns this stream, and retires it when done
                }

                inFlight = handler(request);
            }
            catch
            {
                pending.Dispose();
                throw;
            }

            // Answered synchronously, which nearly every handler does. Stay inline: this response
            // is staged in time for the pass flush, so it still leaves with every other one, and
            // there is no Task to allocate.
            if (inFlight.IsCompletedSuccessfully)
            {
                try
                {
                    WriteResponse(pending.StreamId, inFlight.Result);
                }
                finally
                {
                    RetireStream(pending);
                }
                continue;
            }

            // It parked - a database, an upstream, a disk. Awaiting here would hold every OTHER
            // stream on this connection behind it, including responses already staged and ready to
            // go, because they all share this one dispatch loop and one TCP connection. So it
            // finishes on its own and writes its own bytes when it does.
            _ = CompleteBufferedAsync(inFlight, pending);
        }
    }

    /// <summary>
    /// The tail of a handler that parked. Nothing is awaiting this, so everything the dispatch loop
    /// would have done afterwards has to happen here instead - retiring the request, and writing,
    /// since the pass flush has long gone by. Forgetting that tail in the streamed path is what
    /// leaked 20 GB.
    /// </summary>
    private async Task CompleteBufferedAsync(ValueTask<Http2Response> inFlight, PendingRequest pending)
    {
        try
        {
            Http2Response response = await inFlight;
            WriteResponse(pending.StreamId, response);
        }
        catch (Exception exception)
        {
            // Nobody can observe this task, so an escaping exception would vanish silently and the
            // peer would wait on a stream that is never coming.
            Console.Error.WriteLine($"[ioxide.http2] request handler faulted: {exception.GetBaseException().Message}");

            if (!IsBroken)
            {
                WriteResponse(pending.StreamId, new Http2Response { Status = 500 });
            }
        }
        finally
        {
            RetireStream(pending);
            await MaybeFlushAsync();
        }
    }

    // While a response is owed the read loop's parked read is not waiting on the peer, so the read
    // timeout is suspended; a slow request must not time out the connection it shares with others.
    private void Owe(PendingRequest pending)
    {
        if (pending.Owed)
        {
            return;
        }
        pending.Owed = true;

        if (_owed++ == 0)
        {
            _connection?.SuspendReadTimeout();
        }
    }

    // Every end of a stream disposes its PendingRequest, which settles here.
    private void Settle(PendingRequest pending)
    {
        if (!pending.Owed)
        {
            return;
        }
        pending.Owed = false;

        if (--_owed == 0)
        {
            _connection?.ResumeReadTimeout();
        }
    }

    /// <summary>
    /// Done with a stream. The buffered path already took it out of <c>_streams</c> when it became
    /// ready; a streamed request is still in there, because DATA frames were arriving the whole
    /// time the handler ran.
    /// </summary>
    private void RetireStream(PendingRequest pending)
    {
        _streams.Remove(pending.StreamId);
        pending.Dispose();
    }

    /// <summary>Return a consumed chunk's credit to the peer, on both windows it was charged to.</summary>
    internal void CreditBody(int streamId, int length)
    {
        if (length <= 0 || IsBroken)
        {
            return;
        }

        WriteWindowUpdate(0, length);
        WriteWindowUpdate(streamId, length);
    }

    /// <summary>A reader has something for a parked ReadAsync; wake it once the parser is done.</summary>
    internal void NoteBodyWake(Http2BodyReader reader)
    {
        if (!_bodyWakes.Contains(reader))
        {
            _bodyWakes.Add(reader);
        }
    }

    private void FireBodyWakes()
    {
        if (_bodyWakes.Count == 0)
        {
            return;
        }

        // Snapshot-and-clear: a resumed handler reads again, which can land another wake here, and
        // the list must not be mutated while it is being walked.
        Http2BodyReader[] wakes = _bodyWakes.ToArray();
        _bodyWakes.Clear();

        foreach (Http2BodyReader reader in wakes)
        {
            reader.FireIfReady();
        }
    }
}
