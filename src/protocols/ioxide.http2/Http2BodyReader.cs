using System.Buffers;
using System.Threading.Tasks.Sources;

namespace ioxide.http2;

/// <summary>
/// Pull surface for a streaming request body, handed to the handler as
/// <see cref="Http2Request.BodyReader"/> when <see cref="Http2Options.StreamRequestBodies"/> is on.
/// The connection loop pushes chunks in as DATA frames arrive; the handler pulls with
/// <see cref="ReadAsync"/>. An empty chunk means end of body (END_STREAM or a reset stream).
///
/// Backpressure is real rather than buffered-and-hoped-for: a chunk is credited back to the peer's
/// window only as it is handed over, so a slow consumer stops replenishing, the peer runs out of
/// window and stops sending. Memory is bound by one window instead of by the whole body, which is
/// the difference that makes a hostile upload harmless.
///
/// Unlike HTTP/3, credit here is shared. Every stream rides one TCP connection, so a chunk opens
/// both the stream's window and the CONNECTION's - and a handler that never reads holds down the
/// connection window for every other stream on it, not only its own.
/// </summary>
/// <remarks>
/// Single consumer, reactor thread only. Each <see cref="ReadAsync"/> invalidates the previous
/// chunk's memory - its pooled buffer goes back - so a handler that needs to keep bytes past the
/// next read must copy them. Wakes are deferred by the connection loop until the parser has
/// unwound, so a resumed handler cannot re-enter it mid-frame.
/// </remarks>
public sealed class Http2BodyReader : IValueTaskSource<ReadOnlyMemory<byte>>
{
    private readonly Http2Connection _owner;
    private readonly int _streamId;

    private readonly Queue<(byte[] Buffer, int Length)> _chunks = new();
    private (byte[]? Buffer, int Length) _handedOut;
    private bool _ended;
    private bool _armed;

    private ManualResetValueTaskSourceCore<ReadOnlyMemory<byte>> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };

    internal Http2BodyReader(Http2Connection owner, int streamId, bool ended)
    {
        _owner = owner;
        _streamId = streamId;
        _ended = ended;
    }

    /// <summary>
    /// The next body chunk; empty means end of body. The memory is valid until the next
    /// <see cref="ReadAsync"/> call, or until the handler returns, whichever comes first.
    /// </summary>
    public ValueTask<ReadOnlyMemory<byte>> ReadAsync()
    {
        ReleaseHandedOut();

        if (_chunks.TryDequeue(out (byte[] Buffer, int Length) chunk))
        {
            _handedOut = chunk;
            _owner.CreditBody(_streamId, chunk.Length);   // consumption is what opens the window
            return new ValueTask<ReadOnlyMemory<byte>>(chunk.Buffer.AsMemory(0, chunk.Length));
        }

        if (_ended)
        {
            return default;
        }

        _core.Reset();
        _armed = true;
        return new ValueTask<ReadOnlyMemory<byte>>(this, _core.Version);
    }

    // Body bytes straight off a DATA frame. The span points into the connection's accumulator and
    // dies when the parser moves on, so it has to be copied. Never completes a parked reader
    // inline: the wake is deferred to FireIfReady, after the parser unwinds.
    internal void Push(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(data.Length);
        data.CopyTo(buffer);
        _chunks.Enqueue((buffer, data.Length));

        if (_armed)
        {
            _owner.NoteBodyWake(this);
        }
    }

    /// <summary>End of body: END_STREAM, a reset stream, or the connection going away. Idempotent.</summary>
    internal void End()
    {
        if (_ended)
        {
            return;
        }
        _ended = true;

        if (_armed)
        {
            _owner.NoteBodyWake(this);
        }
    }

    // The deferred wake: complete a parked ReadAsync now that the parser is off the stack.
    internal void FireIfReady()
    {
        if (!_armed)
        {
            return;
        }

        if (_chunks.TryDequeue(out (byte[] Buffer, int Length) chunk))
        {
            _armed = false;
            _handedOut = chunk;
            _owner.CreditBody(_streamId, chunk.Length);
            _core.SetResult(chunk.Buffer.AsMemory(0, chunk.Length));
        }
        else if (_ended)
        {
            _armed = false;
            _core.SetResult(default);
        }
    }

    // Teardown while chunks may still be queued: recycle everything and wake anyone parked.
    internal void Drop()
    {
        ReleaseHandedOut();

        int unread = 0;
        while (_chunks.TryDequeue(out (byte[] Buffer, int Length) chunk))
        {
            unread += chunk.Length;
            ArrayPool<byte>.Shared.Return(chunk.Buffer);
        }

        // Unread bytes still count against the CONNECTION window, which every other stream shares.
        // Dropping them without credit shrinks it for good - a handler that answers without reading
        // its body, or a fetch the browser cancels, each takes a bite - until no request body on
        // this connection can move at all. The stream is closing, so only the connection is owed.
        _owner.CreditBody(0, unread);

        // Drained first, so the wake below reports end-of-body rather than handing out a chunk
        // whose stream is already gone. Woken directly rather than through the connection's
        // deferred list: teardown is the last thing that happens, so nothing would fire it, and a
        // handler parked mid-body would wait forever on a body that stopped arriving.
        _ended = true;
        FireIfReady();
    }

    private void ReleaseHandedOut()
    {
        if (_handedOut.Buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_handedOut.Buffer);
            _handedOut = (null, 0);
        }
    }

    // Completes on the reactor thread only; the context-post is stripped so resumes stay inline.
    ReadOnlyMemory<byte> IValueTaskSource<ReadOnlyMemory<byte>>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<ReadOnlyMemory<byte>>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<ReadOnlyMemory<byte>>.OnCompleted(Action<object?> continuation, object? state,
        short token, ValueTaskSourceOnCompletedFlags flags)
        => _core.OnCompleted(continuation, state, token,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
}
