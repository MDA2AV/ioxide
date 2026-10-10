using System.Buffers;
using System.Threading.Tasks.Sources;

namespace ioxide.nghttp3;

/// <summary>
/// Pull surface for a streaming request body (the <see cref="Nghttp3Connection.RunStreamingAsync"/>
/// overload): the connection loop pushes body chunks in as nghttp3 delivers them, the handler
/// pulls with <see cref="ReadAsync"/>. An empty chunk means end of body (fin or stream reset).
///
/// Backpressure is real, not buffered-and-prayed: the request stream is flow-control paced, and
/// each chunk is credited back to the peer's window only as it is handed to the handler - a slow
/// consumer freezes the window and the PEER stops sending, so the sink never holds more than a
/// window's worth (256 KB by engine default).
///
/// Contract: single consumer, reactor thread only, and each ReadAsync invalidates the previous
/// chunk's memory (its pooled buffer is recycled). Wakes are deferred by the connection loop to
/// after nghttp3 unwinds - same discipline as the engine's once-per-read fire.
/// </summary>
public sealed class Nghttp3BodyReader : IValueTaskSource<ReadOnlyMemory<byte>>
{
    /// <summary>Shared pre-ended reader for bodyless requests (fin arrived with the headers):
    /// stateless on its read path, so every such request hands out the same instance - no
    /// allocation, no pacing, reads return empty immediately.</summary>
    internal static readonly Nghttp3BodyReader Ended = new(null, 0, ended: true);

    private readonly Nghttp3Connection? _owner;
    private readonly long _streamId;

    private readonly Queue<(byte[] Buf, int Len)> _chunks = new();
    private (byte[]? Buf, int Len) _handedOut;
    private bool _ended;
    private bool _armed;

    private ManualResetValueTaskSourceCore<ReadOnlyMemory<byte>> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };

    internal Nghttp3BodyReader(Nghttp3Connection? owner, long streamId, bool ended)
    {
        _owner = owner;
        _streamId = streamId;
        _ended = ended;
    }

    /// <summary>
    /// Next body chunk; empty = end of body. The returned memory is valid until the next
    /// ReadAsync call (or handler return), whichever comes first.
    /// </summary>
    public ValueTask<ReadOnlyMemory<byte>> ReadAsync()
    {
        ReleaseHandedOut();

        if (_chunks.TryDequeue(out (byte[] Buf, int Len) chunk))
        {
            _handedOut = chunk;
            _owner?.CreditBody(_streamId, chunk.Len);   // consumption opens the peer's window
            return new ValueTask<ReadOnlyMemory<byte>>(chunk.Buf.AsMemory(0, chunk.Len));
        }

        if (_ended)
        {
            return default;
        }

        _core.Reset();
        _armed = true;
        return new ValueTask<ReadOnlyMemory<byte>>(this, _core.Version);
    }

    // Body bytes from nghttp3 (reactor thread, inside ih3_read_stream - the span dies at return,
    // so copy into a pooled buffer). Never completes the reader inline: the wake is deferred to
    // FireIfReady after nghttp3 unwinds, so a resumed handler can't re-enter it mid-read.
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
            _owner?.NoteBodyWake(this);
        }
    }

    // End of body: fin, stream reset, or connection teardown. Idempotent.
    internal void End()
    {
        if (_ended)
        {
            return;
        }
        _ended = true;
        if (_armed)
        {
            _owner?.NoteBodyWake(this);
        }
    }

    // The deferred wake: complete a parked ReadAsync now that the engine layers have unwound.
    internal void FireIfReady()
    {
        if (!_armed)
        {
            return;
        }
        if (_chunks.TryDequeue(out (byte[] Buf, int Len) chunk))
        {
            _armed = false;
            _handedOut = chunk;
            _owner?.CreditBody(_streamId, chunk.Len);
            _core.SetResult(chunk.Buf.AsMemory(0, chunk.Len));
        }
        else if (_ended)
        {
            _armed = false;
            _core.SetResult(default);
        }
    }

    // Handler finished or connection teardown while chunks may still be queued: recycle everything.
    internal void Drop()
    {
        End();
        ReleaseHandedOut();
        int unread = 0;
        while (_chunks.TryDequeue(out (byte[] Buf, int Len) chunk))
        {
            unread += chunk.Len;
            ArrayPool<byte>.Shared.Return(chunk.Buf);
        }
        _owner?.CreditBody(_streamId, unread);   // unread bytes hold the connection window until credited
    }

    private void ReleaseHandedOut()
    {
        if (_handedOut.Buf is not null)
        {
            ArrayPool<byte>.Shared.Return(_handedOut.Buf);
            _handedOut = (null, 0);
        }
    }

    // IValueTaskSource<ReadOnlyMemory<byte>> - completes on the reactor thread only; strip the
    // context-post so resumes stay inline (see ReactorSynchronizationContext).
    ReadOnlyMemory<byte> IValueTaskSource<ReadOnlyMemory<byte>>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<ReadOnlyMemory<byte>>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<ReadOnlyMemory<byte>>.OnCompleted(
        Action<object?> continuation,
        object? state,
        short token,
        ValueTaskSourceOnCompletedFlags flags)
    {
        _core.OnCompleted(continuation, state, token,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }
}
