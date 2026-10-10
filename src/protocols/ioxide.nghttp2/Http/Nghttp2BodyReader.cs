using System.Buffers;
using System.Threading.Tasks.Sources;

namespace ioxide.nghttp2;

/// <summary>
/// Pull surface for a streaming request body, handed to the handler as
/// <see cref="Nghttp2Request.BodyReader"/> when <see cref="Nghttp2Options.StreamRequestBodies"/> is on.
/// The connection pushes chunks in as nghttp2 delivers DATA; the handler pulls with
/// <see cref="ReadAsync"/>. An empty chunk means end of body (END_STREAM or a reset stream).
///
/// Backpressure is real rather than buffered-and-hoped-for: the session sends no WINDOW_UPDATE of
/// its own, and a chunk is credited back to the peer's window only as it is handed over, so a slow
/// consumer stops replenishing, the peer runs out of window and stops sending. Memory is bound by
/// one window instead of by the whole body, which is the difference that makes a hostile upload
/// harmless.
///
/// As on <c>ioxide.http2</c>, credit is shared. Every stream rides one TCP connection, so a chunk
/// opens both the stream's window and the CONNECTION's - and a handler that never reads holds down
/// the connection window for every other stream on it, until it returns.
/// </summary>
/// <remarks>
/// Single consumer, reactor thread only. Each <see cref="ReadAsync"/> invalidates the previous
/// chunk's memory - its pooled buffer goes back - so a handler that needs to keep bytes past the
/// next read must copy them. Wakes are deferred until nghttp2 has unwound, so a resumed handler
/// cannot re-enter the session mid-call.
/// </remarks>
public sealed class Nghttp2BodyReader : IValueTaskSource<ReadOnlyMemory<byte>>
{
    private readonly Nghttp2Connection _owner;
    private readonly int _streamId;

    private readonly Queue<(byte[] Buffer, int Length)> _chunks = new();
    private (byte[]? Buffer, int Length) _handedOut;
    private bool _ended;
    private bool _armed;

    private ManualResetValueTaskSourceCore<ReadOnlyMemory<byte>> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };

    internal Nghttp2BodyReader(Nghttp2Connection owner, int streamId)
    {
        _owner = owner;
        _streamId = streamId;
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

    // Body bytes straight out of nghttp2's data callback, whose span dies when it returns, so they
    // are copied. Never completes a parked reader inline: the wake is deferred until nghttp2 unwinds.
    // False once the body has ended: the caller credits bytes nobody will read.
    internal bool Push(ReadOnlySpan<byte> data)
    {
        if (_ended)
        {
            return false;
        }

        if (data.IsEmpty)
        {
            return true;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(data.Length);
        data.CopyTo(buffer);
        _chunks.Enqueue((buffer, data.Length));

        if (_armed)
        {
            _owner.NoteBodyWake(this);
        }
        return true;
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

    // The deferred wake: complete a parked ReadAsync now that nghttp2 is off the stack.
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

    // The stream was reset, or the connection went away, under a running handler: what is queued will
    // never be read, so it goes back now, credit included. The chunk the handler holds stays valid
    // until its next read or its return.
    internal void Abort()
    {
        DropQueued();
        End();
    }

    // The handler finished: recycle everything, the chunk it held included. Ended, so DATA still on
    // its way is credited as it arrives, and a read it left parked completes instead of never.
    internal void Drop()
    {
        ReleaseHandedOut();
        DropQueued();

        _ended = true;
        FireIfReady();
    }

    // Unread bytes still hold the peer's windows, so dropping them owes the credit reading would have.
    private void DropQueued()
    {
        int unread = 0;
        while (_chunks.TryDequeue(out (byte[] Buffer, int Length) chunk))
        {
            unread += chunk.Length;
            ArrayPool<byte>.Shared.Return(chunk.Buffer);
        }
        _owner.CreditBody(_streamId, unread);
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
