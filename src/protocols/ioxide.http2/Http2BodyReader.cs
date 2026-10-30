using System.Buffers;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;

namespace ioxide.http2;

/// <summary>
/// Pull surface for a streaming request body, handed to a handler that takes one - the
/// <c>RunAsync</c> overloads with an <see cref="Http2BodyReader"/> parameter.
/// The connection loop pushes chunks in as DATA frames arrive; the handler pulls with
/// <see cref="ReadAsync"/>. An empty chunk means the body ended whole, at END_STREAM. A body cut off
/// by a reset stream or a lost connection ends with an <see cref="IOException"/> instead.
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
/// Single consumer, on any thread: a read made off the reactor is served on it. Each
/// <see cref="ReadAsync"/> invalidates the previous chunk's memory - its pooled buffer goes back -
/// so a handler that needs to keep bytes past the next read must copy them. Wakes are deferred by
/// the connection loop until the parser has unwound, so a resumed handler cannot re-enter it
/// mid-frame.
/// </remarks>
public sealed class Http2BodyReader : IValueTaskSource<ReadOnlyMemory<byte>>
{
    private readonly Http2Connection _owner;
    private readonly int _streamId;

    private readonly Queue<(byte[] Buffer, int Length)> _chunks = new();
    private (byte[]? Buffer, int Length) _handedOut;
    private bool _ended;
    private Exception? _fault;   // what the end is reported as, when the body was cut off
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
    /// The next body chunk; empty means the body ended whole. Throws <see cref="IOException"/> in
    /// place of the end when it was cut off. The memory is valid until the next
    /// <see cref="ReadAsync"/> call, or until the handler returns, whichever comes first.
    /// </summary>
    public ValueTask<ReadOnlyMemory<byte>> ReadAsync()
    {
        if (_owner.OffReactor is Reactor reactor)
        {
            return ReadOffReactor(reactor);
        }

        ReleaseHandedOut();

        if (_chunks.TryDequeue(out (byte[] Buffer, int Length) chunk))
        {
            _handedOut = chunk;
            _owner.CreditBody(_streamId, chunk.Length);   // consumption is what opens the window
            return new ValueTask<ReadOnlyMemory<byte>>(chunk.Buffer.AsMemory(0, chunk.Length));
        }

        if (_ended)
        {
            return _fault is null ? default : ValueTask.FromException<ReadOnlyMemory<byte>>(_fault);
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

    /// <summary>End of body: END_STREAM, or a cut one once <see cref="Abort"/> has said so. Idempotent.</summary>
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

    // The queue and the window credit belong to the reactor, so a read from another thread is served
    // there. Out of line, so the on-reactor read compiles as it did before the check.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private ValueTask<ReadOnlyMemory<byte>> ReadOffReactor(Reactor reactor)
    {
        _core.Reset();
        reactor.ScheduleOnReactor(static state => ((Http2BodyReader)state!).ReadOnReactor(), this);
        return new ValueTask<ReadOnlyMemory<byte>>(this, _core.Version);
    }

    // Parked here, and completed at once when there is something to hand over.
    private void ReadOnReactor()
    {
        ReleaseHandedOut();
        _armed = true;
        FireIfReady();
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
            if (_fault is null)
            {
                _core.SetResult(default);
            }
            else
            {
                _core.SetException(_fault);
            }
        }
    }

    // The stream was reset, or the connection went away, under a running handler: what is queued
    // will never be read, so it goes back now. The chunk the handler holds stays its own until its
    // next read or its return, and a parked read wakes through the deferred list. A body that had
    // not ended, or loses bytes here, was cut off, and its end has to say so.
    internal void Abort()
    {
        if (!_ended || _chunks.Count > 0)
        {
            _fault = new IOException("the request body was cut off: its stream was reset or its connection closed");
        }
        DropQueued();
        End();
    }

    // The handler is done with the request, or never got it: recycle everything, the chunk it held
    // included, and complete a read it left parked.
    internal void Drop()
    {
        ReleaseHandedOut();
        DropQueued();

        // Drained first, so the wake below reports end-of-body rather than handing out a chunk
        // whose stream is already gone.
        _ended = true;
        FireIfReady();
    }

    // Every stream shares the connection window, so bytes dropped unread still owe it credit.
    private void DropQueued()
    {
        int unread = 0;
        while (_chunks.TryDequeue(out (byte[] Buffer, int Length) chunk))
        {
            unread += chunk.Length;
            ArrayPool<byte>.Shared.Return(chunk.Buffer);
        }
        _owner.CreditConnection(unread);
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
