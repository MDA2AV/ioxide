using System.IO.Pipelines;
using System.Threading.Tasks.Sources;

namespace ioxide.http2;

/// <summary>
/// A flush waiting for the write pump's next turn (<c>Http2Connection.Write.cs</c>). Reusable: a streamed writer
/// keeps one for its whole life, so a flush that only waits for the turn allocates nothing.
/// </summary>
internal sealed class TurnWaiter : IValueTaskSource<FlushResult>
{
    private ManualResetValueTaskSourceCore<FlushResult> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };

    /// <summary>The waiter parked after this one, for the same turn.</summary>
    internal TurnWaiter? Next;

    /// <summary>
    /// Parked and not woken yet. A flush whose wait was never awaited leaves its writer in the turn, and the
    /// writer's next flush then waits for that same wake instead of joining a second time.
    /// </summary>
    internal bool Enlisted;

    internal ValueTask<FlushResult> Arm()
    {
        _core.Reset();
        return new ValueTask<FlushResult>(this, _core.Version);
    }

    internal void Release() => _core.SetResult(default);

    FlushResult IValueTaskSource<FlushResult>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<FlushResult>.GetStatus(short token) => _core.GetStatus(token);

    // Woken by the pump on the reactor: resume there rather than post.
    void IValueTaskSource<FlushResult>.OnCompleted(Action<object?> continuation, object? state, short token,
        ValueTaskSourceOnCompletedFlags flags)
        => _core.OnCompleted(continuation, state, token, flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
}
