using System.Threading.Tasks.Sources;

namespace ioxide;

/// <summary>
/// The awaitable half of a ring op, reusable across operations: Prepare() arms it, hand it to a
/// submit as the completion, await the returned task. Continuations run synchronously, so the
/// awaiter resumes inline on the reactor. One op in flight per source; use two sources (or a
/// pool) for concurrency. Zero allocation per op.
/// </summary>
public sealed class RingOpSource : IRingCompletion, IValueTaskSource<int>
{
    private ManualResetValueTaskSourceCore<int> _core = new()
    {
        RunContinuationsAsynchronously = false
    };

    private volatile bool _inFlight;

    /// <summary>Arm for one operation; call immediately before the submit.</summary>
    public ValueTask<int> Prepare()
    {
        if (_inFlight)
        {
            throw new InvalidOperationException("An operation is already in flight on this RingOpSource.");
        }

        _inFlight = true;
        _core.Reset();
        return new ValueTask<int>(this, _core.Version);
    }

    public void Complete(int result)
    {
        // Cleared before SetResult: the inline continuation may Prepare() the next op.
        _inFlight = false;
        _core.SetResult(result);
    }

    int IValueTaskSource<int>.GetResult(short token)
    {
        return _core.GetResult(token);
    }

    ValueTaskSourceStatus IValueTaskSource<int>.GetStatus(short token)
    {
        return _core.GetStatus(token);
    }

    void IValueTaskSource<int>.OnCompleted(
        Action<object?> continuation,
        object? state,
        short token,
        ValueTaskSourceOnCompletedFlags flags)
    {
        // Completes on the reactor thread only - strip the context-post so resumes stay inline.
        _core.OnCompleted(continuation, state, token,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }
}
