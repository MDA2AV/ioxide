using System.Threading.Tasks.Sources;

namespace epoxide.utils;

/// <summary>
/// Where the awaiter of an operation a reactor completes resumes. The completion runs on the
/// reactor thread: an awaiter that was on that same reactor resumes inline there, as in ioxide,
/// and any other awaiter must never run on it - it resumes on its own SynchronizationContext, if it
/// has one, or on the thread pool.
/// </summary>
/// <remarks>
/// Decided at OnCompleted, on the awaiting thread, and stored before the continuation is published,
/// so the completing thread always reads the choice made for the continuation it finds.
/// </remarks>
internal static class Continuations
{
    public static void OnCompleted<T>(ref ManualResetValueTaskSourceCore<T> core, Reactor reactor,
        Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
    {
        if (reactor.OnReactorThread)
        {
            // Stripped so a SynchronizationContext someone installs on the reactor thread cannot turn
            // the inline resume into a post.
            core.RunContinuationsAsynchronously = false;
            core.OnCompleted(continuation, state, token, flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
        }
        else
        {
            core.RunContinuationsAsynchronously = true;
            core.OnCompleted(continuation, state, token, flags);
        }
    }

    /// <summary>
    /// For an adapter (pipe reader, stream) completing its own source from inside the continuation of
    /// a connection operation: that continuation already runs where the caller belongs, so the
    /// adapter's caller resumes inline there.
    /// </summary>
    public static void OnCompletedInline<T>(ref ManualResetValueTaskSourceCore<T> core,
        Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
    {
        core.RunContinuationsAsynchronously = false;
        core.OnCompleted(continuation, state, token, flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }
}
