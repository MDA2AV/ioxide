using System.Threading.Tasks.Sources;

namespace epoxide.utils;

/// <summary>
/// Where the awaiter of an operation a reactor completes resumes: inline on that reactor, inside the
/// completion, wherever the awaiter was - the reactor is the thread that saw the event, so anywhere
/// else would cost a hop. An awaiter with a SynchronizationContext or TaskScheduler of its own
/// resumes on that instead.
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
        core.RunContinuationsAsynchronously = false;

        // Stripped on the reactor's thread, so a SynchronizationContext someone installs there cannot
        // turn the inline resume into a post.
        core.OnCompleted(continuation, state, token,
            reactor.OnReactorThread ? flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext : flags);
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
