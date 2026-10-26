using System.Runtime.CompilerServices;

namespace Epoxide.Tests;

/// <summary>
/// The move a handler makes when it leaves its reactor for the thread pool, as one await:
/// <c>await Hop.ToThreadPool();</c>. It always continues on a pool thread, whatever it starts from,
/// and a pool thread has no SynchronizationContext - so nothing after it is posted back to the
/// reactor, exactly as after any await of something other than a connection that really suspended.
/// </summary>
/// <remarks>
/// Only for the tests about epoxide's thread-pool support. Everywhere else a handler stays on its
/// reactor and waits with <see cref="epoxide.ReactorTimer"/>.
/// </remarks>
public static class Hop
{
    public static ThreadPoolAwaitable ToThreadPool() => default;

    /// <summary>
    /// The way onto a given reactor: <c>await Hop.ToReactor(r);</c> continues on <paramref name="reactor"/>'s
    /// thread, posted there only once the await has registered, so it never finishes on the thread it left.
    /// </summary>
    public static ReactorAwaitable ToReactor(epoxide.Reactor reactor) => new(reactor);

    public readonly struct ReactorAwaitable(epoxide.Reactor reactor) : ICriticalNotifyCompletion
    {
        public ReactorAwaitable GetAwaiter() => this;

        public bool IsCompleted => false;

        public void GetResult()
        {
        }

        public void OnCompleted(Action continuation)
            => reactor.ScheduleOnReactor(static c => ((Action)c!)(), continuation);

        public void UnsafeOnCompleted(Action continuation) => OnCompleted(continuation);
    }

    public readonly struct ThreadPoolAwaitable : ICriticalNotifyCompletion
    {
        public ThreadPoolAwaitable GetAwaiter() => this;

        // Never complete: completing synchronously would continue on the caller's thread.
        public bool IsCompleted => false;

        public void GetResult()
        {
        }

        public void OnCompleted(Action continuation)
            => ThreadPool.QueueUserWorkItem(static c => c(), continuation, preferLocal: false);

        public void UnsafeOnCompleted(Action continuation)
            => ThreadPool.UnsafeQueueUserWorkItem(static c => c(), continuation, preferLocal: false);
    }
}
