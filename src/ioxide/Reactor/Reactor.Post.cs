using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace ioxide;

// Reactor-thread scheduling: the _remoteOps/WakeFdWrite machinery generalized to carry arbitrary
// callbacks, so a Kestrel transport built on BCL pipes can route their reader/writer continuations
// onto the reactor thread.
public sealed unsafe partial class Reactor
{
    private readonly struct PostItem
    {
        public readonly Action<object?> Callback;
        public readonly object? State;
        public PostItem(Action<object?> callback, object? state)
        {
            Callback = callback;
            State = state;
        }
    }

    private readonly ConcurrentQueue<PostItem> _postQ = new();

    // Set at the end of Teardown: from then on nothing drains the queue.
    private volatile bool _postsClosed;

    /// <summary>True once the reactor has stopped for good: nothing posted to it runs on it any more.</summary>
    internal bool PostsClosed => _postsClosed;

    /// <summary>True when the caller is executing on this reactor's loop thread.</summary>
    public bool OnReactorThread => Environment.CurrentManagedThreadId == _reactorThreadId;

    [ThreadStatic]
    private static Reactor? t_current;

    /// <summary>The reactor whose loop runs on the calling thread, or null on any other thread.</summary>
    public static Reactor? Current => t_current;

    /// <summary>
    /// Schedule a continuation to run on the reactor thread. Always enqueues (drained each loop
    /// iteration by <see cref="DrainPostQ"/>); wakes the loop via the eventfd only when called off the
    /// reactor, coalescing concurrent producers so at most one wake is outstanding per drain.
    /// </summary>
    public void ScheduleOnReactor(Action<object?> callback, object? state)
    {
        _postQ.Enqueue(new PostItem(callback, state));

        // On the reactor: the loop will drain before it next parks, so no eventfd write needed.
        if (Environment.CurrentManagedThreadId == _reactorThreadId)
        {
            return;
        }

        Wake();

        if (_postsClosed)
        {
            DrainStoppedPosts();   // the reactor is gone: nothing else will take it
        }
    }

    /// <summary>
    /// <see cref="ScheduleOnReactor"/> for a continuation somebody is waiting on, posted the way a
    /// <see cref="ReactorSwitch"/> posts its own: if the reactor stops before running it, it runs on the
    /// thread pool rather than never. There it finds <see cref="PostsClosed"/> set, and must leave alone
    /// what the reactor owns.
    /// </summary>
    internal void ScheduleContinuation(Action continuation) => ScheduleOnReactor(ReactorSwitch.Resume, continuation);

    // A switch waiting on a stopped reactor resumes on the thread pool, where its GetResult throws, instead of
    // waiting forever, as does a continuation posted like one (ScheduleContinuation). Every other post is dropped:
    // it would never have run.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private void DrainStoppedPosts()
    {
        // Teardown's volatile write may not be visible yet when the queue reads empty, stranding a post that saw it open.
        Interlocked.MemoryBarrier();

        while (_postQ.TryDequeue(out PostItem item))
        {
            if (item.Callback == ReactorSwitch.Resume)
            {
                ThreadPool.UnsafeQueueUserWorkItem(static continuation => continuation(), (Action)item.State!, preferLocal: false);
            }
        }
    }

    private void DrainPostQ()
    {
        while (_postQ.TryDequeue(out PostItem item))
        {
            // A callback that throws must not unwind the loop and kill the reactor.
            try
            {
                item.Callback(item.State);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[r{_id}] posted continuation threw: {ex}");
            }
        }
    }
}
