using System.Collections.Concurrent;

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
