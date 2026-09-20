using System.Collections.Concurrent;

namespace ioxide;

// Reactor-thread scheduling: the _remoteOps/WakeFdWrite machinery generalized to carry arbitrary
// callbacks, so a Kestrel transport built on BCL pipes can route their reader/writer continuations
// onto the reactor thread.
public sealed unsafe partial class Reactor
{
    private readonly struct PostItem
    {
        // Action<object?> or SendOrPostCallback - same signature, distinct delegate types.
        // Held as Delegate and type-tested at invoke so neither caller pays a conversion alloc.
        public readonly Delegate Callback;
        public readonly object? State;
        public PostItem(Delegate callback, object? state)
        {
            Callback = callback;
            State = state;
        }
    }

    private readonly ConcurrentQueue<PostItem> _postQ = new();
    private int _postSignalPending;   // 0 = no eventfd wake outstanding, 1 = one issued and undrained

    /// <summary>True when the caller is executing on this reactor's loop thread.</summary>
    public bool OnReactorThread => Environment.CurrentManagedThreadId == _reactorThreadId;

    /// <summary>
    /// Schedule a continuation to run on the reactor thread. Always enqueues (drained each loop
    /// iteration by <see cref="DrainPostQ"/>); wakes the loop via the eventfd only when called off the
    /// reactor, coalescing concurrent producers so at most one wake is outstanding per drain.
    /// </summary>
    public void ScheduleOnReactor(Action<object?> callback, object? state) => EnqueuePost(callback, state);

    // SendOrPostCallback variant for ReactorSynchronizationContext. Distinct name (not an
    // overload): lambdas at existing ScheduleOnReactor call sites would otherwise be ambiguous.
    internal void SchedulePost(SendOrPostCallback callback, object? state) => EnqueuePost(callback, state);

    private void EnqueuePost(Delegate callback, object? state)
    {
        _postQ.Enqueue(new PostItem(callback, state));

        // On the reactor: the loop will drain before it next parks, so no eventfd write needed.
        if (Environment.CurrentManagedThreadId == _reactorThreadId)
        {
            return;
        }

        if (Interlocked.Exchange(ref _postSignalPending, 1) == 0)
        {
            WakeFdWrite();
        }
    }

    private void DrainPostQ()
    {
        // Clear before draining so a producer enqueuing during/after the drain still races to wake.
        Volatile.Write(ref _postSignalPending, 0);
        while (_postQ.TryDequeue(out PostItem item))
        {
            // A faulted continuation (e.g. an async-void rethrow delivered via Post) must not
            // unwind the loop and kill the reactor.
            try
            {
                if (item.Callback is Action<object?> action)
                {
                    action(item.State);
                }
                else
                {
                    ((SendOrPostCallback)item.Callback)(item.State);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[r{_id}] posted continuation threw: {ex}");
            }
        }
    }
}
