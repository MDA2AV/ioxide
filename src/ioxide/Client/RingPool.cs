namespace ioxide;

/// <summary>
/// A pool of ring-native resources for one reactor (Postgres connections, read buffers). Rent,
/// use, return; when empty, renters queue FIFO. Waiter continuations run synchronously on the
/// returning thread, so an inline return resumes the next handler inline - the no-thread-pool
/// property holds under contention. A return from another thread sends the renter back to the
/// reactor it rented on.
/// </summary>
public sealed class RingPool<T> where T : class
{
    private readonly Stack<T> _idle = new();
    private readonly Queue<TaskCompletionSource<T>> _waiters = new();
    private readonly object _gate = new();

    public int IdleCount
    {
        get
        {
            lock (_gate)
            {
                return _idle.Count;
            }
        }
    }

    public int WaiterCount
    {
        get
        {
            lock (_gate)
            {
                return _waiters.Count;
            }
        }
    }

    /// <summary>
    /// Rent a resource, waiting (without blocking a thread) if none is idle.
    /// </summary>
    public ValueTask<T> RentAsync()
    {
        TaskCompletionSource<T> waiter;
        lock (_gate)
        {
            if (_idle.TryPop(out T? item))
            {
                return new ValueTask<T>(item);
            }

            waiter = new TaskCompletionSource<T>();   // sync continuations → inline resume
            _waiters.Enqueue(waiter);
        }
        return WaitAsync(waiter.Task, Reactor.Current);
    }

    // The returner may be on any thread: the renter continues on the reactor it rented on.
    private static async ValueTask<T> WaitAsync(Task<T> waiting, Reactor? reactor)
    {
        T item = await waiting;
        await new ReactorSwitch(reactor);
        return item;
    }

    /// <summary>
    /// Return a resource (also how fresh ones are seeded).
    /// </summary>
    public void Return(T item)
    {
        TaskCompletionSource<T>? waiter;
        lock (_gate)
        {
            if (!_waiters.TryDequeue(out waiter))
            {
                _idle.Push(item);
                return;
            }
        }

        waiter.SetResult(item);   // outside the lock - runs the renter's continuation
    }
}
