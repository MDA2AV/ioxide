namespace ioxide;

/// <summary>
/// A pool of ring-native resources for one reactor (Postgres connections, read buffers). Rent,
/// use, return; when empty, renters queue FIFO. Waiter continuations run synchronously on the
/// returning thread, so an inline return resumes the next handler inline - the no-thread-pool
/// property holds under contention. A return from another thread sends the renter back to the
/// reactor it rented on.
/// </summary>
public sealed class RingPool<T> : IDisposable where T : class
{
    private readonly Stack<T> _idle = new();
    private readonly Queue<TaskCompletionSource<T>> _waiters = new();
    private readonly object _gate = new();
    private bool _disposed;   // under _gate

    /// <summary>
    /// Rent a resource, waiting (without blocking a thread) if none is idle.
    /// </summary>
    public ValueTask<T> RentAsync()
    {
        TaskCompletionSource<T> waiter;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
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
        TaskCompletionSource<T>? waiter = null;
        lock (_gate)
        {
            if (!_disposed && !_waiters.TryDequeue(out waiter))
            {
                _idle.Push(item);
                return;
            }
        }

        if (waiter is null)
        {
            (item as IDisposable)?.Dispose();   // a disposed pool keeps nothing
            return;
        }

        waiter.SetResult(item);   // outside the lock - runs the renter's continuation
    }

    /// <summary>
    /// Dispose the idle resources, and each one returned from now on; the renters waiting, and any
    /// rent made after, fail with <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        T[] idle;
        TaskCompletionSource<T>[] waiters;
        lock (_gate)
        {
            _disposed = true;
            idle = [.. _idle];
            _idle.Clear();
            waiters = [.. _waiters];
            _waiters.Clear();
        }

        foreach (TaskCompletionSource<T> waiter in waiters)
        {
            waiter.SetException(new ObjectDisposedException(GetType().Name));
        }
        foreach (T item in idle)
        {
            (item as IDisposable)?.Dispose();
        }
    }
}
