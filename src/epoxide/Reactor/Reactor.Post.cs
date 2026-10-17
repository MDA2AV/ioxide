using System.Collections.Concurrent;
using static epoxide.Native;

namespace epoxide;

/// <summary>
/// Reactor-thread scheduling. Nothing in the I/O path needs it - a connection is read and written
/// from whatever thread its handler is on - so this carries only what has to run ON the reactor:
/// continuations posted by <see cref="ReactorSynchronizationContext"/>, callbacks handed to
/// <see cref="ScheduleOnReactor"/>, and the reactor's own bookkeeping for connections let go elsewhere.
/// </summary>
public sealed unsafe partial class Reactor
{
    private readonly struct PostItem
    {
        // Action<object?> or SendOrPostCallback - same signature, distinct delegate types. Held as
        // Delegate and type-tested at invoke so neither caller pays a conversion alloc.
        public readonly Delegate Callback;
        public readonly object? State;
        public PostItem(Delegate callback, object? state)
        {
            Callback = callback;
            State = state;
        }
    }

    private readonly ConcurrentQueue<PostItem> _postQ = new();

    // 0 = no eventfd wake outstanding, 1 = one issued and not yet drained.
    private int _postSignalPending;

    private int _wakeFd = -1;

    // Writers currently holding the eventfd's number, so Teardown can wait them out before it closes.
    private int _wakeUsers;

    /// <summary>True when the caller is executing on this reactor's loop thread.</summary>
    public bool OnReactorThread => Environment.CurrentManagedThreadId == _reactorThreadId;

    /// <summary>
    /// Schedule a callback to run on the reactor thread. Always enqueues (drained each loop pass);
    /// wakes the loop via the eventfd only when called off the reactor, coalescing concurrent
    /// producers so at most one wake is outstanding per drain.
    /// </summary>
    public void ScheduleOnReactor(Action<object?> callback, object? state) => EnqueuePost(callback, state);

    // SendOrPostCallback variant for ReactorSynchronizationContext. Distinct name (not an overload):
    // lambdas at ScheduleOnReactor call sites would otherwise be ambiguous.
    internal void SchedulePost(SendOrPostCallback callback, object? state) => EnqueuePost(callback, state);

    private void EnqueuePost(Delegate callback, object? state)
    {
        _postQ.Enqueue(new PostItem(callback, state));
        SignalLoop();

        // Raced the teardown's last drain, or came after it: no loop will take it out of the queue,
        // and whoever waits on what was posted would wait forever. The pool runs it instead - the
        // reactor's thread is gone, so there is no running it there.
        if (_stopped)
        {
            ThreadPool.UnsafeQueueUserWorkItem(static reactor => reactor.DrainPostQ(), this, preferLocal: false);
        }
    }

    // On the reactor the loop drains before it next waits, so no syscall; off it, one wake per drain.
    private void SignalLoop()
    {
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
        // Cleared before draining so a producer enqueuing during the drain still wakes the next wait.
        Interlocked.Exchange(ref _postSignalPending, 0);
        while (_postQ.TryDequeue(out PostItem item))
        {
            // A faulted continuation (an async-void rethrow delivered via Post) must not unwind the
            // loop and kill the reactor.
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

    private void OpenWakeFd()
    {
        int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (fd < 0)
        {
            throw new InvalidOperationException($"[r{_id}] eventfd failed with errno {Errno}");
        }

        // Level-triggered: the counter stays readable until OnWake reads it, so no write is ever lost.
        if (EpollCtl(_epfd, EPOLL_CTL_ADD, fd, EPOLLIN, Tag(KindWake, 0, fd)) < 0)
        {
            int errno = Errno;
            close(fd);
            throw new InvalidOperationException($"[r{_id}] registering the eventfd failed with errno {errno}");
        }

        Volatile.Write(ref _wakeFd, fd);
    }

    private void WakeFdWrite()
    {
        Interlocked.Increment(ref _wakeUsers);
        try
        {
            int fd = Volatile.Read(ref _wakeFd);
            if (fd >= 0)
            {
                ulong one = 1;
                write(fd, &one, 8);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _wakeUsers);
        }
    }

    private void OnWake()
    {
        // Reset the counter; the queues drain at the top of the next pass.
        ulong drained;
        read(_wakeFd, &drained, 8);
    }
}
