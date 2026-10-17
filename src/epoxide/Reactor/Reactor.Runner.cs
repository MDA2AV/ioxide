using System.Runtime.InteropServices;
using static epoxide.Native;

namespace epoxide;

public sealed unsafe partial class Reactor
{
    private int _epfd = -1;
    private int _reactorThreadId;

    // epoll_wait's output, and the reactor's scratch for draining connections nobody reads any more.
    private byte* _events;
    private byte* _scratch;

    internal byte* Scratch => _scratch;

    /// <summary>
    /// The reactor lifecycle, on the caller's (= the reactor's) thread: bind the thread, create the
    /// epoll set, open the listeners, run the loop until <see cref="Stop"/>, tear down.
    /// </summary>
    public void Run()
    {
        BindReactorThread();

        // Covers setup, not just the loop: OnStart is user code, and a throw from it must not leak
        // the epoll set, the eventfd or a listener.
        try
        {
            _epfd = epoll_create1(EPOLL_CLOEXEC);
            if (_epfd < 0)
            {
                throw new InvalidOperationException($"[r{_id}] epoll_create1 failed with errno {Errno}");
            }

            _events = (byte*)NativeMemory.Alloc((nuint)_config.MaxEvents * (nuint)EpollEventSize);
            _scratch = (byte*)NativeMemory.Alloc((nuint)_config.RecvBufferSize);

            OpenWakeFd();
            OpenTcpListeners();

            OnStart?.Invoke(this);

            AnnounceListening();

            // After OnStart. A reactor with no listener registers it with its first outbound connection.
            if (TcpSweepEnabled)
            {
                EnsureTcpSweep();
            }

            StartTicker();

            Loop();
        }
        catch (Exception e) when (OnFault is not null)
        {
            // Handled by the host, so it does not escape to kill the process. Teardown still runs.
            OnFault(this, e);
        }
        finally
        {
            Teardown();
        }
    }

    // Record the owning thread, and route awaits made from reactor code (Task.Delay, HttpClient,
    // Task.Run results) back here instead of the thread pool. Thread-lifetime; nothing to uninstall.
    private void BindReactorThread()
    {
        _reactorThreadId = Environment.CurrentManagedThreadId;
        SynchronizationContext.SetSynchronizationContext(new ReactorSynchronizationContext(this));
    }

    private void AnnounceListening()
    {
        Console.WriteLine($"[r{_id}] listening on " +
                          (_listenPorts.Length > 0 ? $"0.0.0.0:{string.Join(",", _listenPorts)}" : "(no tcp)") +
                          " (epoll)");
    }

    // Set cross-thread by Stop(); the loop checks it at the top of each pass.
    private volatile bool _stopRequested;

    // Set once teardown has let go of every connection: from then on a connection released anywhere
    // closes itself, since no loop is left to recycle it.
    private volatile bool _stopped;

    /// <summary>Whether this reactor has finished its teardown.</summary>
    internal bool Stopped => _stopped;

    /// <summary>
    /// Requests the reactor to stop. Safe to call from any thread. The loop finishes its current pass
    /// and exits, then <see cref="Run"/> closes the listeners, wakes every connection's handler with
    /// the end and closes the epoll set on the reactor thread. Join the reactor thread after calling
    /// this to await teardown.
    /// </summary>
    public void Stop()
    {
        _stopRequested = true;
        WakeFdWrite();
    }

    // On the reactor thread, on every exit path: a failed setup, a throw from OnStart or the loop, a stop.
    private void Teardown()
    {
        CloseTcpListeners();

        // A connection still open belongs to a handler that may be inside a syscall on it right now, on
        // any thread - so it is shut down, not closed: the handler sees the end at once, and the
        // descriptor closes when the handler lets go, which is the only point it is safe to.
        for (int fd = 0; fd < _connections.Length; fd++)
        {
            if (_connections[fd] is { } conn)
            {
                conn.SuppressFin();
                shutdown(fd, SHUT_RDWR);
                CloseFromReactor(conn);
            }
        }

        _stopped = true;

        // A full fence, not the volatile store's release: ConnectAsync and EnqueueRecycle enqueue and
        // then read _stopped, so either a drain below finds the item or its producer sees the flag.
        Interlocked.MemoryBarrier();

        // Anything registered or let go before the flag was visible, queued for a loop that will not
        // run again. A registration is refused here, which completes its ConnectAsync.
        DrainRegisterQ();
        DrainCloseQ();
        DrainRecycleQ();

        // What only this loop would ever have run: continuations posted back to it, and its timers.
        // A handler parked on either resumes now, finds its connection ended, and lets go - left
        // alone it never would, and its descriptor would stay open with it. A timer is cancelled, not
        // expired, so a loop on Expired() ends; anything posted or armed from here on is handled on
        // the pool (EnqueuePost, ScheduleTimer).
        DrainPostQ();
        CancelTimers();

        // Taken away before it is closed, and its writers waited out: closing under one would free
        // the number and let that writer's 8 bytes land in whatever took it next.
        int wakeFd = Interlocked.Exchange(ref _wakeFd, -1);
        if (wakeFd >= 0)
        {
            SpinWait spin = default;
            while (Volatile.Read(ref _wakeUsers) != 0)
            {
                spin.SpinOnce();
            }
            close(wakeFd);
        }

        if (_epfd >= 0)
        {
            close(_epfd);
            _epfd = -1;
        }

        while (_pool.TryPop(out TcpConnection? pooled))
        {
            pooled.Dispose();
        }

        // Kept while a handler outlives the reactor: it may still rent or read a buffer, and the last
        // one's recycle frees them instead.
        if (Volatile.Read(ref _liveConnections) == 0)
        {
            FreePools();
        }

        if (_events != null)
        {
            NativeMemory.Free(_events);
            _events = null;
        }
        if (_scratch != null)
        {
            NativeMemory.Free(_scratch);
            _scratch = null;
        }
    }
}
