using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

public sealed unsafe partial class Reactor
{
    // Off-reactor handoff queues + eventfd wake. Reactor-thread callers take the
    // direct fast path instead (no queue, no syscall).
    private int _wakeFd;
    private int _reactorThreadId;

    private readonly ServerConfig _config;

    // Loop Mode
    private readonly bool _incremental;

    /// <summary>
    /// The reactor lifecycle, on the caller's (= the reactor's) thread: bind the thread, create
    /// the ring, open transports, pick the recv-buffer mode, run the loop until <see cref="Stop"/>,
    /// tear down.
    /// </summary>
    public void Run()
    {
        BindReactorThread();
        _ring = Ring.Create(_ringEntries);

        // Covers setup, not just the loop: OnStart is user code, and a throw from it used to leak
        // the listener, the eventfd and both ring mappings. Ring.Create stays outside - nothing to
        // tear down until it returns.
        try
        {

        // Transports: TCP always; UDP sockets + the QUIC demux only when configured (no-ops otherwise).
        OpenTcpListeners();
        OpenUdpSockets();
        InitQuic();

        // Recv buffering: one shared provided-buffer ring, or a ring per connection.
        if (_incremental) InitIncremental();
        else InitSharedRingBuffer();

        OpenWakeFd();

        // Ring-native clients must be opened on this thread; async opens complete
        // once the loop starts.
        OnStart?.Invoke(this);

        AnnounceListening();
        ArmTcpAccepts();
        ArmWakePoll();

        // After OnStart, so a reactor that serves no TCP registers nothing and the sweep costs it
        // not even a table walk.
        if (TcpSweepEnabled)
        {
            AddTicker(TcpSweep);
        }

        StartTicker();

            _ranLoop = true;
            if (_incremental) LoopIncremental();
            else LoopSharedRing();
        }
        catch (Exception e) when (OnFault is not null)
        {
            // Handled by the host, so it does not escape to kill the process. Teardown still runs.
            OnFault(this, e);
        }
        finally
        {
            // Runs on every exit path: a fatal io_uring_enter, a throw from OnStart, a full SQ.
            Teardown();
        }
    }

    // Record the owning thread (off-reactor callers detect themselves and go through the handoff
    // queues) and route awaits from reactor code (timers, HttpClient, Task.Run results) back here
    // instead of the thread pool. Thread-lifetime; nothing to uninstall.
    private void BindReactorThread()
    {
        _reactorThreadId = Environment.CurrentManagedThreadId;
        SynchronizationContext.SetSynchronizationContext(new ReactorSynchronizationContext(this));
    }

    private void OpenWakeFd()
    {
        _wakeFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (_wakeFd < 0)
        {
            throw new InvalidOperationException("eventfd failed");
        }
    }

    private void AnnounceListening()
    {
        Console.WriteLine($"[r{_id}] listening on " +
                          (_listenPorts.Length > 0 ? $"0.0.0.0:{string.Join(",", _listenPorts)}" : "(no tcp)") +
                          (_udpFds.Length > 0 ? $" udp:{string.Join(",", _udpFdPorts)}" : "") +
                          $" (incremental={_incremental})");
    }

    /// <summary>Set once the loop is entered, so Teardown can tell a failed start from a stop.</summary>
    private bool _ranLoop;

    // Still on the reactor thread, in dependency order: sockets close while the ring is alive
    // (in-flight ops surface as errors/cancels and are dropped), the ring fd goes next, and native
    // memory the kernel could reference is freed only after that.
    private void Teardown()
    {
        bool startFailed = !_ranLoop;

        CloseTcpListeners();
        TeardownQuic();
        CloseUdpFds();
        CloseAcceptedTcpSockets();

        // Taken away before it is closed, and its writers waited out: closing under one would
        // free the number and let that writer's 8 bytes land in whatever socket took it next.
        // The > 0 test also covers a throw before OpenWakeFd, where this is still 0 - stdin.
        int wakeFd = Interlocked.Exchange(ref _wakeFd, 0);
        if (wakeFd > 0)
        {
            SpinWait spin = default;
            while (Volatile.Read(ref _wakeUsers) != 0)
            {
                spin.SpinOnce();
            }
            close(wakeFd);
        }
        if (_timerTs != null)
        {
            NativeMemory.Free(_timerTs);
            _timerTs = null;
        }
        if (_opTimespecs != null)
        {
            NativeMemory.Free(_opTimespecs);
            _opTimespecs = null;
            _opTimespecCapacity = 0;
        }
        // Before the fd goes: unregistering is synchronous, closing is not (io_uring_release
        // defers to a workqueue), so without this the frees below could hand the kernel's pages
        // back to the allocator while it still holds them.
        UnregisterSharedBufRings();

        // Both mappings go back either way; the descriptor is kept when the start failed, because
        // releasing its number mid-run kills an unrelated live connection - #242. Bisected: closing
        // it by dup2'ing /dev/null over the number is green, so the damage is the number being
        // reused, not the ring teardown. Costs the ring's memlock charge until exit, which is what
        // this path already did before it tore anything down at all.
        _ring.Dispose(closeFd: !startFailed);

        // Shared provided-buffer ring (incremental mode allocates per connection instead).
        if (_bufRing != null)
        {
            NativeMemory.AlignedFree(_bufRing);
            _bufRing = null;
        }
        if (_bufSlab != null)
        {
            NativeMemory.AlignedFree(_bufSlab);
            _bufSlab = null;
        }
        FreeUdpMemory();
    }

    // Both are no-ops unless that ring was registered: incremental mode leaves _bufRing null (one
    // ring per connection instead), and a reactor with no datagram transport leaves _udpBufRing null.
    private void UnregisterSharedBufRings()
    {
        if (_bufRing != null)
        {
            var reg = new io_uring_buf_reg { bgid = BgId };
            io_uring_register(_ring.Fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);
        }

        if (_udpBufRing != null)
        {
            var reg = new io_uring_buf_reg { bgid = UdpBgId };
            io_uring_register(_ring.Fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);
        }
    }

    // Set cross-thread by Stop(); the loops check it at the top of each iteration and exit, after which
    // Run() tears the ring down on this (the reactor) thread - mandatory for a single-issuer ring.
    private volatile bool _stopRequested;

    /// <summary>
    /// Requests the reactor to stop. Safe to call from any thread. The loop finishes its current
    /// iteration and exits, then <see cref="Run"/> closes the listeners and wake fd and disposes the
    /// io_uring ring on the reactor thread (a single-issuer / DEFER_TASKRUN ring must be torn down on the
    /// thread that owns it). Join the reactor thread after calling this to await teardown.
    /// </summary>
    public void Stop()
    {
        _stopRequested = true;

        // Wake a loop parked in io_uring_enter so it observes the flag promptly. Writing the eventfd is
        // the only ring-adjacent action safe off the reactor thread. The guard covers Stop() racing ahead
        // of Run() creating _wakeFd - the loop still sees the flag on its first iteration.
        if (_wakeFd > 0)
        {
            WakeFdWrite();
        }
    }
}
