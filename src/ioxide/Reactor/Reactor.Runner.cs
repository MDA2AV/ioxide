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

        // The try opens HERE, not at the loop: setup is where the leak actually happens. OnStart is
        // user code and the test harness deliberately throws from it, which leaked the ring fd, the
        // listener and the eventfd - three descriptors and ~745 KiB of RLIMIT_MEMLOCK - on every
        // failed start. Ring.Create itself is outside because there is nothing to tear down until
        // it returns.
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

        // After OnStart, so a reactor that serves no TCP - or has both clocks off - registers
        // nothing and the sweep costs it not even a table walk.
        if (TcpSweepEnabled)
        {
            AddTicker(TcpSweep);
        }

        StartTicker();

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
            // Whatever happened - a fatal io_uring_enter, a throw from OnStart, GetSqeOrFlush
            // giving up on a full SQ - the ring fd, both mmaps, the eventfd and the buffer slab go
            // back. Ring memory is charged against RLIMIT_MEMLOCK, so leaking rings is how a
            // long-lived host eventually cannot create one.
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

    // Teardown, still on the reactor thread, in dependency order: sockets close while the ring is
    // alive (in-flight ops surface as errors/cancels and are dropped), the ring fd goes next, and
    // native memory the kernel could reference (buffer slabs, UDP slot blocks) is freed only after
    // that.
    private void Teardown()
    {
        CloseTcpListeners();
        TeardownQuic();
        CloseUdpFds();
        CloseAcceptedTcpSockets();

        // Guarded because OpenWakeFd runs late in setup and Teardown now also follows a throw
        // from anything before it, where _wakeFd is still its default 0 - stdin, not an eventfd.
        //
        // Zeroed rather than merely closed: WakeFdWrite is called from any thread and guards only
        // on _wakeFd > 0, so leaving the old number here writes into whatever fd reused it.
        // Teardown used to follow an explicit Stop(); it can now also follow a fault, at any
        // instant, while a host is still handing work in.
        if (_wakeFd > 0)
        {
            close(_wakeFd);
        }
        _wakeFd = 0;
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
        _ring.Dispose();

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
