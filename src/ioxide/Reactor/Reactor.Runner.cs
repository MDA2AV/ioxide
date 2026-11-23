using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide.tls;
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

        // A kernel that refuses the ring is a fault the host must hear of too (#270); it gets its own
        // catch because there is nothing to tear down until Create returns.
        try
        {
            _ring = Ring.Create(_ringEntries);
        }
        catch (Exception e) when (OnFault is not null)
        {
            OnFault(this, e);
            return;
        }

        // Set once the loop is entered, so Teardown can tell a failed start from a stop.
        bool ranLoop = false;

        // Covers setup, not just the loop: OnStart is user code, and a throw from it used to leak
        // the listener, the eventfd and both ring mappings.
        try
        {

        // Transports, each a no-op unless configured: TCP listeners, UDP sockets, the QUIC demux.
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

        // After OnStart, so a reactor that serves no TCP registers nothing. Whenever TCP is on, clocks
        // or not: the sweep re-arms accepts paused on a lack of descriptors and retries write shutdowns
        // deferred behind a flush, and walks the table only when a clock is set or a recv is starved (TcpSweep).
        if (_tcpEnabled)
        {
            AddTicker(TcpSweep);
        }

        StartTicker();

            ranLoop = true;
            Loop();
        }
        catch (Exception e) when (OnFault is not null)
        {
            // Handled by the host, so it does not escape to kill the process. Teardown still runs.
            OnFault(this, e);
        }
        finally
        {
            // Runs on every exit path: a fatal io_uring_enter, a throw from OnStart, a full SQ.
            Teardown(startFailed: !ranLoop);
        }
    }

    // Record the owning thread: off-reactor callers detect themselves and go through the handoff
    // queues. Teardown takes both back, as the runtime gives a dead thread's id to a new one.
    private void BindReactorThread()
    {
        _reactorThreadId = Environment.CurrentManagedThreadId;
        t_current = this;
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
                          (_listenPorts.Length > 0 ? $"{ListenHost()}:{string.Join(",", _listenPorts)}" : "(no tcp)") +
                          (_udpFds.Length > 0 ? $" udp:{string.Join(",", _udpFdPorts)}" : "") +
                          $" (incremental={_incremental})");
    }

    private string ListenHost() => _tcp.Address switch
    {
        null => _config.DualStack ? "[::]" : "0.0.0.0",
        { AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 } address => $"[{address}]",
        { } address => address.ToString(),
    };

    // How long a stop waits for its handlers to let go of their connections and for its ring ops to end.
    private const int StopDrainMs = 1_000;

    // The stop's first pass closes everything; the passes after it run as usual until nothing is held or the deadline.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private bool Stopped(ref long deadlineMs)
    {
        if (deadlineMs == 0)
        {
            deadlineMs = Native.MonotonicMs + StopDrainMs;
            // Left queued past the closes, an entry would reach whatever takes its socket's number; a failed prep ends a submit early.
            while (_ring.SubmitAndWait(0) > 0)
            {
            }
            CloseAll();
            DrainPostQ();   // what the stoppers and the closes woke: posted here, past the pass's own drain
            CancelClientOps();
        }

        return (_tcpLive == 0 && _opFreeTop == _opTargets.Length) || Native.MonotonicMs >= deadlineMs;
    }

    // The clients stop, then every socket closes, ending every read, write and wait on one; Teardown runs it for a
    // loop that faulted.
    private void CloseAll()
    {
        RunStoppers();
        CloseTcpListeners();
        CloseTcpConnections();
        TeardownQuic();
        CloseUdpFds();
    }

    // Once, though CloseAll runs again in Teardown; one that throws must not leave the others unrun.
    private void RunStoppers()
    {
        List<Action>? stoppers = _stoppers;
        _stoppers = null;
        foreach (Action stopper in stoppers ?? [])
        {
            try
            {
                stopper();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[r{_id}] stopper faulted: {e.Message}");
            }
        }
    }

    // Everything the reactor owns is freed here, on its thread, but what a handler still holds and what it can reach.
    private void Teardown(bool startFailed)
    {
        // A faulted loop never set it: UdpSendTo sends directly from here, as the ring may never be submitted again.
        _stopRequested = true;
        CloseAll();

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

        // The ring goes either way, its memory with it. When the start failed its number does not: releasing that
        // mid-run kills an unrelated live connection - #242, whose bisect found the damage is the number being handed
        // out again, not the ring teardown. So /dev/null takes the ring's place at the number, and a host that retries
        // a failed start is left a /dev/null descriptor per attempt rather than a ring (#573).
        if (startFailed)
        {
            _ring.DisposeKeepingNumber();
        }
        else
        {
            _ring.Dispose();
        }

        // Pooled connections are past their last send (#250) and their incremental ring is unregistered.
        while (_pool.TryPop(out TcpConnection? pooled))
        {
            pooled.Dispose();
        }

        // What a connection still held has queued, and what its reader took, points into the shared slab.
        if (_tcpLive == 0)
        {
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
        }
        FreeUdpMemory();

        // Last, so what is still queued, or posted from here on, fails its switch rather than waiting forever.
        _postsClosed = true;
        DrainStoppedPosts();
        DrainStoppedOps();

        // After all that could still run here, since until then a handshake may read a TLS service's contexts (#543).
        foreach (TlsService service in _tlsServices ?? [])
        {
            service.Free();
        }

        // No thread is the reactor's from here: not this one, which may run on, nor a new one given its id once this one's
        // Thread object is collected. -1 is no thread's id and not 0, so a caller still hands off, and finds it stopped.
        _reactorThreadId = -1;
        t_current = null;
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

    // Set cross-thread by Stop(); the loop checks it once a pass, and the teardown that follows the loop runs on this
    // (the reactor) thread - mandatory for a single-issuer ring.
    private volatile bool _stopRequested;

    /// <summary>
    /// Requests the reactor to stop. Safe to call from any thread. From then on a ring op submitted on
    /// the reactor throws <see cref="ObjectDisposedException"/>. On its next pass the reactor runs the
    /// stoppers its clients registered (<see cref="AddStopper"/>), closes its listeners, aborts every
    /// connection, so its peer gets a reset and nothing still queued is sent (a kTLS connection is shut
    /// down instead, and what it queued may still go out), and cancels every ring op
    /// once, so every handler's reads, writes and waits end. The loop then runs on, posts and switches
    /// included, until every connection has been let go and every ring op has completed, or about a
    /// second has passed, and <see cref="Run"/> frees all the reactor owns on its thread. A connection a
    /// handler still holds by then stays allocated, its descriptor and the receive memory it can reach
    /// included, and what it calls on the reactor after that fails or reports the connection closed.
    /// Join the reactor thread after calling this to await the teardown.
    /// </summary>
    public void Stop()
    {
        _stopRequested = true;

        // Wake a loop parked in io_uring_enter so it observes the flag promptly. Writing the eventfd is
        // the only ring-adjacent action safe off the reactor thread. WakeFdWrite skips a _wakeFd Run() has
        // not created yet - the loop still sees the flag on its first iteration.
        WakeFdWrite();
    }
}
