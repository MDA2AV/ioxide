using System.Net;
using System.Net.Sockets;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Starts an epoxide server on a unique loopback port and waits for it to listen. The runner stops
/// every server a test started when the test ends; teardown-focused tests use the returned reactor +
/// thread to Stop() and join themselves. Tiny buffers keep many concurrent test servers cheap.
/// </summary>
public static class TestServer
{
    /// <summary>
    /// Every test process needs its own port range, and the failure mode when it does not have one
    /// is silent rather than loud: epoxide listeners set SO_REUSEPORT, so two processes binding the
    /// same port BOTH succeed and the kernel load-balances connections between them. WaitForListen
    /// connects happily and a test is then answered by the other process's server, which shows up
    /// as an unrelated assertion failing somewhere far away.
    ///
    /// The window therefore mixes the entry assembly name (so different suites never overlap) with
    /// the process id (so two runs of the SAME suite - a developer and CI, or two terminals - do
    /// not either). No registration, no coordination, and new suites need no changes.
    /// </summary>
    private static int _nextPort = PortBaseForThisProcess();

    // 20000 to 32700, which stops short of ip_local_port_range (32768 on Linux by default): a
    // listener bound above that line races the machine's own ephemeral allocations, including the
    // client sockets these very tests open. A window has to hold a whole suite's servers.
    private const int WindowSize = 250;
    private const int WindowCount = 50;

    private static int PortBaseForThisProcess()
    {
        string name = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name ?? "unknown";

        // Hashed by hand: string.GetHashCode is randomized per process, so the suite half of the
        // key would move between runs and stop being a property of the suite at all.
        int hash = 17;
        foreach (char c in name)
        {
            hash = (hash * 31) + c;
        }

        int window = Math.Abs(hash ^ Environment.ProcessId) % WindowCount;

        // 20000 upward, clear of bench/run.sh (18080-18464) and the playground defaults.
        return 20000 + (window * WindowSize);
    }

    /// <summary>Reserve a unique port (e.g. for TcpOptions.ExtraPorts).</summary>
    public static int NextPort() => ReserveFreePort();

    /// <summary>
    /// A port on which nothing is currently listening.
    /// </summary>
    /// <remarks>
    /// A bind failure is NOT how a collision shows up here. epoxide listeners are opened with
    /// SO_REUSEPORT, so a second process binding a port another already holds SUCCEEDS - and the
    /// kernel then load-balances arriving connections between the two servers, and a test's client
    /// is answered by an unrelated process's handler.
    ///
    /// So the port is PROBED rather than assumed: an exclusive bind fails against a port an
    /// SO_REUSEPORT listener already holds, which is exactly the case that needs detecting. The
    /// probe socket is closed immediately, leaving a window in which another process could take
    /// the port - narrow, and combined with per-process windows it makes a collision rare rather
    /// than certain.
    /// </remarks>
    private static int ReserveFreePort()
    {
        for (int attempt = 0; attempt < 500; attempt++)
        {
            int port = Interlocked.Increment(ref _nextPort);
            if (IsFree(port))
            {
                return port;
            }
        }

        throw new Exception(
            "every port in this process's window is already held - too many suites running at once");

        static bool IsFree(int port)
        {
            try
            {
                using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                {
                    ExclusiveAddressUse = true,   // so an SO_REUSEPORT holder is detected, not joined
                };
                probe.Bind(new IPEndPoint(IPAddress.Loopback, port));
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }
    }

    // Every server this harness starts, so the runner can shut them down when a test ends.
    private static readonly List<(Reactor Reactor, Thread Thread)> Started = [];
    private static readonly Lock StartedLock = new();

    private static void Track(Reactor reactor, Thread thread)
    {
        lock (StartedLock)
        {
            Started.Add((reactor, thread));
        }
    }

    /// <summary>
    /// Stops every server started since the last call. The runner does this after each test, so a
    /// suite runs against the servers the current test started and nothing else.
    /// </summary>
    /// <remarks>
    /// Stopping is best-effort: a reactor that will not come down in time is left to the process
    /// exit rather than failing the test that happened to run last.
    /// </remarks>
    public static void StopAll()
    {
        (Reactor Reactor, Thread Thread)[] running;

        lock (StartedLock)
        {
            running = [.. Started];
            Started.Clear();
        }

        foreach ((Reactor reactor, _) in running)
        {
            try
            {
                reactor.Stop();
            }
            catch (Exception)
            {
                // Already stopped by the test itself, or never finished starting.
            }
        }

        int stuck = 0;

        foreach ((_, Thread thread) in running)
        {
            if (!thread.Join(2000))
            {
                stuck++;
            }
        }

        if (stuck > 0)
        {
            Console.WriteLine($"[harness] {stuck}/{running.Length} reactors did not stop");
        }
    }

    /// <summary>
    /// A port with nothing listening on it, for the tests that need a connect to be refused.
    /// </summary>
    /// <remarks>
    /// Derived rather than hardcoded. A literal like 5599 is a standing bet that no other process on
    /// the machine listens there, and losing that bet does not fail the test loudly - it inverts it,
    /// because the connect succeeds and the refusal being asserted never happens. Binding port 0 has
    /// the kernel pick one that was free a moment ago, and closing it immediately leaves it free.
    /// </remarks>
    public static int DeadPort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    public static int Start(Func<Reactor, TcpConnection, Task> handle, Action<Reactor>? onStart = null)
        => StartConfigured(handle, DefaultConfig(), onStart).Port;

    /// <summary>
    /// Start with explicit config overrides (Port and ReactorCount are stamped by the harness) and
    /// hand back the reactor + its thread so tests can assert against them or stop cleanly - moving
    /// to another port if the one it picked is taken.
    /// </summary>
    /// <remarks>
    /// A port collision is not a test failure and must not be reported as one. Each process gets a
    /// window of ports, but the range available is finite, so with enough processes running at once
    /// two of them genuinely land on the same number. Retrying on the next port makes that
    /// self-healing rather than a flake someone has to try to reproduce.
    /// </remarks>
    public static (int Port, Reactor Reactor, Thread Thread) StartConfigured(
        Func<Reactor, TcpConnection, Task> handle, ServerConfig config, Action<Reactor>? onStart = null)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return StartConfiguredOnce(handle, config, onStart);
            }
            catch (Exception e) when (attempt < 25 && PortTaken(e))
            {
                // The next pass takes the next port. Nothing to clean up: the reactor never bound.
            }
        }
    }

    /// <summary>Whether a start failed because something else already holds the port.</summary>
    /// <remarks>epoxide reports a refused bind as "bind to 0.0.0.0:{port} failed with errno 98" (EADDRINUSE).</remarks>
    private static bool PortTaken(Exception e)
    {
        for (Exception? at = e; at is not null; at = at.InnerException)
        {
            if ((at.Message.Contains("bind to ", StringComparison.Ordinal) && at.Message.Contains("errno 98", StringComparison.Ordinal))
                || at.Message.Contains("Address already in use", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static (int Port, Reactor Reactor, Thread Thread) StartConfiguredOnce(
        Func<Reactor, TcpConnection, Task> handle, ServerConfig config, Action<Reactor>? onStart = null)
    {
        int port = ReserveFreePort();
        config = config with { Tcp = (config.Tcp ?? new TcpOptions()) with { Port = (ushort)port }, ReactorCount = 1 };

        // Wrapped so the caller can be told when OnStart has actually RUN - see the wait below.
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var reactor = new Reactor(0, config)
        {
            OnStart = r =>
            {
                try
                {
                    onStart?.Invoke(r);
                    started.TrySetResult();
                }
                catch (Exception e)
                {
                    started.TrySetException(e);
                    throw;   // RunGuarded still records the reactor death, exactly as before
                }
            },
            TcpHandle = handle,
        };

        var thread = new Thread(RunGuarded(reactor, port))
        {
            IsBackground = true,
            Name = $"test-reactor-{port}",
        };
        thread.Start();
        Track(reactor, thread);

        WaitForListen(port);
        WaitForOnStart(port, started);
        return (port, reactor, thread);
    }

    private static ServerConfig DefaultConfig() => new()
    {
        RecvBufferSize = 4096,
        Tcp = new TcpOptions
        {
            WriteSlabSize = 16 * 1024,
            PoolMax = 64,
            RecvQueueEntries = 64,
        },
    };

    /// <summary>
    /// Start <paramref name="reactorCount"/> reactors sharing ONE port via SO_REUSEPORT - the
    /// production sharding shape, which the single-reactor Start() helpers deliberately avoid. The
    /// handler is handed its reactor's shard index so a test can see which shard served each
    /// connection (and thus that the kernel spread connections across them).
    ///
    /// Readiness is gated on every shard's OnStart firing, not on a single probe: Run() opens the
    /// listener before OnStart, so once all N have signalled, all N listeners are bound and the
    /// kernel has the full set to load-balance across.
    /// </summary>
    /// <param name="onStart">
    /// Run on each reactor's own thread before that shard reports ready, and handed the shard
    /// index so a caller can keep the per-reactor object it creates.
    /// </param>
    public static int StartSharded(int reactorCount, Func<int, Reactor, TcpConnection, Task> handle,
        Action<int, Reactor>? onStart = null)
        => StartShardedReactors(reactorCount, handle, onStart).Port;

    /// <summary><see cref="StartSharded"/>, handing back the reactors too, in shard order.</summary>
    public static (int Port, Reactor[] Reactors) StartShardedReactors(int reactorCount,
        Func<int, Reactor, TcpConnection, Task> handle, Action<int, Reactor>? onStart = null)
    {
        int port = ReserveFreePort();
        var config = new ServerConfig
        {
            ReactorCount = reactorCount,
            RecvBufferSize = 4096,
            Tcp = new TcpOptions
            {
                Port = (ushort)port,
                WriteSlabSize = 16 * 1024,
                PoolMax = 64,
                RecvQueueEntries = 64,
            },
        };

        using var ready = new CountdownEvent(reactorCount);
        var reactors = new Reactor[reactorCount];

        for (int i = 0; i < reactorCount; i++)
        {
            int shard = i;
            var reactor = new Reactor(shard, config)
            {
                TcpHandle = (r, conn) => handle(shard, r, conn),
                OnStart = r =>
                {
                    // Before the signal, so a shard that is "ready" is one whose service exists.
                    // A throw here is caught by RunGuarded and surfaced by WaitForListen, rather
                    // than leaving the countdown to time out with nothing to say.
                    onStart?.Invoke(shard, r);
                    ready.Signal();
                },
            };
            reactors[shard] = reactor;

            var thread = new Thread(RunGuarded(reactor, port))
            {
                IsBackground = true,
                Name = $"test-shard-{port}-{shard}",
            };
            thread.Start();
            Track(reactor, thread);
        }

        // All shards up - or a shard died before OnStart, in which case WaitForListen surfaces the
        // real reason instead of a bare timeout.
        if (!ready.Wait(10_000))
        {
            WaitForListen(port);
        }

        return (port, reactors);
    }

    /// <summary>
    /// A reactor with no TCP listener at all - the outbound-only shape, for <see cref="Reactor.ConnectAsync"/>.
    /// Returns once OnStart has run, so the reactor's thread is bound and its loop is about to wait.
    /// </summary>
    public static (Reactor Reactor, Thread Thread) StartClientOnly(ServerConfig? config = null, Action<Reactor>? onStart = null)
    {
        config = (config ?? new ServerConfig { RecvBufferSize = 4096 }) with { ReactorCount = 1, Tcp = null };

        // Not a port, but a key that cannot collide with one, for the death bookkeeping below.
        int key = -Interlocked.Increment(ref _clientOnlyKeys);

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reactor = new Reactor(0, config)
        {
            OnStart = r =>
            {
                try
                {
                    onStart?.Invoke(r);
                    started.TrySetResult();
                }
                catch (Exception e)
                {
                    started.TrySetException(e);
                    throw;
                }
            },
            TcpHandle = static (_, conn) =>
            {
                conn.DecRef();
                return Task.CompletedTask;
            },
        };

        var thread = new Thread(RunGuarded(reactor, key))
        {
            IsBackground = true,
            Name = $"test-client-reactor{key}",
        };
        thread.Start();
        Track(reactor, thread);

        WaitForOnStart(key, started);
        return (reactor, thread);
    }

    private static int _clientOnlyKeys;

    // Startup failures recorded by RunGuarded, keyed by the port that failed, so WaitForListen can
    // report the real reason instead of "never started listening".
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, Exception> StartupFailures = new();

    /// <summary>
    /// Ports whose death a test has already accounted for, so a late record cannot be re-reported
    /// as unowned.
    /// </summary>
    /// <remarks>
    /// Ordering, not speed. A reactor whose OnStart throws faults `started` at once but reaches
    /// StartupFailures only after Run unwinds through its teardown. So the consumer can look before
    /// the producer writes, remove nothing, and the entry lands with nobody left to claim it.
    /// Marking the port closes that either way. ReserveFreePort only moves forward, so a port keys
    /// one server's lifetime.
    /// </remarks>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, byte> ObservedDeaths = new();

    /// <summary>
    /// Reactor.Run as a thread body, with the exception caught. Without this a bind or listen
    /// failure is unhandled on a background thread and .NET terminates the process - so a single
    /// unlucky port produces ZERO test results rather than one FAIL.
    /// </summary>
    private static ThreadStart RunGuarded(Reactor reactor, int port) => () =>
    {
        try
        {
            reactor.Run();
        }
        catch (Exception e)
        {
            // Not recorded if a test already accounted for this death - see ObservedDeaths.
            if (!ObservedDeaths.ContainsKey(port))
            {
                StartupFailures[port] = e;
            }

            // ALWAYS print, even though WaitForListen may also report it. Only failures that happen
            // before the listener is up are ever consumed there, and Run opens the listener before
            // OnStart - so a reactor that dies in OnStart or later loses that race, and a reactor
            // dying AFTER its own test has passed would leave the suite green. Catching the
            // exception must not make it quieter than not catching it.
            Console.Error.WriteLine($"[test-reactor:{port}] died: {e}");
        }
    };

    /// <summary>
    /// Reactor deaths that no WaitForListen consumed, cleared as they are read. A reactor can die
    /// long after its own test passed - in a ticker, a sweep, a later handler - and nothing else in
    /// the harness would ever notice, so the runner checks this before reporting success.
    /// </summary>
    public static IReadOnlyList<string> DrainUnreportedFailures()
    {
        var drained = new List<string>();
        foreach (int port in StartupFailures.Keys)
        {
            if (StartupFailures.TryRemove(port, out Exception? failure))
            {
                drained.Add($":{port} - {failure.Message}");
            }
        }
        return drained;
    }

    /// <summary>
    /// Waits until the reactor's <c>OnStart</c> has finished, and rethrows what it threw.
    /// </summary>
    /// <remarks>
    /// Run opens the listener BEFORE it calls OnStart, so WaitForListen's probe proves only that
    /// the port is bound. A test could otherwise return from Start and use something OnStart was
    /// supposed to have created, and an OnStart that THREW would surface later as an unrelated
    /// "a test reactor died" at the end of the run instead of failing the test it belongs to.
    /// </remarks>
    private static void WaitForOnStart(int port, TaskCompletionSource started)
    {
        for (int attempt = 0; attempt < 200; attempt++)
        {
            // A reactor that died before reaching OnStart never completes the task, so its failure
            // has to be looked for rather than waited on.
            if (StartupFailures.TryRemove(port, out Exception? failure))
            {
                ObservedDeaths[port] = 1;
                throw new Exception($"server on :{port} failed to start: {failure.Message}", failure);
            }

            try
            {
                if (started.Task.Wait(50))
                {
                    return;
                }
            }
            catch (AggregateException e) when (e.InnerException is not null)
            {
                // Claimed BEFORE removing: the reactor may not have recorded it yet, because the
                // throw still has to unwind through Run's teardown.
                ObservedDeaths[port] = 1;
                StartupFailures.TryRemove(port, out _);
                throw new Exception($"server on :{port} failed to start: {e.InnerException.Message}", e.InnerException);
            }
        }

        throw new Exception($"server on :{port} bound its listener but never finished OnStart");
    }

    private static void WaitForListen(int port)
    {
        for (int attempt = 0; attempt < 100; attempt++)
        {
            if (StartupFailures.TryRemove(port, out Exception? failure))
            {
                throw new Exception($"server on :{port} failed to start: {failure.Message}", failure);
            }

            try
            {
                using var probe = new TcpClient();
                probe.Connect("127.0.0.1", port);
                return;
            }
            catch
            {
                Thread.Sleep(50);
            }
        }

        throw new Exception($"server on :{port} never started listening");
    }
}
