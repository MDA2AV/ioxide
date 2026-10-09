using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Regression tests for the hardening issues: #92 (gid-exhaustion reactor crash), #93 (-ENOBUFS
/// teardown of healthy connections, both loop modes), #94 (faulted handlers leaking connections).
/// Each of these failed (or killed the process) before its fix.
/// </summary>
internal static class HardeningTests
{
    public static void Register(Runner runner)
    {
        runner.Test("harness: Start does not return before OnStart has run", () =>
        {
            // A test of the harness, because the harness is what every other test's setup trusts.
            // Reactor.Run opens the listener BEFORE calling OnStart, and readiness was a TCP probe -
            // so Start could return while OnStart was still running. A test that configured a
            // service there and used it on the next line raced it and NREd intermittently, and a
            // configuration refusal thrown from OnStart could arrive AFTER the assertion meant to
            // catch it, surfacing later as an unrelated reactor death.
            //
            // The delay is what makes this deterministic: without the wait, the probe wins every
            // time and the flag is still false when Start returns.
            bool ranToCompletion = false;

            TestServer.Start(
                static (_, conn) => { conn.DecRef(); return Task.CompletedTask; },
                _ =>
                {
                    Thread.Sleep(200);
                    ranToCompletion = true;
                });

            Assert.True(ranToCompletion,
                "Start returned while OnStart was still running - everything a test configures there is a race");
        });

        runner.Test("harness: a refusal thrown from OnStart reaches the caller", () =>
        {
            // The other half. Every "this configuration is refused" test in the suite asserts on an
            // exception from Start, and that exception is raised on the reactor thread inside
            // OnStart - so it only ever arrived in time because the probe happened to be slower.
            Assert.Throws<Exception>(
                () => TestServer.Start(
                    static (_, conn) => { conn.DecRef(); return Task.CompletedTask; },
                    _ =>
                    {
                        // Delayed on purpose. Thrown immediately it beats the probe on any machine
                        // fast enough to notice, which is how this test passed against the old
                        // harness too - proving the timing rather than the behaviour.
                        Thread.Sleep(200);
                        throw new InvalidOperationException("refused-on-purpose");
                    }),
                "refused-on-purpose");
        });

        runner.Test("core: shared recv survives buffer-group exhaustion (#93)", () =>
        {
            const int totalBytes = 24 * 1024;   // vs an 8 x 1 KiB group: guaranteed exhaustion while held
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, _, _) = TestServer.StartConfigured(
                HoldFirstThenDrain(release, totalBytes),
                new ServerConfig
                {
                    RecvBufferSize = 1024, RecvSlots = 8,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            DriveExhaustion(port, totalBytes, release);
        });

        runner.Test("core: incremental recv survives per-conn ring exhaustion (#93)", () =>
        {
            const int totalBytes = 12 * 1024;   // vs a 4 x 1 KiB per-conn ring
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, _, _) = TestServer.StartConfigured(
                HoldFirstThenDrain(release, totalBytes),
                new ServerConfig
                {
                    Incremental = new IncrementalOptions { MaxConnections = 8, RecvSlots = 4, RecvBufferSize = 1024 },
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            DriveExhaustion(port, totalBytes, release);
        }, skip: !TestServer.KernelAtLeast(6, 12));

        runner.Test("core: faulted handler releases the connection (#94)", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(
                async (_, _) =>
                {
                    await Task.Yield();
                    throw new InvalidOperationException("boom (test)");
                },
                new ServerConfig
                {
                    RecvBufferSize = 1024, RecvSlots = 64,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            // Stable() already waits out WaitForListen's probe connection recycling.
            int before = FdCount.Stable();

            for (int i = 0; i < 10; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                c.GetStream().Write("x"u8.ToArray());
                Thread.Sleep(20);
            }   // dispose closes the client; the server must observe EOF and recycle

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 3, $"{leaked} fds leaked by 10 faulted handlers (CLOSE_WAIT sockets)");
        });

        runner.Test("core: incremental accept past MaxConnections sheds, reactor survives (#92)", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(Handlers.Raw,
                new ServerConfig
                {
                    Incremental = new IncrementalOptions { MaxConnections = 4, RecvSlots = 4, RecvBufferSize = 1024 },
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            // Fill the reactor to its gid cap with live keep-alive connections. WaitForListen's
            // probe connection still holds a gid until the reactor recycles it, so the fourth slot
            // may not be free yet: retry rather than sleep a fixed 250 ms and hope. A loaded
            // machine misses that deadline and the fill below fails on a server that is fine.
            var held = new List<TcpClient>();
            for (int i = 0; i < 4; i++)
            {
                held.Add(ConnectServing(port, TimeSpan.FromSeconds(10)));
            }

            // Beyond the cap: the unfixed core threw in AllocGid and the reactor died here.
            for (int i = 0; i < 3; i++)
            {
                using var extra = new TcpClient();
                extra.Connect("127.0.0.1", port);
                extra.ReceiveTimeout = 1500;
                try
                {
                    _ = extra.GetStream().Read(new byte[1], 0, 1);   // shed = immediate close
                }
                catch
                {
                    // RST/timeout are both acceptable shed observations
                }
            }

            // The reactor must still serve the connections it already owns...
            GetOk(held[0]);

            // ...and accept fresh ones once capacity frees.
            held[3].Close();
            held.RemoveAt(3);

            // The gid returns when the reactor recycles that connection, which is its own event,
            // not a fixed interval - so retry until the capacity is actually back.
            using TcpClient fresh = ConnectServing(port, TimeSpan.FromSeconds(10));

            foreach (TcpClient c in held)
            {
                c.Close();
            }
        }, skip: !TestServer.KernelAtLeast(6, 12));

        runner.Test("core: incremental accept whose buffer ring the kernel refuses sheds, reactor survives", () =>
        {
            // The accept registers the connection's buffer ring, and the kernel charges it to
            // RLIMIT_MEMLOCK: a host short of locked memory gets -ENOMEM there. That threw out of the
            // accept and ended the reactor, where the gid cap beside it sheds the connection (#92).
            (int port, _, _) = TestServer.StartConfigured(Handlers.Raw,
                new ServerConfig
                {
                    Incremental = new IncrementalOptions { MaxConnections = 8, RecvSlots = 4, RecvBufferSize = 1024 },
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            // Served before the limit drops: the control, and a connection that must outlive the refusal.
            using TcpClient held = ConnectServing(port, TimeSpan.FromSeconds(10));

            Assert.Equal(0, getrlimit(RlimitMemlock, out RLimit original));
            using var refused = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                ReceiveTimeout = 5_000,
            };
            bool shed;
            try
            {
                // The soft limit only, so it can be put back. held's ring is already charged.
                var none = new RLimit { Cur = 0, Max = original.Max };
                Assert.Equal(0, setrlimit(RlimitMemlock, in none));

                refused.Connect(IPAddress.Loopback, port);
                refused.Send(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: t\r\n\r\n"));
                shed = Shed(refused);   // returns once the reactor has dealt with the accept
            }
            finally
            {
                setrlimit(RlimitMemlock, in original);
            }

            Assert.True(shed, "the connection accepted under a zero memlock limit was served, so its ring was never refused and nothing was tested");

            // The unfixed reactor died in that accept and closed held on its way down.
            GetOk(held);
            using TcpClient fresh = ConnectServing(port, TimeSpan.FromSeconds(10));
        }, skip: !TestServer.KernelAtLeast(6, 12) || HoldsIpcLock());
    }

    /// <summary>
    /// Connect and keep trying until the server answers, up to a deadline. Capacity in these tests
    /// frees on the reactor's own schedule (a recycle, a sweep), so waiting for the observable
    /// outcome is the only synchronization that holds on a slow machine.
    /// </summary>
    private static TcpClient ConnectServing(int port, TimeSpan timeout)
    {
        long deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        Exception? last = null;

        while (Environment.TickCount64 < deadline)
        {
            var candidate = new TcpClient();
            try
            {
                candidate.Connect("127.0.0.1", port);
                candidate.ReceiveTimeout = 1000;
                GetOk(candidate);
                candidate.ReceiveTimeout = 4000;
                return candidate;
            }
            catch (Exception e)
            {
                last = e;
                candidate.Dispose();
                Thread.Sleep(50);
            }
        }

        throw new Exception($"no connection served within {timeout.TotalSeconds}s: {last?.Message}");
    }

    private static void GetOk(TcpClient c)
    {
        NetworkStream s = c.GetStream();
        s.Write(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: t\r\n\r\n"));
        byte[] buf = new byte[256];
        int n = s.Read(buf, 0, buf.Length);
        Assert.True(n > 0 && Encoding.ASCII.GetString(buf, 0, n).Contains("200"),
            "keep-alive connection stopped responding");
    }

    // Reads once and holds the buffers until released, then drains until totalBytes arrived and
    // answers "done" - the starvation-then-recovery shape both #93 tests share.
    private static Func<Reactor, TcpConnection, Task> HoldFirstThenDrain(TaskCompletionSource release, int totalBytes)
        => async (_, conn) =>
        {
            try
            {
                long got = 0;
                bool held = false;
                while (true)
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    UnmanagedMemoryManager[] rings = conn.GetSnapshotMemories(snapshot);
                    foreach (UnmanagedMemoryManager m in rings)
                    {
                        got += m.Memory.Length;
                    }

                    if (!held && rings.Length > 0)
                    {
                        held = true;
                        await release.Task;   // hold the first buffers while the client floods
                    }
                    conn.ReturnBuffers(rings);

                    if (got >= totalBytes)
                    {
                        conn.Write("done"u8);
                        await conn.FlushAsync();
                    }
                    if (snapshot.IsClosed)
                    {
                        return;
                    }
                    conn.ResetRead();
                }
            }
            finally
            {
                conn.DecRef();
            }
        };

    private static void DriveExhaustion(int port, int totalBytes, TaskCompletionSource release)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 8000;
        NetworkStream stream = client.GetStream();

        byte[] payload = new byte[totalBytes];
        stream.Write(payload, 0, 1024);                    // handler reads this and parks holding it
        Thread.Sleep(150);
        stream.Write(payload, 1024, totalBytes - 1024);    // floods past the buffer group
        Thread.Sleep(300);                                 // unfixed core: -ENOBUFS teardown here
        release.SetResult();                               // buffers return; recv must resume

        byte[] reply = new byte[4];
        int n = stream.Read(reply, 0, 4);
        Assert.True(n == 4 && Encoding.ASCII.GetString(reply) == "done",
            "connection died during buffer-group exhaustion (expected it to stall and resume)");
    }

    private const int RlimitMemlock = 8;

    [StructLayout(LayoutKind.Sequential)]
    private struct RLimit
    {
        public ulong Cur;
        public ulong Max;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getrlimit(int resource, out RLimit limit);

    [DllImport("libc", SetLastError = true)]
    private static extern int setrlimit(int resource, in RLimit limit);

    // io_uring charges nothing to RLIMIT_MEMLOCK for a process with CAP_IPC_LOCK, so it cannot run out.
    private static bool HoldsIpcLock()
    {
        string? caps = File.ReadLines("/proc/self/status").FirstOrDefault(l => l.StartsWith("CapEff:", StringComparison.Ordinal));
        return caps is not null && (Convert.ToUInt64(caps["CapEff:".Length..].Trim(), 16) & (1UL << 14)) != 0;
    }

    // Closed without an answer: EOF, or a reset when the request was still unread at the close.
    private static bool Shed(Socket client)
    {
        try
        {
            return client.Receive(new byte[256]) == 0;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
        {
            return true;
        }
    }
}
