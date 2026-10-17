using System.Net;
using System.Net.Sockets;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Teardown after a setup that FAILED. Run tears down on every exit path, including a throw from
/// the setup sequence itself, so the descriptor tables it closes may only be half filled. And what
/// the teardown after a stop frees.
/// </summary>
/// <remarks>
/// A table filled with <c>new int[n]</c> reads 0 in every unset slot - stdin, not something this
/// library opened. Closing it is the opposite of a leak: the number goes back to the process, the
/// next socket opened takes it, and the next teardown to close 0 shuts somebody else's live
/// connection.
///
/// /proc/self/fd/0 answers whether fd 0 is open without a P/Invoke: it exists while it does.
///
/// Translated: ioxide's "a ring the kernel refuses reaches OnFault" - epoxide has no ring, so the
/// setup failure that reaches OnFault is the listener's refused bind. Not ported: the incremental
/// variant of "a stop frees its pooled connections" - epoxide has no per-connection buffer ring.
/// </remarks>
internal static class ReactorSetupTeardownTests
{
    public static void Register(Runner runner)
    {
        RegisterTcpOptIn(runner);

        runner.Test("reactor: a bind that fails tears down without closing stdin", () =>
        {
            Assert.True(File.Exists("/proc/self/fd/0"), "fd 0 must be open before the test says anything");

            // A SO_REUSEPORT bind is refused unless EVERY socket on the port asked for it, and a
            // plain listener asks for nothing - so this bind fails with EADDRINUSE, deterministically
            // and without privilege. The throw lands in OpenTcpListeners, with the listener table
            // half filled.
            using var blocker = new TcpListener(IPAddress.Any, 0);
            blocker.Start();
            int port = ((IPEndPoint)blocker.LocalEndpoint).Port;

            var reactor = new Reactor(0, new ServerConfig
            {
                ReactorCount = 1,
                Tcp = new TcpOptions { Port = (ushort)port },
            })
            {
                TcpHandle = (_, connection) =>
                {
                    connection.DecRef();
                    return Task.CompletedTask;
                },
            };

            Exception? failure = null;
            var thread = new Thread(() =>
            {
                try
                {
                    reactor.Run();
                }
                catch (Exception e)
                {
                    failure = e;
                }
            });
            thread.Start();

            Assert.True(thread.Join(TimeSpan.FromSeconds(10)),
                "the reactor should have failed its bind and returned, not parked in the loop");
            Assert.True(failure is not null,
                "binding a port already held without SO_REUSEPORT must fail the reactor");

            Assert.True(File.Exists("/proc/self/fd/0"),
                "teardown after the failed bind closed fd 0 - stdin - and the number is now free "
                + "for the next socket the process opens");
        });

        runner.Test("reactor: a setup the kernel refuses reaches OnFault instead of ending the process", () =>
        {
            // The same refused bind, with a host that asked to hear of faults: it must hear of this
            // one, which ends the reactor during setup, rather than have it thrown out of Run - on a
            // bare new Thread(reactor.Run), that ends the process.
            using var blocker = new TcpListener(IPAddress.Any, 0);
            blocker.Start();
            int port = ((IPEndPoint)blocker.LocalEndpoint).Port;

            Exception? reported = null;
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = new TcpOptions { Port = (ushort)port } })
            {
                TcpHandle = (_, connection) =>
                {
                    connection.DecRef();
                    return Task.CompletedTask;
                },
                OnFault = (_, e) => reported = e,
            };

            Exception? escaped = null;
            var thread = new Thread(() =>
            {
                try
                {
                    reactor.Run();
                }
                catch (Exception e)
                {
                    escaped = e;
                }
            });
            thread.Start();

            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "Run should have returned after the bind was refused");
            Assert.True(escaped is null,
                $"the refused bind was thrown out of Run past OnFault - on a host's thread, that ends the process: {escaped?.Message}");
            Assert.True(reported is InvalidOperationException, $"OnFault was not told: {reported}");
            Assert.True(reported!.Message.Contains($":{port}") && reported.Message.Contains("errno 98"),
                $"the message does not say what the kernel refused: {reported.Message}");
        });

        runner.Test("reactor: OnFault is raised before the teardown, with the listener still open", () =>
        {
            // Run calls OnFault from its catch and tears down in its finally, so a host's handler
            // runs against a reactor that is still whole. A throw from OnStart reaches the same
            // catch as a fault in the loop, after the listener is bound.
            int port = TestServer.NextPort();
            Exception? reported = null;
            bool? listeningInOnFault = null;

            var reactor = new Reactor(0, new ServerConfig
            {
                ReactorCount = 1,
                RecvBufferSize = 4096,
                Tcp = new TcpOptions { Port = (ushort)port },
            })
            {
                TcpHandle = (_, connection) =>
                {
                    connection.DecRef();
                    return Task.CompletedTask;
                },
                OnStart = _ => throw new InvalidOperationException("fault-on-purpose"),
                OnFault = (_, e) =>
                {
                    reported = e;
                    listeningInOnFault = Accepts(port);
                },
            };

            var thread = new Thread(reactor.Run) { IsBackground = true };
            thread.Start();

            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "Run should have returned after OnStart threw");
            Assert.True(reported is InvalidOperationException { Message: "fault-on-purpose" },
                $"OnFault was not told of the fault: {reported}");
            Assert.True(listeningInOnFault == true,
                "the listener was already closed when OnFault ran, so the teardown came first");

            // Control: the same probe sees the listener gone once the teardown has run.
            Assert.True(!Accepts(port), "the listener still accepted after Run returned, so the probe cannot tell");
        });

        RegisterStopFrees(runner);
    }

    private const int SlabSize = 4096;
    private const int ResponseBytes = 3 * SlabSize;

    // A pooled connection owns native memory - its write slab - and so do the reactor's pools of spare
    // write slabs and recv buffers. A stop that freed none of them would leak them every time a host
    // starts and stops a server, since a connection has no finalizer (ioxide's #223).
    private static void RegisterStopFrees(Runner runner)
    {
        runner.Test("reactor: a stop frees its pooled connections, its spare write slabs and its recv buffers (segmented writes)", () =>
        {
            var config = new ServerConfig
            {
                RecvBufferSize = 4096,
                Tcp = new TcpOptions
                {
                    WriteSlabSize = SlabSize,
                    PoolMax = 8,
                    RecvQueueEntries = 64,
                    WriteOverflow = WriteOverflowStrategy.Segmented,
                },
            };

            TcpConnection? kept = null;
            int keptGeneration = 0;
            int spareSlabs = 0;
            using var released = new ManualResetEventSlim();

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    Wire.ReadPath(conn, snapshot);
                    if (snapshot.IsClosed)
                    {
                        return;   // the harness's readiness probe, which sends no request
                    }
                    conn.ResetRead();

                    conn.Write(new byte[ResponseBytes]);   // past the slab, so a segmented write rents spare slabs
                    await conn.FlushAsync();
                    spareSlabs = Internals.WriteSlabPool(r).Total;   // handed back as the flush completed
                    keptGeneration = Internals.Generation(conn);
                    kept = conn;

                    // Held until the client closes: the reactor then recycles it in the same dispatch
                    // that wakes this read, before its loop can see the stop.
                    while (!(snapshot = await conn.ReadAsync()).IsClosed)
                    {
                        Wire.ReadPath(conn, snapshot);
                        conn.ResetRead();
                    }
                }
                finally
                {
                    conn.DecRef();
                    if (ReferenceEquals(kept, conn))
                    {
                        released.Set();
                    }
                }
            }, config);

            using (var client = new TcpClient())
            {
                client.Connect(IPAddress.Loopback, port);
                NetworkStream stream = client.GetStream();
                stream.Write("GET / HTTP/1.1\r\n\r\n"u8);
                stream.ReadExactly(new byte[ResponseBytes]);
            }

            Assert.True(released.Wait(TimeSpan.FromSeconds(10)), "the handler never saw the client close");
            Assert.True(SpinWait.SpinUntil(() => Internals.Generation(kept!) != keptGeneration, 5_000),
                "the connection was never recycled, so it never reached the pool");
            Assert.True(Internals.InPool(reactor, kept!), "the recycled connection is not in the pool, so a stop had nothing of it to free");

            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");

            Assert.True(!Internals.HasWriteBuffer(kept!), "the pooled connection's write slab outlived its reactor");

            Assert.True(spareSlabs > 0, "the response never spilled past the slab, so no spare slab was pooled");
            Internals.PoolCount slabs = Internals.WriteSlabPool(reactor);
            Assert.True(slabs.Total == 0, $"{slabs.Total} spare write slabs outlived their reactor");

            Internals.PoolCount recv = Internals.RecvPool(reactor);
            Assert.True(recv.Total == 0, $"{recv.Total} recv buffers outlived their reactor");
        });
    }

    // A connect completes into a listener's backlog without anyone accepting, so it succeeds exactly
    // while the listening socket is open.
    private static bool Accepts(int port)
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            probe.Connect(IPAddress.Loopback, port);
            return true;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return false;
        }
    }

    // ServerConfig.Tcp is null by default, a reactor for outbound connections only (ioxide's #191:
    // its Tcp defaulted to new(), a listener on 8080). The listeners are read off /proc rather than
    // probed, so nothing here binds or connects to 8080, which other processes may hold.
    private static void RegisterTcpOptIn(Runner runner)
    {
        runner.Test("reactor: a config that never sets Tcp opens no TCP listener", () =>
        {
            ServerConfig[] configs =
            [
                new ServerConfig { ReactorCount = 1 },
                new ServerConfig { ReactorCount = 1, MaxEvents = 64, RecvBufferSize = 8192, DualStack = true },
            ];

            foreach (ServerConfig config in configs)
            {
                // Before any reactor runs: one that asks for a listener would bind the shared 8080.
                Assert.True(config.Tcp is null, $"a config that never set Tcp asks for a TCP listener on {config.Tcp?.Port}");

                HashSet<string> opened = ListenersOpenedBy(config);
                Assert.True(opened.Count == 0, $"the reactor opened TCP listeners: {string.Join(", ", opened)}");
            }
        });

        runner.Test("control: a config that sets Tcp opens its listener, and the same probe sees it", () =>
        {
            var config = new ServerConfig { ReactorCount = 1, Tcp = new TcpOptions { Port = (ushort)TestServer.NextPort() } };

            Assert.True(ListenersOpenedBy(config).Count == 1, "the probe did not see the one listener the config asked for");
        });
    }

    // The TCP listeners this process gained while a reactor ran config; Run binds them before OnStart.
    private static HashSet<string> ListenersOpenedBy(ServerConfig config)
    {
        HashSet<string> before = ListeningSockets();
        Exception? fault = null;
        using var started = new ManualResetEventSlim();

        var reactor = new Reactor(0, config)
        {
            TcpHandle = (_, connection) =>
            {
                connection.DecRef();
                return Task.CompletedTask;
            },
            OnStart = _ => started.Set(),
            OnFault = (_, e) => fault = e,
        };
        var thread = new Thread(reactor.Run) { IsBackground = true };
        thread.Start();

        try
        {
            Assert.True(started.Wait(TimeSpan.FromSeconds(10)), $"the reactor never reached OnStart: {fault?.Message}");

            HashSet<string> opened = ListeningSockets();
            opened.ExceptWith(before);
            return opened;
        }
        finally
        {
            reactor.Stop();
            thread.Join(TimeSpan.FromSeconds(10));
        }
    }

    // This process's listening TCP sockets, v4 and v6: rows in state 0A whose inode a descriptor here holds.
    private static HashSet<string> ListeningSockets()
    {
        var listening = new HashSet<string>();
        foreach (string table in (string[])["/proc/self/net/tcp", "/proc/self/net/tcp6"])
        {
            foreach (string row in File.ReadLines(table).Skip(1))
            {
                string[] f = row.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (f[3] == "0A")
                {
                    listening.Add($"socket:[{f[9]}]");
                }
            }
        }

        var mine = new HashSet<string>();
        foreach (string fd in Directory.EnumerateFileSystemEntries("/proc/self/fd"))
        {
            try
            {
                if (new FileInfo(fd).LinkTarget is { } target && listening.Contains(target))
                {
                    mine.Add(target);
                }
            }
            catch (IOException)
            {
                // Closed between the listing and the read.
            }
        }

        return mine;
    }
}
