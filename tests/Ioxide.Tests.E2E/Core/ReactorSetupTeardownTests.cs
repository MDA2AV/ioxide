using System.Net;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Teardown after a setup that FAILED. Run tears the ring down on every exit path, including a
/// throw from the setup sequence itself, so the fd tables it closes may only be half filled.
/// </summary>
/// <remarks>
/// The tables are <c>new int[n]</c>, so an unset slot reads as 0 - stdin, not something this
/// library opened. Closing it is the opposite of a leak: the number goes back to the process, the
/// next socket opened takes it, and the next teardown to close 0 shuts somebody else's live
/// connection. Same for <c>_wakeFd</c>, which OpenWakeFd sets only near the end of setup.
///
/// /proc/self/fd/0 answers whether fd 0 is open without a P/Invoke: it exists while it does.
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
            // and without privilege. The throw lands in OpenTcpListeners, which runs before
            // OpenWakeFd: _listenFds[0] and _wakeFd are both still 0 when the finally tears down.
            using var blocker = new TcpListener(IPAddress.Any, 0);
            blocker.Start();
            int port = ((IPEndPoint)blocker.LocalEndpoint).Port;

            var config = new ServerConfig
            {
                ReactorCount = 1,
                Tcp = new TcpOptions { Port = (ushort)port },
            };
            var reactor = new Reactor(0, config)
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

        runner.Test("reactor: a ring the kernel refuses reaches OnFault instead of ending the process", () =>
        {
            // Every kernel refuses more than 32768 entries with EINVAL - the errno a kernel older than
            // 6.1 gives for SINGLE_ISSUER | DEFER_TASKRUN (#270). Ring.Create ran outside the try that
            // hands faults to OnFault, so a host that asked to hear of faults lost the process instead.
            Exception? reported = null;
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, RingEntries = 65_536 })
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

            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "Run should have returned after the ring was refused");
            Assert.True(escaped is null,
                $"the refused ring was thrown out of Run past OnFault - on a host's thread, that ends the process: {escaped?.Message}");
            Assert.True(reported is InvalidOperationException, $"OnFault was not told: {reported}");
            Assert.True(reported!.Message.Contains("32768"),
                $"the message does not say what the kernel refused: {reported.Message}");
        });

        runner.Test("reactor: OnFault is raised before the teardown, with the listener still open", () =>
        {
            // Run calls OnFault from its catch and tears down in its finally, so a host's handler
            // runs against a reactor that is still whole - the doc said the opposite. A throw from
            // OnStart reaches the same catch as a fault in the loop, after the listener is bound.
            int port = TestServer.NextPort();
            Exception? reported = null;
            bool? listeningInOnFault = null;

            var reactor = new Reactor(0, new ServerConfig
            {
                ReactorCount = 1,
                RecvBufferSize = 4096,
                RecvSlots = 256,
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

    // ServerConfig.Tcp defaulted to new(), a listener on 8080, so a config that never asked for TCP bound
    // 8080 anyway - a QUIC-only one too, whose TcpHandle is never set (#191). The listeners are read off
    // /proc rather than probed, so nothing here binds or connects to 8080, which other processes may hold.
    private static void RegisterTcpOptIn(Runner runner)
    {
        runner.Test("reactor: a config that never sets Tcp opens no TCP listener, empty or QUIC-only", () =>
        {
            ServerConfig[] configs =
            [
                new ServerConfig { ReactorCount = 1 },
                new ServerConfig { ReactorCount = 1, Quic = new QuicOptions { Port = (ushort)TestServer.NextPort() } },
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
