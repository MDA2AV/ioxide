using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// TcpOptions.Address: where a reactor's listeners bind. Checked against /proc and against connections, not against
/// what the reactor says, since a listener on the wildcard answers a test on loopback just as well.
/// </summary>
internal static class ListenerAddressTests
{
    private const string V4Loopback = "tcp 0100007F";
    private const string V4Any = "tcp 00000000";
    private const string V6Loopback = "tcp6 00000000000000000000000001000000";
    private const string V6Any = "tcp6 00000000000000000000000000000000";

    private static readonly bool NoIpv6 = !Socket.OSSupportsIPv6 || !File.Exists("/proc/net/tcp6") || !CanBind(IPAddress.IPv6Loopback);

    private static readonly IPAddress? OwnAddress = NetworkInterface.GetAllNetworkInterfaces()
        .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
        .Select(unicast => unicast.Address)
        .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);

    public static void Register(Runner runner)
    {
        runner.Test("tcp: a listener given IPv4 loopback listens there and nowhere else", () =>
        {
            Listening(new TcpOptions { Address = IPAddress.Loopback }, dualStack: false, port =>
            {
                Assert.Equal(V4Loopback, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.Loopback, port));
                Assert.True(!Accepts(IPAddress.IPv6Loopback, port), "IPv6 loopback was accepted");
                Assert.True(OwnAddress is null || !Accepts(OwnAddress, port), "this machine's own address was accepted");
            });
        });

        runner.Test("tcp: a listener given IPv6 loopback listens there and nowhere else", () =>
        {
            Listening(new TcpOptions { Address = IPAddress.IPv6Loopback }, dualStack: false, port =>
            {
                Assert.Equal(V6Loopback, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.IPv6Loopback, port));
                Assert.True(!Accepts(IPAddress.Loopback, port), "IPv4 loopback was accepted");
            });
        }, skip: NoIpv6);

        runner.Test("tcp: a listener given this machine's own address listens there and not on loopback", () =>
        {
            Listening(new TcpOptions { Address = OwnAddress }, dualStack: false, port =>
            {
                Assert.Equal(200, Get(OwnAddress!, port));
                Assert.True(!Accepts(IPAddress.Loopback, port), "IPv4 loopback was accepted");
            });
        }, skip: OwnAddress is null);

        runner.Test("tcp: a listener given 0.0.0.0 takes IPv4 only", () =>
        {
            Listening(new TcpOptions { Address = IPAddress.Any }, dualStack: false, port =>
            {
                Assert.Equal(V4Any, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.Loopback, port));
                Assert.True(!Accepts(IPAddress.IPv6Loopback, port), "IPv6 loopback was accepted");
            });
        });

        runner.Test("tcp: a listener given :: takes both families", () =>
        {
            Listening(new TcpOptions { Address = IPAddress.IPv6Any }, dualStack: false, port =>
            {
                Assert.Equal(V6Any, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.IPv6Loopback, port));
                Assert.Equal(200, Get(IPAddress.Loopback, port));
            });
        }, skip: NoIpv6);

        runner.Test("tcp: an address decides the family, whatever DualStack says", () =>
        {
            Listening(new TcpOptions { Address = IPAddress.Loopback }, dualStack: true, port =>
            {
                Assert.Equal(V4Loopback, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.Loopback, port));
            });
        });

        runner.Test("tcp: control: no address is every IPv4 interface", () =>
        {
            Listening(new TcpOptions(), dualStack: false, port =>
            {
                Assert.Equal(V4Any, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.Loopback, port));
            });
        });

        runner.Test("tcp: control: no address under DualStack is every interface of both families", () =>
        {
            Listening(new TcpOptions(), dualStack: true, port =>
            {
                Assert.Equal(V6Any, string.Join(", ", Rows(port)));
                Assert.Equal(200, Get(IPAddress.IPv6Loopback, port));
                Assert.Equal(200, Get(IPAddress.Loopback, port));
            });
        }, skip: NoIpv6);

        runner.Test("tcp: ExtraPorts bind the same address", () =>
        {
            ushort extra = (ushort)TestServer.NextPort();
            Listening(new TcpOptions { Address = IPAddress.Loopback, ExtraPorts = [extra] }, dualStack: false, port =>
            {
                Assert.Equal(V4Loopback, string.Join(", ", Rows(port)));
                Assert.Equal(V4Loopback, string.Join(", ", Rows(extra)));
                Assert.Equal(200, Get(IPAddress.Loopback, extra));
            });
        });

        runner.Test("tcp: several reactors share an address", () =>
        {
            Listening(new TcpOptions { Address = IPAddress.Loopback }, dualStack: false, port =>
            {
                Assert.Equal(V4Loopback, string.Join(", ", Rows(port)));
                for (int i = 0; i < 16; i++)
                {
                    Assert.Equal(200, Get(IPAddress.Loopback, port));
                }
            }, reactors: 2);
        });

        runner.Test("tcp: an address this machine doesn't have stops the reactor, naming it", () =>
        {
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.NextPort();
            var reactor = new Reactor(0, new ServerConfig { Tcp = new TcpOptions { Port = (ushort)port, Address = IPAddress.Parse("192.0.2.1") } })
            {
                TcpHandle = Handlers.Raw,
                OnFault = (_, e) => failed.TrySetResult(e),
            };

            var thread = new Thread(reactor.Run) { IsBackground = true };
            thread.Start();

            Assert.True(failed.Task.Wait(5_000), "no fault was reported");
            string message = failed.Task.Result.Message;
            Assert.True(message.Contains("bind failed") && message.Contains("192.0.2.1"), message);
            Assert.True(thread.Join(5_000), "the reactor did not stop");
        });
    }

    // Started directly: the harness waits on 127.0.0.1, which most of these must refuse.
    private static void Listening(TcpOptions tcp, bool dualStack, Action<int> check, int reactors = 1)
    {
        int port = tcp.Port != 8080 ? tcp.Port : TestServer.NextPort();
        var config = new ServerConfig { ReactorCount = reactors, DualStack = dualStack, RecvBufferSize = 4096, RecvSlots = 64, Tcp = tcp with { Port = (ushort)port } };

        var running = new List<(Reactor Reactor, Thread Thread)>();
        using var started = new CountdownEvent(reactors);
        try
        {
            for (int i = 0; i < reactors; i++)
            {
                var reactor = new Reactor(i, config)
                {
                    TcpHandle = Handlers.Raw,
                    OnStart = _ => started.Signal(),
                };

                var thread = new Thread(reactor.Run) { IsBackground = true };
                thread.Start();
                running.Add((reactor, thread));
            }

            Assert.True(started.Wait(5_000), "the reactors never came up");
            check(port);
        }
        finally
        {
            foreach ((Reactor reactor, Thread thread) in running)
            {
                reactor.Stop();
                Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "a reactor did not stop");
            }
        }
    }

    private static string[] Rows(int port)
    {
        var rows = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string family in new[] { "tcp", "tcp6" })
        {
            string path = $"/proc/net/{family}";
            if (!File.Exists(path))
            {
                continue;
            }

            foreach (string line in File.ReadLines(path).Skip(1))
            {
                string[] row = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                int colon = row[1].IndexOf(':');
                if (row[3] == "0A" && Convert.ToInt32(row[1][(colon + 1)..], 16) == port)
                {
                    rows.Add($"{family} {row[1][..colon]}");
                }
            }
        }

        return rows.ToArray();
    }

    private static int Get(IPAddress address, int port)
    {
        using var client = new TcpClient(address.AddressFamily);
        client.ReceiveTimeout = 5_000;
        client.Connect(address, port);

        using NetworkStream stream = client.GetStream();
        Client.Send(stream, "/");
        return Client.ReadResponse(stream).Status;
    }

    private static bool Accepts(IPAddress address, int port)
    {
        try
        {
            using var client = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(address, port);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static bool CanBind(IPAddress address)
    {
        try
        {
            using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(address, 0));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
