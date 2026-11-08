using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// TcpOptions.Address, UdpOptions.Address and QuicOptions.Address: where a reactor's sockets bind. Checked against /proc
/// and against traffic, not against what the reactor says, since a socket on the wildcard answers a test on loopback
/// just as well.
/// </summary>
internal static class ListenerAddressTests
{
    private const string V4Loopback = "tcp 0100007F";
    private const string V4Any = "tcp 00000000";
    private const string V6Loopback = "tcp6 00000000000000000000000001000000";
    private const string V6Any = "tcp6 00000000000000000000000000000000";
    private const string UdpV4Loopback = "udp 0100007F";
    private const string UdpV4Any = "udp 00000000";
    private const string UdpV6Loopback = "udp6 00000000000000000000000001000000";
    private const string UdpV6Any = "udp6 00000000000000000000000000000000";

    // The ECN codepoint ECT(0) in the traffic class, which is where QUIC reads ECN from.
    private const int IpprotoIpv6 = 41;
    private const int Ipv6Tclass = 67;
    private const byte EcnEct0 = 0b10;

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

        runner.Test("udp: a socket given IPv4 loopback binds there and nowhere else", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port], Address = IPAddress.Loopback }, quic: null, dualStack: false, () =>
            {
                Assert.Equal(UdpV4Loopback, string.Join(", ", Rows(port, "udp")));
                Assert.Equal("ping", Echo(IPAddress.Loopback, port));
                Assert.True(Echo(IPAddress.IPv6Loopback, port, 500) is null, "IPv6 loopback was answered");
                Assert.True(OwnAddress is null || Echo(OwnAddress, port, 500) is null, "this machine's own address was answered");
            });
        });

        runner.Test("udp: a socket given IPv6 loopback binds there and nowhere else", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port], Address = IPAddress.IPv6Loopback }, quic: null, dualStack: false, () =>
            {
                Assert.Equal(UdpV6Loopback, string.Join(", ", Rows(port, "udp")));
                Assert.Equal("ping", Echo(IPAddress.IPv6Loopback, port));
                Assert.True(Echo(IPAddress.Loopback, port, 500) is null, "IPv4 loopback was answered");
            });
        }, skip: NoIpv6);

        runner.Test("udp: a socket given :: takes both families", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port], Address = IPAddress.IPv6Any }, quic: null, dualStack: false, () =>
            {
                Assert.Equal(UdpV6Any, string.Join(", ", Rows(port, "udp")));
                Assert.Equal("ping", Echo(IPAddress.IPv6Loopback, port));
                Assert.Equal("ping", Echo(IPAddress.Loopback, port));
            });
        }, skip: NoIpv6);

        runner.Test("udp: an address decides the family, whatever DualStack says", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port], Address = IPAddress.Loopback }, quic: null, dualStack: true, () =>
            {
                Assert.Equal(UdpV4Loopback, string.Join(", ", Rows(port, "udp")));
                Assert.Equal("ping", Echo(IPAddress.Loopback, port));
            });
        });

        runner.Test("udp: control: no address is every IPv4 interface", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port] }, quic: null, dualStack: false, () =>
            {
                Assert.Equal(UdpV4Any, string.Join(", ", Rows(port, "udp")));
                Assert.Equal("ping", Echo(IPAddress.Loopback, port));
            });
        });

        runner.Test("udp: every port binds the same address", () =>
        {
            int port = TestServer.NextPort(), extra = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port, (ushort)extra], Address = IPAddress.Loopback }, quic: null, dualStack: false, () =>
            {
                Assert.Equal(UdpV4Loopback, string.Join(", ", Rows(port, "udp")));
                Assert.Equal(UdpV4Loopback, string.Join(", ", Rows(extra, "udp")));
                Assert.Equal("ping", Echo(IPAddress.Loopback, extra));
            });
        });

        // An IPv6 socket reports the traffic class only when asked, and DualStack used to be what asked.
        runner.Test("udp: a socket given an IPv6 address reads the traffic class, where ECN is", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port], Address = IPAddress.IPv6Loopback }, quic: null, dualStack: false,
                () => Assert.Equal(EcnEct0, TrafficClassSeen(port)), onDatagram: EchoTos);
        }, skip: NoIpv6);

        runner.Test("udp: control: a dual-stack socket with no address reads the traffic class", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)port] }, quic: null, dualStack: true,
                () => Assert.Equal(EcnEct0, TrafficClassSeen(port)), onDatagram: EchoTos);
        }, skip: NoIpv6);

        runner.Test("udp: an address this machine doesn't have stops the reactor, naming it", () =>
        {
            var failed = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.NextPort();
            var reactor = new Reactor(0, new ServerConfig { Udp = new UdpOptions { Ports = [(ushort)port], Address = IPAddress.Parse("192.0.2.1") } })
            {
                OnFault = (_, e) => failed.TrySetResult(e),
            };

            var thread = new Thread(reactor.Run) { IsBackground = true };
            thread.Start();

            Assert.True(failed.Task.Wait(5_000), "no fault was reported");
            string message = failed.Task.Result.Message;
            Assert.True(message.Contains("udp bind failed") && message.Contains("192.0.2.1"), message);
            Assert.True(thread.Join(5_000), "the reactor did not stop");
        });

        runner.Test("quic: a socket given IPv4 loopback serves there and nowhere else", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions(), Quic(port, IPAddress.Loopback), dualStack: false, () =>
            {
                Assert.Equal(UdpV4Loopback, string.Join(", ", Rows(port, "udp")));
                Assert.Equal(200, H3Get(IPAddress.Loopback, port));
                Assert.True(OwnAddress is null || !H3Handshakes(OwnAddress, port), "this machine's own address was answered");
            });
        });

        runner.Test("quic: a socket given IPv6 loopback serves there and nowhere else", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions(), Quic(port, IPAddress.IPv6Loopback), dualStack: false, () =>
            {
                Assert.Equal(UdpV6Loopback, string.Join(", ", Rows(port, "udp")));
                Assert.Equal(200, H3Get(IPAddress.IPv6Loopback, port));
                Assert.True(!H3Handshakes(IPAddress.Loopback, port), "IPv4 loopback was answered");
            });
        }, skip: NoIpv6);

        runner.Test("quic: a socket given :: serves both families", () =>
        {
            int port = TestServer.NextPort();
            Datagrams(new UdpOptions(), Quic(port, IPAddress.IPv6Any), dualStack: false, () =>
            {
                Assert.Equal(UdpV6Any, string.Join(", ", Rows(port, "udp")));
                Assert.Equal(200, H3Get(IPAddress.IPv6Loopback, port));
                Assert.Equal(200, H3Get(IPAddress.Loopback, port));
            });
        }, skip: NoIpv6);

        runner.Test("quic: the QUIC port binds QUIC's address even when Udp.Ports lists it, and the other UDP ports bind UDP's", () =>
        {
            int raw = TestServer.NextPort(), port = TestServer.NextPort();
            Datagrams(new UdpOptions { Ports = [(ushort)raw, (ushort)port], Address = IPAddress.Loopback }, Quic(port, IPAddress.Any), dualStack: false, () =>
            {
                Assert.Equal(UdpV4Loopback, string.Join(", ", Rows(raw, "udp")));
                Assert.Equal(UdpV4Any, string.Join(", ", Rows(port, "udp")));
                Assert.Equal("ping", Echo(IPAddress.Loopback, raw));
                Assert.Equal(200, H3Get(IPAddress.Loopback, port));
            });
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

    // Started directly, as Listening is. Raw UDP datagrams are echoed, and QUIC answers h3 requests.
    private static void Datagrams(UdpOptions udp, QuicOptions? quic, bool dualStack, Action check, UdpDatagramHandler? onDatagram = null)
    {
        var config = new ServerConfig { DualStack = dualStack, RecvBufferSize = 4096, RecvSlots = 64, Udp = udp, Quic = quic };
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reactor = new Reactor(0, config)
        {
            OnDatagram = onDatagram ?? (static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload)),
            QuicHandle = static (_, conn) => new Nghttp3Connection(conn).RunAsync(static _ => Nghttp3Response.Text("ok")),
            OnStart = _ => started.TrySetResult(),
            OnFault = (_, e) => started.TrySetException(e),
        };

        var thread = new Thread(reactor.Run) { IsBackground = true };
        thread.Start();
        try
        {
            Assert.True(started.Task.Wait(5_000), "the reactor never came up");
            check();
        }
        finally
        {
            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");
        }
    }

    private static QuicOptions Quic(int port, IPAddress address)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        QuicEngine engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
        return new QuicOptions { Port = (ushort)port, Address = address, LocalCidLength = 8, ConnectionFactory = engine.CreateFactory() };
    }

    // What came back, or null when nothing did in time.
    private static string? Echo(IPAddress address, int port, int timeoutMs = 5_000)
    {
        try
        {
            using var client = new UdpClient(address.AddressFamily);
            client.Client.ReceiveTimeout = timeoutMs;
            client.Send("ping"u8.ToArray(), 4, new IPEndPoint(address, port));
            IPEndPoint? from = null;
            return Encoding.ASCII.GetString(client.Receive(ref from));
        }
        catch (SocketException)
        {
            return null;
        }
    }

    private static void EchoTos(Reactor reactor, in UdpDatagram datagram)
        => reactor.UdpSendTo(datagram.SocketFd, datagram.PeerAddr, datagram.PeerAddrLen, new[] { datagram.Tos });

    // Sends over IPv6 loopback marked ECT(0), and returns the traffic class the server says it saw.
    private static byte TrafficClassSeen(int port)
    {
        using var client = new UdpClient(AddressFamily.InterNetworkV6);
        client.Client.ReceiveTimeout = 5_000;
        client.Client.SetRawSocketOption(IpprotoIpv6, Ipv6Tclass, BitConverter.GetBytes((int)EcnEct0));
        client.Send("tos"u8.ToArray(), 3, new IPEndPoint(IPAddress.IPv6Loopback, port));
        IPEndPoint? from = null;
        return client.Receive(ref from)[0];
    }

    private static int H3Get(IPAddress address, int port)
    {
        using var client = new H3TestClient(address.ToString(), port);
        client.Connect();
        Assert.True(client.CompleteHandshake(10_000), $"no handshake over {address}");
        return client.Request("GET", "/", null, 10_000).Status;
    }

    private static bool H3Handshakes(IPAddress address, int port)
    {
        try
        {
            using var client = new H3TestClient(address.ToString(), port);
            client.Connect();
            return client.CompleteHandshake(1_000);
        }
        catch (SocketException)
        {
            return false;   // no such family here
        }
    }

    // TCP's listening sockets, or UDP's bound ones that aren't connected, which leaves out QUIC's claimed peers.
    private static string[] Rows(int port, string protocol = "tcp")
    {
        string state = protocol == "tcp" ? "0A" : "07";
        var rows = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string family in new[] { protocol, protocol + "6" })
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
                if (row[3] == state && Convert.ToInt32(row[1][(colon + 1)..], 16) == port)
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
