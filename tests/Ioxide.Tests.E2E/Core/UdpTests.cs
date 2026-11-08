using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>UDP transport: RECVMSG slots, per-datagram addressing, GSO, and datagram edge cases.</summary>
internal static class UdpTests
{
    public static void Register(Runner runner)
    {
        runner.Test("core: udp echo (3 datagrams, one socket)", () =>
        {
            (_, int udpPort) = TestServer.StartDatagram(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload));

            using var client = new UdpClient();
            client.Client.ReceiveTimeout = 4000;
            var server = new IPEndPoint(IPAddress.Loopback, udpPort);

            for (int i = 0; i < 3; i++)
            {
                byte[] ping = Encoding.ASCII.GetBytes($"ping-{i}");
                client.Send(ping, ping.Length, server);
                IPEndPoint? from = null;
                byte[] reply = client.Receive(ref from);
                Assert.Equal($"ping-{i}", Encoding.ASCII.GetString(reply));
            }
        });

        // One socket on [::] serves both families: IPv4 peers reach it as IPv4-mapped addresses.
        runner.Test("core: a dual-stack udp socket takes datagrams over IPv4", () => DualStackEcho(IPAddress.Loopback),
            skip: !Socket.OSSupportsIPv6);

        runner.Test("core: a dual-stack udp socket takes datagrams over IPv6", () => DualStackEcho(IPAddress.IPv6Loopback),
            skip: !Ipv6LoopbackUp());

        // SO_REUSEPORT is how the port is shared: between the reactors, a migrated peer's claim, and other processes of
        // the same user. A socket that doesn't set it gets no share.
        runner.Test("core: a socket that doesn't set SO_REUSEPORT can't bind a reactor's udp port", () =>
        {
            (_, int udpPort) = TestServer.StartDatagram(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload));
            RefusedWithoutReusePort(udpPort);
        });

        runner.Test("core: a socket that doesn't set SO_REUSEPORT can't bind a reactor's quic port", () =>
        {
            (_, int quicPort) = TestServer.StartDatagram(onDatagram: null,
                quicFactory: static (Reactor _, in UdpDatagram _, in QuicCid _) => null);
            RefusedWithoutReusePort(quicPort);
        });

        runner.Test("core: control: a socket that sets SO_REUSEPORT still shares a reactor's udp port", () =>
        {
            (_, int udpPort) = TestServer.StartDatagram(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload));
            using var other = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            other.SetRawSocketOption(SolSocket, SoReusePort, BitConverter.GetBytes(1));
            other.Bind(new IPEndPoint(IPAddress.Any, udpPort));
        });

        runner.Test("core: udp 8 KiB payload + two clients (per-datagram addressing)", () =>
        {
            (_, int udpPort) = TestServer.StartDatagram(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload));

            var server = new IPEndPoint(IPAddress.Loopback, udpPort);
            using var a = new UdpClient();
            using var b = new UdpClient();
            a.Client.ReceiveTimeout = 4000;
            b.Client.ReceiveTimeout = 4000;

            byte[] big = new byte[8192];
            Random.Shared.NextBytes(big);
            byte[] small = Encoding.ASCII.GetBytes("from-b");

            a.Send(big, big.Length, server);
            b.Send(small, small.Length, server);

            IPEndPoint? from = null;
            byte[] replyA = a.Receive(ref from);
            byte[] replyB = b.Receive(ref from);
            Assert.True(replyA.AsSpan().SequenceEqual(big), "8 KiB echo mismatch");
            Assert.Equal("from-b", Encoding.ASCII.GetString(replyB));
        });

        runner.Test("core: udp gso reply (UDP_SEGMENT splits one submit into wire datagrams)", () =>
        {
            (_, int udpPort) = TestServer.StartDatagram(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload, gsoSegmentSize: 4));

            using var client = new UdpClient();
            client.Client.ReceiveTimeout = 4000;
            var server = new IPEndPoint(IPAddress.Loopback, udpPort);
            IPEndPoint? from = null;

            byte[] batch = Encoding.ASCII.GetBytes("abcdefgh");
            client.Send(batch, batch.Length, server);
            Assert.Equal("abcd", Encoding.ASCII.GetString(client.Receive(ref from)));
            Assert.Equal("efgh", Encoding.ASCII.GetString(client.Receive(ref from)));
        });

        runner.Test("core: udp zero-length datagram round-trips", () =>
        {
            (_, int udpPort) = TestServer.StartDatagram(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload));

            using var client = new UdpClient();
            client.Client.ReceiveTimeout = 4000;
            var server = new IPEndPoint(IPAddress.Loopback, udpPort);
            IPEndPoint? from = null;

            client.Send([], 0, server);   // a 0-byte datagram is legal UDP
            byte[] empty = client.Receive(ref from);
            Assert.Equal(0, empty.Length);

            client.Send("x"u8.ToArray(), 1, server);   // and the slot re-armed fine after it
            Assert.Equal("x", Encoding.ASCII.GetString(client.Receive(ref from)));
        });

        runner.Test("core: udp burst past the ring depth (multishot -ENOBUFS re-arm)", () =>
        {
            // Echo server with a small recv ring; a burst larger than the ring depth forces the
            // multishot to terminate on -ENOBUFS and re-arm. All datagrams must still round-trip.
            (_, int udpPort) = TestServer.StartDatagramConfigured(
                static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload),
                quicFactory: null, quicReadMs: 60_000, udpRecvSlots: 4);

            using var client = new UdpClient();
            client.Client.ReceiveTimeout = 4000;
            var server = new IPEndPoint(IPAddress.Loopback, udpPort);

            const int count = 200;
            for (int i = 0; i < count; i++)
            {
                byte[] p = Encoding.ASCII.GetBytes($"n{i}");
                client.Send(p, p.Length, server);
            }

            // Count distinct echoes (UDP may drop under real loss, but on loopback with re-arm all
            // should return; require a strong majority to stay robust to scheduler hiccups).
            var seen = new HashSet<string>();
            try
            {
                for (int i = 0; i < count; i++)
                {
                    IPEndPoint? from = null;
                    seen.Add(Encoding.ASCII.GetString(client.Receive(ref from)));
                }
            }
            catch (SocketException)
            {
                // ran out before count - fall through to the assertion
            }
            Assert.True(seen.Count >= count - 2, $"only {seen.Count}/{count} datagrams echoed through the ring");
        });

        runner.Test("core: udp RecvSlots past what a kernel buffer ring holds is refused by name, not spun on at startup", () =>
        {
            // 40000 rounds up to a 65536-buffer ring, which a ushort buffer id never counts to.
            Assert.Throws<ArgumentException>(
                () => TestServer.StartDatagramConfigured(onDatagram: null, udpRecvSlots: 40_000),
                "config.Udp.RecvSlots ('40000') must be less than or equal to '32768'");
        });

        runner.Test("core: udp with no handler drops datagrams, reactor stays up", () =>
        {
            (int tcpPort, int udpPort) = TestServer.StartDatagram(onDatagram: null);

            using var client = new UdpClient();
            client.Client.ReceiveTimeout = 700;
            var server = new IPEndPoint(IPAddress.Loopback, udpPort);
            client.Send("drop-me"u8.ToArray(), 7, server);

            bool dropped = false;
            try
            {
                IPEndPoint? from = null;
                client.Receive(ref from);
            }
            catch (SocketException)
            {
                dropped = true;
            }
            Assert.True(dropped, "datagram was answered despite no handler");

            using var probe = new TcpClient();
            probe.Connect("127.0.0.1", tcpPort);   // the owning reactor is still alive
        });

        runner.Test("core: a udp bind that fails closes its socket, so a pin retried every sweep leaks no descriptor", () =>
        {
            // No SO_REUSEADDR or SO_REUSEPORT here, so every bind to this port is refused, the dual-stack one too.
            using var holder = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            holder.Bind(new IPEndPoint(IPAddress.Any, 0));
            ushort port = (ushort)((IPEndPoint)holder.LocalEndPoint!).Port;

            const int attempts = 16;
            int before = FdCount.Stable();

            foreach (bool dualStack in new[] { false, true })
            {
                for (int i = 0; i < attempts; i++)
                {
                    // 64 KiB: small enough that no buffer-clamp warning is printed.
                    Assert.Throws<InvalidOperationException>(
                        () => OpenUdpSocket(null, port, dualStack, gro: false, socketBufferBytes: 64 * 1024, connectTo: 0, connectLen: 0),
                        "udp bind");
                }
            }

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 2, $"{2 * attempts} refused binds left {leaked} descriptors open");
        });
    }

    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "OpenUdpSocket")]
    private static extern int OpenUdpSocket(Reactor? type, ushort port, bool dualStack, bool gro, int socketBufferBytes,
        nint connectTo, int connectLen);

    private const int SolSocket = 1;
    private const int SoReuseAddr = 2;
    private const int SoReusePort = 15;

    // The port's own address, and a narrower one.
    private static void RefusedWithoutReusePort(int port)
    {
        foreach (IPAddress address in new[] { IPAddress.Any, IPAddress.Loopback })
        {
            using var other = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            other.SetRawSocketOption(SolSocket, SoReuseAddr, BitConverter.GetBytes(1));   // raw: on Linux, .NET's ReuseAddress sets SO_REUSEPORT too
            Assert.Throws<SocketException>(() => other.Bind(new IPEndPoint(address, port)), "Address already in use");
        }
    }

    private static void DualStackEcho(IPAddress peer)
    {
        (_, int udpPort) = TestServer.StartDatagramConfigured(
            static (Reactor r, in UdpDatagram d) => r.UdpSendTo(d.SocketFd, d.PeerAddr, d.PeerAddrLen, d.Payload),
            dualStack: true);

        using var client = new UdpClient(peer.AddressFamily);
        client.Client.ReceiveTimeout = 4000;
        client.Send("dual"u8.ToArray(), 4, new IPEndPoint(peer, udpPort));

        IPEndPoint? from = null;
        Assert.Equal("dual", Encoding.ASCII.GetString(client.Receive(ref from)));
    }

    // ::1 binds only where the loopback has an IPv6 address, which a container often lacks.
    private static bool Ipv6LoopbackUp()
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            probe.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
