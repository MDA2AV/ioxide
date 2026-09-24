using System.Net;
using System.Net.Sockets;
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
    }
}
