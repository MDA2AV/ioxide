using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// QUIC transport chaos: junk sprayed at the UDP port a real ngtcp2 + nghttp3 server listens on. The
/// demux must drop what is not a routable QUIC packet without disturbing the transport - proven not
/// by an echo but by a full HTTP/3 handshake and request completing AFTER the flood. The engine and
/// its native shims survive being fed nonsense.
/// </summary>
internal static class QuicChaosTests
{
    private static void AssertH3Serves(int udpPort)
    {
        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete after the flood");
        (int status, string body) = client.Get("/", timeoutMs: 5000);
        Assert.Equal(200, status);
        Assert.Equal("ok", body);
    }

    private static int StartH3(QuicEngine engine) => TestServer.StartDatagram(
        onDatagram: null,
        quicFactory: engine.CreateFactory(),
        quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
            static _ => Nghttp3Response.Text("ok"))).UdpPort;

    public static void Register(Runner runner)
    {
        runner.Test("quic: a garbage datagram flood doesn't stop h3 from serving", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            int udpPort = StartH3(engine);

            using (var udp = new UdpClient())
            {
                var server = new IPEndPoint(IPAddress.Loopback, udpPort);
                var rng = new Random(9);
                // 300 datagrams at every awkward size: empty, tiny, and near-MTU noise.
                for (int i = 0; i < 300; i++)
                {
                    int size = i % 5 switch { 0 => 0, 1 => 1, 2 => 8, 3 => 64, _ => 1200 };
                    byte[] junk = new byte[size];
                    rng.NextBytes(junk);
                    udp.Send(junk, junk.Length, server);
                }
            }

            AssertH3Serves(udpPort);
        });

        runner.Test("quic: malformed QUIC packets are dropped, a real handshake still completes", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            int udpPort = StartH3(engine);

            using (var udp = new UdpClient())
            {
                var server = new IPEndPoint(IPAddress.Loopback, udpPort);

                Span<byte> overlongDcid = stackalloc byte[27];
                overlongDcid.Clear();
                overlongDcid[0] = 0xC0;   // long header, fixed bit
                overlongDcid[5] = 21;     // DCID length 21 > RFC 9000 max of 20

                byte[][] malformed =
                [
                    [],                       // empty datagram
                    [0xC0],                   // long header, truncated at the first byte
                    [0x40, 1, 2, 3],          // short header shorter than a routable CID
                    overlongDcid.ToArray(),   // long header claiming an illegal DCID length
                ];

                foreach (byte[] packet in malformed)
                {
                    udp.Send(packet, packet.Length, server);
                }
            }

            AssertH3Serves(udpPort);
        });

        runner.Test("quic: a long-header datagram that is not an acceptable Initial is refused before a connection is built", () =>
        {
            // What a reactor allocates handing each one to the factory, measured on its own thread.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var probe = new FactoryProbe(engine.CreateFactory());

            int udpPort = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: probe.Create,
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => Nghttp3Response.Text("ok"))).UdpPort;

            const int Sent = 200;
            using (var udp = new UdpClient())
            {
                var server = new IPEndPoint(IPAddress.Loopback, udpPort);
                var rng = new Random(23);
                for (int i = 0; i < Sent; i++)
                {
                    byte[] junk = NotAnInitial(rng, i);
                    udp.Send(junk, junk.Length, server);
                }
            }

            long deadline = Environment.TickCount64 + 10_000;
            while (Volatile.Read(ref probe.Refused) < Sent && Environment.TickCount64 < deadline)
            {
                Thread.Sleep(20);
            }

            int refused = Volatile.Read(ref probe.Refused);
            Assert.True(refused >= Sent / 2, $"only {refused} of {Sent} junk datagrams reached the factory");
            long perDatagram = Volatile.Read(ref probe.RefusedBytes) / refused;
            Assert.True(perDatagram < 1024,
                $"each refused datagram allocated {perDatagram} bytes on the reactor, over {refused} of them");

            // The control: a real client is accepted through the same probe, which sees it allocate.
            AssertH3Serves(udpPort);
            Assert.True(Volatile.Read(ref probe.Accepted) == 1 && Volatile.Read(ref probe.AcceptedBytes) > 16 * 1024,
                $"the probe saw {probe.Accepted} accepted connection(s) allocate {probe.AcceptedBytes} bytes, so it measures nothing");
        });
    }

    // Long headers every reactor hands to the factory and ngtcp2_accept refuses: a valid DCID length,
    // and either a type other than Initial or an Initial too short or with too short a DCID.
    private static byte[] NotAnInitial(Random rng, int i)
    {
        (byte first, int size, int dcid) = (i % 5) switch
        {
            0 => ((byte)0xC0, 7, 1),       // v1 Initial, seven bytes
            1 => ((byte)0xC0, 600, 8),     // v1 Initial under the 1200-byte floor
            2 => ((byte)0xC0, 1200, 4),    // v1 Initial, no token, DCID under 8 bytes
            3 => ((byte)0xE0, 1200, 8),    // v1 Handshake
            _ => ((byte)0xD0, 1200, 8),    // v1 0-RTT
        };

        byte[] packet = new byte[size];
        rng.NextBytes(packet);
        packet[0] = first;
        packet[1] = 0; packet[2] = 0; packet[3] = 0; packet[4] = 1;   // version 1
        packet[5] = (byte)dcid;
        if (size > 6 + dcid)
        {
            packet[6 + dcid] = 8;    // SCID length
        }
        if (size > 15 + dcid && first == 0xC0)
        {
            packet[15 + dcid] = 0;   // no token
        }
        return packet;
    }

    /// <summary>Counts the bytes the factory allocates per call, refused and accepted apart.</summary>
    private sealed class FactoryProbe(QuicConnectionFactory inner)
    {
        public int Refused;
        public long RefusedBytes;
        public int Accepted;
        public long AcceptedBytes;

        public QuicConnection? Create(Reactor reactor, in UdpDatagram datagram, in QuicCid dcid)
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            QuicConnection? connection = inner(reactor, in datagram, in dcid);
            long spent = GC.GetAllocatedBytesForCurrentThread() - before;

            if (connection is null)
            {
                Volatile.Write(ref RefusedBytes, RefusedBytes + spent);
                Volatile.Write(ref Refused, Refused + 1);
            }
            else
            {
                Volatile.Write(ref AcceptedBytes, AcceptedBytes + spent);
                Volatile.Write(ref Accepted, Accepted + 1);
            }
            return connection;
        }
    }
}
