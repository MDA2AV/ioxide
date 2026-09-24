using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// QUIC transport scaffold (DCID demux; no engine): adopt/dedupe/route invariants, malformed-packet
/// drops, CID retirement, idle eviction, factory rejection, and ticker-driven timer dispatch.
/// </summary>
internal static class QuicTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic: bundled native engine loads (ngtcp2 + picotls)", () =>
        {
            string version = QuicEngine.NativeVersion();
            Assert.True(version.Length > 0 && char.IsDigit(version[0]),
                $"unexpected ngtcp2 version [{version}] - native bundle failed to load?");
        });

        runner.Test("core: quic dcid demux (long-header adopt, short-header route)", () =>
        {
            EchoQuicConnection.Created = 0;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: static (Reactor r, in UdpDatagram d, in QuicCid dcid) =>
                {
                    EchoQuicConnection.Created++;
                    var conn = new EchoQuicConnection();
                    r.QuicRegisterCid(conn, new QuicCid("srv-cid1"u8));   // the CID "we" minted
                    return conn;
                });

            using var client = NewClient(udpPort, out IPEndPoint server);
            IPEndPoint? from = null;

            byte[] initial = LongHeader("cli-cid1"u8, "hello"u8);
            client.Send(initial, initial.Length, server);
            Assert.True(client.Receive(ref from).AsSpan().SequenceEqual(initial), "long-header echo mismatch");

            // Same client DCID again - must route to the existing connection, not mint a second.
            client.Send(initial, initial.Length, server);
            client.Receive(ref from);

            byte[] shortHdr = ShortHeader("srv-cid1"u8, "ping"u8);
            client.Send(shortHdr, shortHdr.Length, server);
            Assert.True(client.Receive(ref from).AsSpan().SequenceEqual(shortHdr), "short-header echo mismatch");

            Assert.Equal(1, EchoQuicConnection.Created);
        });

        runner.Test("core: quic malformed packets drop, transport stays routable", () =>
        {
            EchoQuicConnection.Created = 0;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: static (Reactor r, in UdpDatagram d, in QuicCid dcid) =>
                {
                    EchoQuicConnection.Created++;
                    return new EchoQuicConnection();
                });

            using var client = NewClient(udpPort, out IPEndPoint server, receiveTimeoutMs: 400);

            ExpectDropped(client, server, []);                                      // empty datagram
            ExpectDropped(client, server, [0xC0]);                                  // truncated long header
            ExpectDropped(client, server, MalformedLongDcid21());                   // DCID length 21 > RFC max 20
            ExpectDropped(client, server, [0x40, 1, 2, 3]);                         // short header < 1 + LocalCidLength
            ExpectDropped(client, server, ShortHeader("unknown!"u8, "x"u8));        // short header, unregistered CID

            Assert.Equal(0, EchoQuicConnection.Created);

            // A valid long header must still adopt after all the garbage.
            byte[] valid = LongHeader("cli-cidM"u8, "ok"u8);
            client.Client.ReceiveTimeout = 4000;
            client.Send(valid, valid.Length, server);
            IPEndPoint? from = null;
            Assert.True(client.Receive(ref from).AsSpan().SequenceEqual(valid), "valid packet after garbage");
            Assert.Equal(1, EchoQuicConnection.Created);
        });

        runner.Test("core: quic CID retirement stops routing that CID", () =>
        {
            TestQuicConnection.Reset();
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: static (Reactor r, in UdpDatagram d, in QuicCid dcid) =>
                {
                    TestQuicConnection.Created++;
                    var conn = new TestQuicConnection();
                    r.QuicRegisterCid(conn, new QuicCid("srv-cidR"u8));
                    return conn;
                });

            using var client = NewClient(udpPort, out IPEndPoint server);
            IPEndPoint? from = null;

            byte[] initial = LongHeader("cli-cidR"u8, "hello"u8);
            client.Send(initial, initial.Length, server);
            client.Receive(ref from);

            byte[] viaShort = ShortHeader("srv-cidR"u8, "before"u8);
            client.Send(viaShort, viaShort.Length, server);
            Assert.True(client.Receive(ref from).AsSpan().SequenceEqual(viaShort), "short-header route before retirement");

            // Ask the connection (on the reactor thread) to retire its server CID.
            byte[] retire = LongHeader("cli-cidR"u8, "retire:srv-cidR"u8);
            client.Send(retire, retire.Length, server);

            client.Client.ReceiveTimeout = 500;
            ExpectDropped(client, server, viaShort);   // retired CID no longer routes

            // The original DCID route is untouched.
            client.Client.ReceiveTimeout = 4000;
            client.Send(initial, initial.Length, server);
            Assert.True(client.Receive(ref from).AsSpan().SequenceEqual(initial), "long-header route after retirement");
            Assert.Equal(1, TestQuicConnection.Created);
        });

        runner.Test("core: quic read-timeout eviction drops the connection, re-adopts on new handshake", () =>
        {
            TestQuicConnection.Reset();
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: static (Reactor r, in UdpDatagram d, in QuicCid dcid) =>
                {
                    TestQuicConnection.Created++;
                    var conn = new TestQuicConnection();
                    r.QuicRegisterCid(conn, new QuicCid("srv-cidE"u8));
                    return conn;
                },
                quicReadMs: 300);

            using var client = NewClient(udpPort, out IPEndPoint server);
            IPEndPoint? from = null;

            byte[] initial = LongHeader("cli-cidE"u8, "hi"u8);
            client.Send(initial, initial.Length, server);
            client.Receive(ref from);
            Assert.Equal(1, TestQuicConnection.Created);

            Thread.Sleep(900);   // silent 300 ms + 250 ms sweep granularity, with margin
            Assert.Equal(QuicEvictReason.ReadTimeout, TestQuicConnection.Evicted);

            client.Client.ReceiveTimeout = 500;
            ExpectDropped(client, server, ShortHeader("srv-cidE"u8, "stale"u8));   // routes died with it

            client.Client.ReceiveTimeout = 4000;
            client.Send(initial, initial.Length, server);   // a fresh handshake re-adopts
            client.Receive(ref from);
            Assert.Equal(2, TestQuicConnection.Created);
        });

        runner.Test("core: quic factory returning null drops the packet", () =>
        {
            TestQuicConnection.Reset();
            TestQuicConnection.RejectNextAdopt = true;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: static (Reactor r, in UdpDatagram d, in QuicCid dcid) =>
                {
                    if (TestQuicConnection.RejectNextAdopt)
                    {
                        TestQuicConnection.RejectNextAdopt = false;
                        return null;
                    }
                    TestQuicConnection.Created++;
                    return new TestQuicConnection();
                });

            using var client = NewClient(udpPort, out IPEndPoint server, receiveTimeoutMs: 500);
            byte[] initial = LongHeader("cli-cidN"u8, "hi"u8);

            ExpectDropped(client, server, initial);   // rejected: no adoption, no reply

            client.Client.ReceiveTimeout = 4000;
            client.Send(initial, initial.Length, server);
            IPEndPoint? from = null;
            client.Receive(ref from);
            Assert.Equal(1, TestQuicConnection.Created);
        });

        runner.Test("core: quic engine timer fires via the reactor ticker", () =>
        {
            TestQuicConnection.Reset();
            TestQuicConnection.ArmTimerDelayMs = 100;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: static (Reactor r, in UdpDatagram d, in QuicCid dcid) =>
                {
                    TestQuicConnection.Created++;
                    return new TestQuicConnection();
                });

            using var client = NewClient(udpPort, out IPEndPoint server);
            byte[] initial = LongHeader("cli-cidT"u8, "hi"u8);
            client.Send(initial, initial.Length, server);
            IPEndPoint? from = null;
            client.Receive(ref from);

            Thread.Sleep(800);   // deadline at +100 ms, sweep every ~250 ms
            Assert.True(TestQuicConnection.TimerFired >= 1, "engine deadline never dispatched by the ticker");
            TestQuicConnection.ArmTimerDelayMs = 0;
        });
    }

    private static UdpClient NewClient(int udpPort, out IPEndPoint server, int receiveTimeoutMs = 4000)
    {
        var client = new UdpClient();
        client.Client.ReceiveTimeout = receiveTimeoutMs;
        server = new IPEndPoint(IPAddress.Loopback, udpPort);
        return client;
    }

    private static void ExpectDropped(UdpClient client, IPEndPoint server, byte[] packet)
    {
        client.Send(packet, packet.Length, server);
        try
        {
            IPEndPoint? from = null;
            byte[] reply = client.Receive(ref from);
            throw new Exception($"expected the packet to be dropped, got a {reply.Length}-byte reply");
        }
        catch (SocketException)
        {
            // timeout = dropped, as expected
        }
    }

    // Long header: 0xC0 | version 1 | dcid len | dcid | payload (RFC 8999 shape, no protection).
    private static byte[] LongHeader(ReadOnlySpan<byte> dcid, ReadOnlySpan<byte> payload)
        => [0xC0, 0, 0, 0, 1, (byte)dcid.Length, .. dcid.ToArray(), .. payload.ToArray()];

    // Short header: 0x40 | the endpoint-known fixed-length CID | payload.
    private static byte[] ShortHeader(ReadOnlySpan<byte> cid, ReadOnlySpan<byte> payload)
        => [0x40, .. cid.ToArray(), .. payload.ToArray()];

    private static byte[] MalformedLongDcid21()
        => [0xC0, 0, 0, 0, 1, 21, .. new byte[21]];
}

/// <summary>Engine-less QUIC connection for demux tests: echoes each routed datagram to the peer.</summary>
internal sealed class EchoQuicConnection : QuicConnection
{
    public static int Created;

    public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos) => Send(payload);
    public override long GetNextTimeout(long nowMs) => long.MaxValue;
    public override void OnTimer(long nowMs) { }
    public override void OnEvicted(QuicEvictReason reason) { }
    public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin) { }   // engine-less: no streams
}

/// <summary>
/// Instrumented engine stub: echoes datagrams, retires a CID on a "retire:&lt;cid&gt;" payload,
/// records evictions, and can arm a one-shot engine deadline for the ticker test.
/// </summary>
internal sealed class TestQuicConnection : QuicConnection
{
    public static int Created;
    public static int TimerFired;
    public static QuicEvictReason? Evicted;
    public static bool RejectNextAdopt;
    public static int ArmTimerDelayMs;

    private long _deadline;

    public TestQuicConnection()
    {
        _deadline = ArmTimerDelayMs > 0 ? Environment.TickCount64 + ArmTimerDelayMs : long.MaxValue;
    }

    public static void Reset()
    {
        Created = 0;
        TimerFired = 0;
        Evicted = null;
        RejectNextAdopt = false;
        ArmTimerDelayMs = 0;
    }

    public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos)
    {
        int idx = payload.IndexOf("retire:"u8);
        if (idx >= 0)
        {
            var cid = new QuicCid(payload.Slice(idx + 7, 8));
            Reactor.QuicUnregisterCid(in cid);
            return;
        }
        Send(payload);
    }

    public override long GetNextTimeout(long nowMs) => _deadline;

    public override void OnTimer(long nowMs)
    {
        TimerFired++;
        _deadline = long.MaxValue;
    }

    public override void OnEvicted(QuicEvictReason reason) => Evicted = reason;
    public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin) { }   // engine-less: no streams
}
