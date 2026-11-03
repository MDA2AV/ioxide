using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

        // IP_LOCAL_PORT_RANGE (6.3+) confines a socket's port-0 bind to one port, so the kernel's
        // ephemeral pick - a 1-in-28,000 collision at full range - has a single outcome to choose.
        bool confinable = TestServer.KernelAtLeast(6, 3);

        runner.Test("quic/client: the kernel never gives the client socket's port to another socket", () =>
        {
            // A later socket with SO_REUSEADDR is preferred for the whole port, so sharing it takes
            // every reply the server sends the client.
            (ushort clientPort, Reactor client, int serverPort) = StartClientAndServer();

            using Socket other = BindConfinedTo(clientPort, out bool given);
            bool served = Handshakes(client, serverPort);

            Assert.True(served, given
                ? $"the client's handshake never completed: another socket was given its port {clientPort} and took the replies"
                : "the client's handshake never completed, though no other socket was given its port");
            Assert.True(!given, $"another socket was given port {clientPort}, which the client socket holds");
        }, skip: !confinable);

        runner.Test("control: a socket confined to a free port is given it, and the client still connects", () =>
        {
            // Without this the test above would also pass on a kernel that ignores the confinement.
            (_, Reactor client, int serverPort) = StartClientAndServer();

            int free = TestServer.DeadUdpPort();
            using Socket other = BindConfinedTo(free, out bool given);

            Assert.True(given && ((IPEndPoint)other.LocalEndPoint!).Port == free,
                $"a port-0 bind confined to free port {free} was not given it, so confinement does not work here");
            Assert.True(Handshakes(client, serverPort), "the client's handshake never completed");
        }, skip: !confinable);

        runner.Test("quic/client: a client socket whose port cannot be read is closed, so the failed open leaves no descriptor behind", () =>
        {
            // getsockname cannot fail on the socket the reactor just opened, so BoundPort gets a descriptor it fails on: not a socket.
            const int attempts = 16;
            int before = FdCount.Stable();

            foreach (bool dualStack in new[] { false, true })
            {
                for (int i = 0; i < attempts; i++)
                {
                    int fd = ioxide.Native.open("/dev/null", 0, 0);
                    Assert.True(fd >= 0, "could not open /dev/null");
                    Assert.Throws<InvalidOperationException>(() => BoundPort(null, fd, dualStack), "getsockname failed");
                }
            }

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 2, $"{2 * attempts} failed port reads left {leaked} descriptors open");
        });

        runner.Test("quic/client: a socket that could not be opened is opened by the next connect, on the buffer ring the first one brought up", () =>
        {
            Assert.Equal(0, getrlimit(RlimitNofile, out RLimit original));
            var none = new RLimit { Cur = 0, Max = original.Max };

            // With no descriptor to be had the ring still comes up, and then the socket cannot be opened.
            ClientOpens opens = OpenAfterAFailure(
                fail: _ => setrlimit(RlimitNofile, in none),
                restore: _ => setrlimit(RlimitNofile, in original));

            Assert.True(opens.Failed?.Message.Contains("udp socket failed") == true,
                $"the first open was to fail at the socket, after the ring came up; got: {opens.Failed?.Message ?? "no failure"}");
            Assert.True(opens.Retried is null, $"the next open failed: {opens.Retried?.Message}");
            Assert.True(opens.RingAfterRetry == opens.RingAfterFailure, "the next open brought up a second buffer ring, leaking the first");
            Assert.True(Handshakes(opens.Client, opens.ServerPort), "the client's handshake never completed");
        });

        runner.Test("quic/client: a buffer ring the kernel refused is freed, so the next connect brings one up from scratch", () =>
        {
            // A ring of the test's own holds the UDP ring's group id, so the reactor's registration is refused.
            nint held = 0;
            ClientOpens opens = OpenAfterAFailure(
                fail: reactor => held = HoldUdpGroup(reactor),
                restore: reactor => ReleaseUdpGroup(reactor, held));

            Assert.True(opens.Failed?.Message.Contains("register udp pbuf_ring failed") == true,
                $"the first open was to fail at the ring's registration; got: {opens.Failed?.Message ?? "no failure"}");
            Assert.True(opens.RingAfterFailure == 0, "the refused ring was kept, so the next open would arm its socket on a ring the kernel never took");
            Assert.True(opens.Retried is null, $"the next open failed: {opens.Retried?.Message}");
            Assert.True(Handshakes(opens.Client, opens.ServerPort), "the client's handshake never completed");
        });

        runner.Test("quic/client: a buffer ring whose buffers could not be allocated is freed, so the next connect brings one up from scratch", () =>
        {
            Assert.Equal(0, getrlimit(RlimitAs, out RLimit original));

            // 64 MiB of headroom fits the 64 KiB ring, not its 257 MiB of buffers, which only a new mapping could supply.
            ClientOpens opens = OpenAfterAFailure(
                fail: _ => setrlimit(RlimitAs, new RLimit { Cur = AddressSpaceInUse() + 64 * 1024 * 1024, Max = original.Max }),
                restore: _ => setrlimit(RlimitAs, in original),
                udpRecvSlots: 4096);

            Assert.True(opens.Failed is OutOfMemoryException,
                $"the first open was to fail allocating the ring's buffers; got: {opens.Failed?.Message ?? "no failure"}");
            Assert.True(opens.RingAfterFailure == 0, "the ring from the failed setup was kept, so the next open would arm its socket on a ring the kernel never took");
            Assert.True(opens.Retried is null, $"the next open failed: {opens.Retried?.Message}");
            Assert.True(Handshakes(opens.Client, opens.ServerPort), "the client's handshake never completed");
        });
    }

    // A QUIC server, and a client-only reactor that has opened its ephemeral socket.
    private static (ushort ClientPort, Reactor Client, int ServerPort) StartClientAndServer()
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = new QuicEngine(certPath, keyPath, cidLength: 8);   // outlives the test: connections hold it
        (_, int serverPort) = TestServer.StartDatagram(onDatagram: null, quicFactory: engine.CreateFactory());

        var opened = new TaskCompletionSource<(ushort, Reactor)>(TaskCreationOptions.RunContinuationsAsynchronously);
        TestServer.StartQuicClientHost(
            tcpHandle: static (_, _) => Task.CompletedTask,
            onStart: reactor =>
            {
                reactor.QuicEnsureClientTransport();
                opened.TrySetResult((reactor.QuicLocalPort, reactor));
            });

        Assert.True(opened.Task.Wait(10_000), "the client reactor never opened its socket");
        (ushort port, Reactor client) = opened.Task.Result;
        return (port, client, serverPort);
    }

    // What any program's socket gets from bind(:0) with SO_REUSEADDR, confined to one port.
    private static Socket BindConfinedTo(int port, out bool given)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetRawSocketOption(1, 2, BitConverter.GetBytes(1));                           // SOL_SOCKET, SO_REUSEADDR
        socket.SetRawSocketOption(0, 51, BitConverter.GetBytes((uint)port << 16 | (uint)port)); // IPPROTO_IP, IP_LOCAL_PORT_RANGE
        try
        {
            socket.Bind(new IPEndPoint(IPAddress.Any, 0));
            given = true;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            given = false;
        }
        return socket;
    }

    // Connect from the client reactor and wait for the handshake.
    private static bool Handshakes(Reactor client, int serverPort)
    {
        var clientEngine = new QuicClientEngine("echo");   // never disposed: its connection outlives the test
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.ScheduleOnReactor(_ =>
        {
            QuicEngineConnection connection = clientEngine.Connect(client, "127.0.0.1", (ushort)serverPort, "localhost");
            connection.HandshakeCompleted = () => done.TrySetResult();
        }, null);
        return done.Task.Wait(5_000);
    }

    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "BoundPort")]
    private static extern ushort BoundPort(Reactor? type, int fd, bool dualStack);

    // What a client-only reactor saw opening its QUIC socket twice in OnStart: once between fail and
    // restore, then again. Its UDP buffer ring is read after each.
    private readonly record struct ClientOpens(
        Reactor Client, int ServerPort, Exception? Failed, nint RingAfterFailure, Exception? Retried, nint RingAfterRetry);

    private static ClientOpens OpenAfterAFailure(Action<Reactor> fail, Action<Reactor> restore, int udpRecvSlots = 16)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
        (_, int serverPort) = TestServer.StartDatagram(onDatagram: null, quicFactory: engine.CreateFactory());

        var opened = new TaskCompletionSource<ClientOpens>(TaskCreationOptions.RunContinuationsAsynchronously);
        TestServer.StartQuicClientHost(
            tcpHandle: static (_, _) => Task.CompletedTask,
            onStart: reactor =>
            {
                Exception? failed;
                try
                {
                    fail(reactor);
                    failed = TryOpen(reactor);
                }
                finally
                {
                    restore(reactor);   // a process limit left lowered would fail every later test
                }
                nint ring = UdpRing(reactor);
                Exception? retried = TryOpen(reactor);
                opened.TrySetResult(new ClientOpens(reactor, serverPort, failed, ring, retried, UdpRing(reactor)));
            },
            udpRecvSlots: udpRecvSlots);

        Assert.True(opened.Task.Wait(10_000), "the client reactor never tried to open its socket");
        return opened.Task.Result;
    }

    private static Exception? TryOpen(Reactor reactor)
    {
        try
        {
            reactor.QuicEnsureClientTransport();
            return null;
        }
        catch (Exception e)
        {
            return e;
        }
    }

    // The group id the reactor registers its UDP buffer ring under.
    private const ushort UdpGroupId = 0;

    private static unsafe nint HoldUdpGroup(Reactor reactor)
    {
        nuint page = (nuint)Environment.SystemPageSize;
        void* ring = NativeMemory.AlignedAlloc(page, page);
        var reg = new Native.io_uring_buf_reg { ring_addr = (ulong)ring, ring_entries = 1, bgid = UdpGroupId };
        Native.io_uring_register(RingOf(reactor).Fd, Native.IORING_REGISTER_PBUF_RING, &reg, 1);
        return (nint)ring;
    }

    private static unsafe void ReleaseUdpGroup(Reactor reactor, nint ring)
    {
        var reg = new Native.io_uring_buf_reg { bgid = UdpGroupId };
        Native.io_uring_register(RingOf(reactor).Fd, Native.IORING_UNREGISTER_PBUF_RING, &reg, 1);
        NativeMemory.AlignedFree((void*)ring);
    }

    private static unsafe nint UdpRing(Reactor reactor) => (nint)UdpRingOf(reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_udpBufRing")]
    private static extern unsafe ref byte* UdpRingOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ring")]
    private static extern ref Ring RingOf(Reactor reactor);

    private const int RlimitNofile = 7;
    private const int RlimitAs = 9;

    // What RLIMIT_AS counts: the address space mapped now.
    private static ulong AddressSpaceInUse()
    {
        using Process self = Process.GetCurrentProcess();
        return (ulong)self.VirtualMemorySize64;
    }

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
        _deadline = ArmTimerDelayMs > 0 ? Native.MonotonicMs + ArmTimerDelayMs : long.MaxValue;
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
