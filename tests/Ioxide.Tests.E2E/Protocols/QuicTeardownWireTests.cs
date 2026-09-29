using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// What actually reaches the peer when a QUIC connection ends. Four paths end one - an application
/// Close, an engine error, the send-retention backstop and reactor shutdown - and each has to
/// decide between a CONNECTION_CLOSE and silence. Nothing in this repo had ever read the wire to
/// see which one the peer got, which is how a farewell can go missing from a path and the suite
/// stay green.
/// </summary>
/// <remarks>
/// The peer's own ngtcp2 is the detector: receiving a CONNECTION_CLOSE moves a connection to
/// DRAINING, so iq_conn_read answering NGTCP2_ERR_DRAINING is the peer saying it was told. Nothing
/// else the server sends produces that answer, so the check is about the farewell rather than
/// about traffic. Silence is what a peer that will now sit out its own idle timeout sees, and
/// telling the two apart is the whole point of the file.
///
/// Three of the four paths are driven here. The fourth, an engine error reaching CloseFromEngine,
/// is not: a well-behaved ngtcp2 client cannot produce one, and the malformed inputs that can are
/// the Chaos suite's half of the map.
/// </remarks>
internal static class QuicTeardownWireTests
{
    // Enough for the handshake and one echo on loopback; every wait here is a deadline, never a
    // measurement (see tests/README.md - nothing in this file asserts on how long anything took).
    private const int ExchangeMs = 10_000;

    // How long a farewell is waited for. It is written and sent inside the teardown itself, so a
    // peer that has not seen one after this was never going to.
    private const int FarewellMs = 5_000;

    public static void Register(Runner runner)
    {
        // The control every silence assertion below leans on: the one path nobody doubts, measured
        // with the same client and the same detector. If this stops passing, the detector is broken
        // and "no CONNECTION_CLOSE arrived" stops meaning anything at all.
        runner.Test("quic: an application Close reaches the peer as a CONNECTION_CLOSE", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            var accepted = new TaskCompletionSource<Reactor>(TaskCreationOptions.RunContinuationsAsynchronously);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoThen(accepted, torndown, static (conn, _) => conn.Close(0)));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            client.SendRequest("close-me"u8.ToArray());
            Assert.Equal("close-me", client.WaitForEcho(ExchangeMs));

            Assert.True(torndown.Task.Wait(ExchangeMs),
                "the server never ended the connection, so nothing was being asserted about how it ended");
            Assert.True(client.WaitForConnectionClose(FarewellMs),
                $"the peer was never told: {client.DatagramsReceived} datagrams arrived and none was a CONNECTION_CLOSE");
        });

        runner.Test("quic: the send-retention backstop tells the peer before it drops the connection", () =>
        {
            // The backstop is the server aborting a connection over its OWN producer's behaviour:
            // the peer did nothing wrong and has no way to know, so the one thing it must not get
            // is silence. maxSendRetentionBytes is floored at 256 KiB and the ceiling is twice the
            // high-water, so 768 KiB queued in a single call is over it before anything is pumped.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, maxSendRetentionBytes: 256L << 10);

            var accepted = new TaskCompletionSource<Reactor>(TaskCreationOptions.RunContinuationsAsynchronously);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoThen(accepted, torndown, static (conn, _) =>
                {
                    // A fresh uni stream, not the echoed one: the echo carried the client's fin, and
                    // SendStream drops bytes queued after a fin - the flood would never be counted.
                    long uni = conn.OpenUniStream();
                    conn.SendStream(uni, new byte[768 * 1024], fin: false);
                }));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            client.SendRequest("flood-me"u8.ToArray());
            Assert.Equal("flood-me", client.WaitForEcho(ExchangeMs));

            Assert.True(torndown.Task.Wait(ExchangeMs),
                "the backstop never fired, so nothing was being asserted about what it sends");
            Assert.True(client.WaitForConnectionClose(FarewellMs),
                $"the peer was never told: {client.DatagramsReceived} datagrams arrived and none was a CONNECTION_CLOSE");
        });

        runner.Test("quic: an idle-swept connection is discarded in silence", () =>
        {
            // The other half of the rule, and the one a fix for the shutdown case could easily
            // break: RFC 9000 section 10.2.1 says a connection ended by the idle timer is discarded
            // WITHOUT a CONNECTION_CLOSE - the peer is presumed gone, and answering an absent peer
            // is a datagram sent to whoever holds that address now.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            var accepted = new TaskCompletionSource<Reactor>(TaskCreationOptions.RunContinuationsAsynchronously);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: 750,
                quicHandle: EchoThen(accepted, torndown, null));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            client.SendRequest("then-go-quiet"u8.ToArray());
            Assert.Equal("then-go-quiet", client.WaitForEcho(ExchangeMs));

            // Receive-only from here: anything sent would refresh the server's last-seen stamp and
            // the sweep this test is waiting for would never come.
            Assert.True(torndown.Task.Wait(30_000),
                "the idle sweep never evicted the connection, so its silence proves nothing");
            Assert.True(!client.WaitForConnectionClose(FarewellMs),
                "an idle-swept connection answered a CONNECTION_CLOSE; RFC 9000 10.2.1 discards it silently");
        });

        runner.Pending("quic: a reactor shutdown tells its peers instead of leaving them to time out", () =>
        {
            // A reactor coming down knows the connection is over, and it is the only one that
            // knows: every peer is left holding a connection that looks alive until its own idle
            // timer reaps it. Two things stand between OnEvicted and a farewell, and whoever fixes
            // this needs both - the transport has already run QuicRemoveConnection by the time it
            // is called, which frees and zeroes the peer address Send needs, and TeardownQuic runs
            // after the loop has exited, so an SQE queued there is never submitted and the UDP fd
            // is closed a few lines later. Reordering alone leaves this test exactly as red.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            var accepted = new TaskCompletionSource<Reactor>(TaskCreationOptions.RunContinuationsAsynchronously);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoThen(accepted, torndown, null));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            // The echo is the guard that makes the silence below evidence: the server reached this
            // client's address microseconds earlier, so a farewell that never arrives was never
            // sent rather than lost on a socket nobody could reach.
            client.SendRequest("still-here"u8.ToArray());
            Assert.Equal("still-here", client.WaitForEcho(ExchangeMs));

            Assert.True(accepted.Task.Wait(ExchangeMs), "the handler never ran, so the reactor was never captured");
            int beforeShutdown = client.DatagramsReceived;
            accepted.Task.Result.Stop();

            Assert.True(torndown.Task.Wait(ExchangeMs),
                "the reactor never tore the connection down, so its silence is not the shutdown path's");
            Assert.True(client.WaitForConnectionClose(FarewellMs),
                $"the peer was left to time out: {client.DatagramsReceived - beforeShutdown} datagrams arrived "
                + "after the shutdown and none was a CONNECTION_CLOSE");
        }, "issue #195 - OnEvicted only frees the connection, and the transport has already run "
           + "QuicRemoveConnection by then, which zeroes the peer address Send needs");
    }

    /// <summary>
    /// Echoes the peer's first stream bytes back, runs <paramref name="afterFirstEcho"/> once (the
    /// teardown under test), and reports through <paramref name="torndown"/> when the connection
    /// actually ended - the guard that separates "the server said nothing" from "the server never
    /// got as far as ending the connection". <paramref name="accepted"/> hands out the reactor,
    /// which is otherwise not reachable from a datagram server the harness started.
    /// </summary>
    private static Func<Reactor, QuicConnection, Task> EchoThen(
        TaskCompletionSource<Reactor> accepted,
        TaskCompletionSource torndown,
        Action<QuicConnection, long>? afterFirstEcho)
        => async (reactor, conn) =>
        {
            accepted.TrySetResult(reactor);
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();

                    long echoed = -1;
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data)
                        {
                            conn.SendStream(item.StreamId, item.AsSpan(), item.Fin);
                            echoed = item.StreamId;
                        }
                        conn.ReturnBuffer(in item);
                    }

                    if (echoed >= 0 && afterFirstEcho is not null)
                    {
                        Action<QuicConnection, long> once = afterFirstEcho;
                        afterFirstEcho = null;
                        once(conn, echoed);
                    }

                    if (snap.IsClosed)
                    {
                        break;
                    }
                    conn.ResetRead();
                }
            }
            finally
            {
                torndown.TrySetResult();
                conn.DecRef();
            }
        };
}

/// <summary>
/// A raw ngtcp2 client on its own loopback socket, like <c>QuicTestClient</c> but built to report
/// what the server put on the wire at the end: every inbound datagram is counted, and a server
/// CONNECTION_CLOSE is recognised by ngtcp2 answering NGTCP2_ERR_DRAINING. It never sends unless
/// asked to, so a test can wait out a server-side idle timer without refreshing it.
/// </summary>
internal sealed unsafe class TeardownWireClient : IDisposable
{
    // ngtcp2 error codes, verified against the shipped library by QuicEngineTests.
    private const int NgtcpErrDraining = -224;

    private readonly UdpClient _udp;
    private readonly byte[] _scratch = new byte[1452];
    private readonly List<byte> _echo = [];
    private nint _engine;
    private nint _conn;
    private GCHandle _self;
    private bool _echoFin;

    /// <summary>True once the server's CONNECTION_CLOSE has been fed to ngtcp2. Sticky: the answer
    /// can arrive coalesced with the response the test was waiting for.</summary>
    public bool SawConnectionClose { get; private set; }

    /// <summary>Datagrams taken off the socket, so "nothing arrived" can be told apart from
    /// "datagrams arrived and none of them ended the connection".</summary>
    public int DatagramsReceived { get; private set; }

    private static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                            (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

    public TeardownWireClient(int serverPort)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveTimeout = 100;
        _udp.Connect(new IPEndPoint(IPAddress.Loopback, serverPort));   // fixes the local port

        var cbs = new IqCallbacks { StructSize = (nuint)sizeof(IqCallbacks), OnStreamData = &OnClientStreamData };
        _engine = iq_client_engine_new_mtls("echo", null, null, cbs);
        Assert.True(_engine != 0, "client engine init failed");

        _self = GCHandle.Alloc(this);

        Span<byte> local = stackalloc byte[16];
        Span<byte> remote = stackalloc byte[16];
        FillSockaddrIn(local, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port);
        FillSockaddrIn(remote, (ushort)serverPort);

        fixed (byte* l = local)
        fixed (byte* r = remote)
        {
            // One connection per socket, so the scid length only has to be legal (see H3TestClient).
            _conn = iq_client_connect(_engine, l, 16, r, 16, "localhost", "echo",
                                      16, NowNs(), (void*)GCHandle.ToIntPtr(_self), null);
        }
        Assert.True(_conn != 0, "client connect failed");
    }

    public bool CompleteHandshake(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            FlushOut();
            if (iq_conn_is_established(_conn) != 0)
            {
                return true;
            }
            PumpIn();
        }
        return false;
    }

    /// <summary>Open a bidi stream and send the payload with fin, without waiting for the answer.</summary>
    public void SendRequest(byte[] payload)
    {
        long sid = iq_client_open_bidi(_conn);
        Assert.True(sid >= 0, "failed to open a client stream");

        long consumed;
        fixed (byte* dest = _scratch)
        fixed (byte* src = payload)
        {
            int off = 0;
            long stream = sid;
            while (true)
            {
                byte* data = stream >= 0 ? src + off : null;
                nuint len = stream >= 0 ? (nuint)(payload.Length - off) : 0;
                nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, stream,
                                       data, len, 1, &consumed, NowNs());
                if ((int)n < 0)
                {
                    if (stream < 0)
                    {
                        return;   // the connection itself refuses - nothing left to flush
                    }
                    stream = -1;  // the stream is blocked or finished; keep draining the engine
                    continue;
                }
                if (consumed > 0)
                {
                    off += (int)consumed;
                }
                if (n > 0)
                {
                    _udp.Send(_scratch, (int)n);
                }
                if (n == 0)
                {
                    if (stream >= 0 && off < payload.Length)
                    {
                        stream = -1;
                        continue;
                    }
                    return;
                }
            }
        }
    }

    /// <summary>Pump until the server's answer has arrived with its fin, and return it.</summary>
    public string WaitForEcho(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && !_echoFin)
        {
            FlushOut();
            PumpIn();
        }
        return Encoding.ASCII.GetString(_echo.ToArray());
    }

    /// <summary>Pumps both ways for <paramref name="ms"/> - ACKs what arrives, starts nothing.</summary>
    public void Converse(int ms)
    {
        long deadline = Environment.TickCount64 + ms;
        while (Environment.TickCount64 < deadline)
        {
            FlushOut();
            PumpIn();
        }
    }

    /// <summary>
    /// Whether the server ended the connection out loud. Receive-only - it sends nothing, so a test
    /// can wait here through a server-side idle timeout without keeping the connection alive.
    /// </summary>
    public bool WaitForConnectionClose(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (!SawConnectionClose && Environment.TickCount64 < deadline)
        {
            PumpIn();
        }
        return SawConnectionClose;
    }

    // Drain whatever the engine wants to send (handshake, acks, stream data) to the wire.
    private void FlushOut()
    {
        long consumed;
        fixed (byte* dest = _scratch)
        {
            while (true)
            {
                nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, -1, null, 0, 0, &consumed, NowNs());
                if (n <= 0)
                {
                    break;
                }
                _udp.Send(_scratch, (int)n);
            }
        }
    }

    // One inbound datagram (or the socket timeout), fed to ngtcp2. DRAINING is the library saying
    // the packet carried a CONNECTION_CLOSE.
    private void PumpIn()
    {
        try
        {
            IPEndPoint? from = null;
            byte[] pkt = _udp.Receive(ref from);
            DatagramsReceived++;

            fixed (byte* p = pkt)
            {
                if (iq_conn_read(_conn, null, 0, p, (nuint)pkt.Length, 0, NowNs()) == NgtcpErrDraining)
                {
                    SawConnectionClose = true;
                }
            }
        }
        catch (SocketException)
        {
            // Receive timeout: nothing arrived in this slice, the caller owns the deadline.
        }
    }

    private static void FillSockaddrIn(Span<byte> sa, ushort port)
    {
        sa.Clear();
        sa[0] = 2;   // AF_INET (x86 little-endian: family low byte)
        sa[2] = (byte)(port >> 8);
        sa[3] = (byte)(port & 0xff);
        IPAddress.Loopback.GetAddressBytes().CopyTo(sa[4..]);
    }

    [UnmanagedCallersOnly]
    private static void OnClientStreamData(void* user, long streamId, byte* data, nuint len, int fin)
    {
        var self = (TeardownWireClient)GCHandle.FromIntPtr((nint)user).Target!;
        self._echo.AddRange(new ReadOnlySpan<byte>(data, (int)len).ToArray());
        if (fin != 0)
        {
            self._echoFin = true;
        }
    }

    public void Dispose()
    {
        if (_conn != 0)
        {
            iq_conn_free(_conn);
            _conn = 0;
        }
        if (_engine != 0)
        {
            iq_client_engine_free(_engine);
            _engine = 0;
        }
        if (_self.IsAllocated)
        {
            _self.Free();
        }
        _udp.Dispose();
    }

    // --- shim client entry points (test-only) ---

    [StructLayout(LayoutKind.Sequential)]
    private struct IqCallbacks
    {
        public nuint StructSize;
        public delegate* unmanaged<void*, long, byte*, nuint, int, void> OnStreamData;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamClose;
        public delegate* unmanaged<void*, void>                         OnHandshakeCompleted;
        public delegate* unmanaged<void*, byte*, nuint, void>           OnNewCid;
        public delegate* unmanaged<void*, byte*, nuint, void>           OnRetireCid;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamReset;
        public delegate* unmanaged<void*, long, ulong, void>            OnStreamStopSending;
        public delegate* unmanaged<void*, long, ulong, ulong, void>     OnAckedStreamData;
        public delegate* unmanaged<void*, void*, nuint, void>           OnPathChange;
    }

    private const string Lib = "ioxide_ngtcp2";
    [DllImport(Lib)] private static extern nint iq_client_engine_new_mtls(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? certPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, IqCallbacks cbs);
    [DllImport(Lib)] private static extern void iq_client_engine_free(nint e);
    [DllImport(Lib)] private static extern nint iq_client_connect(nint e, byte* localSa, nuint localLen,
        byte* remoteSa, nuint remoteLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string serverName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn, nuint scidLen, ulong ts, void* user, byte* scidOut);
    [DllImport(Lib)] private static extern long iq_client_open_bidi(nint conn);
    [DllImport(Lib)] private static extern nint iq_conn_write(nint conn, byte* dest, nuint destLen, long streamId,
        byte* data, nuint dataLen, int fin, long* pConsumed, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_read(nint conn, void* remoteSa, nuint remoteLen,
        byte* pkt, nuint pktLen, byte ecn, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_is_established(nint conn);
    [DllImport(Lib)] private static extern void iq_conn_free(nint conn);
}
