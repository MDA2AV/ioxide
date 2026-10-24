using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Stream credit over a long-lived connection: the allowance a closed stream returns, and what
/// happens when a connection outlives its initial_max_streams.
/// </summary>
/// <remarks>
/// Reviewed for the failing-test pass. The suspected defect - iq_cb_stream_close forgetting to
/// call ngtcp2_conn_extend_max_streams_bidi/_uni, wedging a kept-alive connection after 1024
/// bidi / 100 uni streams - could NOT be reproduced: the shim replenishes correctly, and so does
/// the connection-level flow-control window (initial_max_data, 1 MiB) via extend_max_offset in
/// iq_cb_recv_stream_data. What WAS true is that nothing in the suite pinned any of it: every
/// existing test opens a handful of streams, and the load tests open a new connection per
/// request, so deleting the replenishment left the whole suite green. These tests pin it.
///
/// All three were proven able to fail: with the extend_max_streams_bidi/_uni and
/// extend_max_offset calls NOP-patched out of a scratch copy of libioxide_ngtcp2.so, the bidi
/// test wedges at exactly 1024 opened / stream #1025 unopenable, the uni test at 100 / #101
/// (open error -206, STREAM_ID_BLOCKED), and the window test on the stream that crosses 1 MiB
/// ("send wedged after 1000 KiB cumulative") - while the OTHER 109 tests of this suite all
/// stayed green, which is the review finding these exist to close.
///
/// The limits live in iq_accept (initial_max_streams_bidi = 1024, _uni = 100, initial_max_data =
/// 1 MiB) and are not configurable, so the bidi test really does run 1064 streams; it stays fast
/// by pipelining a bounded window of streams over one connection. Internal deadlines are
/// progress-based (a stall, not slowness, is what fails), well inside the runner's watchdog.
///
/// Not coverable from here: a stream RESET rather than closed cleanly also funnels into ngtcp2's
/// stream_close (where the replenish lives), but the shim exports no client entry point that
/// sends RESET_STREAM/STOP_SENDING, so that path cannot be driven without editing the harness.
/// </remarks>
internal static class QuicStreamAllowanceTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic: closed bidi streams return allowance - one connection serves 1064 streams (window 1024)", () =>
        {
            // The headline: initial_max_streams_bidi is a WINDOW (1024), not a lifetime cap. A
            // kept-alive connection - h3 keep-alive is exactly this - must still be served past
            // it, which requires the server to extend the allowance as streams close. The client
            // cannot even OPEN stream #1025 unless a MAX_STREAMS frame arrived: ngtcp2 enforces
            // the peer's cumulative limit locally, so reaching stream id 4 * 1063 on ONE
            // connection is itself proof the server replenished at least 40 times.
            const int Streams = 1064;      // 1024 initial window + 40 that need returned credit
            const int MaxInFlight = 32;    // bounded so the server's 256-entry recv ring never floods

            var obs = new ServerObservations();
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoServer(obs));

            using var client = new CreditProbeClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            byte[] payload = "credit-check"u8.ToArray();
            int opened = 0;
            long lastSid = -1;
            var stall = Stopwatch.StartNew();   // restarted on progress; only a WEDGE trips it
            int lastProgress = -1;

            while (client.FinCount < Streams)
            {
                int progress = opened + client.FinCount;
                if (progress != lastProgress)
                {
                    lastProgress = progress;
                    stall.Restart();
                }
                Assert.True(stall.Elapsed < TimeSpan.FromSeconds(20),
                    $"connection wedged: {opened} streams opened, {client.FinCount} echoed - " +
                    (opened < Streams
                        ? $"stream #{opened + 1} never became openable (bidi allowance not replenished on close?)"
                        : "the remaining echoes never arrived"));

                while (opened < Streams && opened - client.FinCount < MaxInFlight)
                {
                    long sid = client.TryOpenBidi();
                    if (sid < 0)
                    {
                        break;   // allowance exhausted right now - pump for MAX_STREAMS and retry
                    }
                    opened++;
                    lastSid = sid;
                    Assert.True(client.TrySendAll(sid, payload, timeoutMs: 10_000),
                        $"stream {sid}: 12-byte payload not accepted within 10s");
                }

                client.Pump(waitMs: 1);
            }

            // Guards against passing vacuously: all N streams echoed byte-for-byte in length, the
            // final stream id proves they were numbered contiguously on one connection (a sneaky
            // reconnect restarts at 0), and the server accepted exactly one connection.
            Assert.Equal(Streams, opened);
            Assert.Equal(4L * (Streams - 1), lastSid);
            int short_ = 0;
            for (int i = 0; i < Streams; i++)
            {
                if (!client.TryGetEcho(4L * i, out long bytes, out _, out bool fin)
                    || !fin || bytes != payload.Length)
                {
                    short_++;
                }
            }
            Assert.True(short_ == 0, $"{short_} of {Streams} streams were not echoed in full");
            Assert.Equal(1, Volatile.Read(ref obs.Connections));
        });

        runner.Test("quic: closed uni streams return allowance - one connection accepts 130 uni streams (window 100)", () =>
        {
            // Same window, the cheap flavour: initial_max_streams_uni is 100, so a kept-alive
            // peer that uses uni streams (h3 pushes its control and QPACK streams here) exhausts
            // it fast. Uni streams cannot be echoed, so completion is observed on the SERVER: the
            // handler records every uni stream id whose FIN it saw, and the test demands 130
            // distinct ones - which cannot happen unless the server returned credit past 100.
            const int Streams = 130;
            const int MaxInFlight = 32;

            var obs = new ServerObservations { Target = Streams };
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: UniDrainServer(obs));

            using var client = new CreditProbeClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            byte[] payload = "uni-credit"u8.ToArray();
            int opened = 0;
            long lastSid = -1;
            long lastOpenErr = 0;
            var stall = Stopwatch.StartNew();
            int lastProgress = -1;

            while (!obs.AllSeen.Task.IsCompleted)
            {
                // ClosedCount is the client seeing its own uni stream fully acked - the pacing
                // signal that keeps the pipeline bounded without any echo to wait for.
                int progress = opened + client.ClosedCount;
                if (progress != lastProgress)
                {
                    lastProgress = progress;
                    stall.Restart();
                }
                Assert.True(stall.Elapsed < TimeSpan.FromSeconds(20),
                    $"connection wedged: {opened} uni streams opened, server saw {obs.SeenUniCount()} fins - " +
                    (opened < Streams
                        ? $"stream #{opened + 1} never became openable (last open error {lastOpenErr}; uni allowance not replenished on close?)"
                        : "the remaining fins never reached the handler"));

                while (opened < Streams && opened - client.ClosedCount < MaxInFlight)
                {
                    long sid = client.TryOpenUni();
                    if (sid < 0)
                    {
                        lastOpenErr = sid;   // NGTCP2_ERR_STREAM_ID_BLOCKED while starved
                        break;
                    }
                    opened++;
                    lastSid = sid;
                    Assert.True(client.TrySendAll(sid, payload, timeoutMs: 10_000),
                        $"uni stream {sid}: payload not accepted within 10s");
                }

                client.Pump(waitMs: 1);
            }

            Assert.Equal(Streams, opened);
            Assert.Equal(2L + 4L * (Streams - 1), lastSid);   // contiguous uni ids on ONE connection
            Assert.Equal(Streams, obs.SeenUniCount());
            Assert.Equal(1, Volatile.Read(ref obs.Connections));
        });

        runner.Test("quic: connection flow-control credit returns as data is consumed - 1.6 MiB crosses the 1 MiB window", () =>
        {
            // One level up from stream count: initial_max_data (1 MiB in iq_accept) bounds the
            // CUMULATIVE bytes a peer may send on the connection, and iq_cb_recv_stream_data must
            // hand the credit back (extend_max_offset) as it consumes. Each stream here stays
            // under its own 256 KiB stream window, so the only thing that can wedge mid-run is
            // the connection-level window - which the 6th stream crosses. Both directions are
            // exercised: the client sends 1.6 MiB and the echoes coming back spend the client's
            // own 1 MiB grant, replenished by the same callback on the client conn.
            const int Streams = 8;
            const int PerStream = 200 * 1024;   // < 256 KiB stream window; 8 x 200 KiB = 1.6 MiB > 1 MiB

            var obs = new ServerObservations();
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoServer(obs));

            using var client = new CreditProbeClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            long totalEchoed = 0;
            for (int i = 0; i < Streams; i++)
            {
                var payload = new byte[PerStream];
                ulong expectedSum = 0;
                for (int j = 0; j < payload.Length; j++)
                {
                    payload[j] = (byte)(j * 131 + i * 17);
                    expectedSum += payload[j];
                }

                long sid = client.TryOpenBidi();
                Assert.True(sid >= 0, $"stream #{i + 1} could not be opened (8 << the 1024 allowance)");

                long already = (i) * (long)PerStream;
                Assert.True(client.TrySendAll(sid, payload, timeoutMs: 30_000),
                    $"stream {sid}: send wedged after {already / 1024} KiB cumulative " +
                    "(connection flow-control window not replenished?)");

                // Sequential: wait for this stream's full echo before the next, so a wedge names
                // the exact stream. Progress-based so a slow box cannot fail it.
                var stall = Stopwatch.StartNew();
                long lastSeen = -1;
                while (true)
                {
                    client.TryGetEcho(sid, out long bytes, out ulong sum, out bool fin);
                    if (fin && bytes == PerStream)
                    {
                        Assert.True(sum == expectedSum, $"stream {sid}: echo of {bytes} bytes came back corrupted");
                        totalEchoed += bytes;
                        break;
                    }
                    if (bytes != lastSeen)
                    {
                        lastSeen = bytes;
                        stall.Restart();
                    }
                    Assert.True(stall.Elapsed < TimeSpan.FromSeconds(20),
                        $"stream {sid}: echo stalled at {bytes} of {PerStream} bytes " +
                        $"({(already + bytes) / 1024} KiB cumulative on the connection)");
                    client.Pump(waitMs: 1);
                }
            }

            Assert.Equal(Streams * (long)PerStream, totalEchoed);   // 1.6 MiB really crossed, both ways
            Assert.Equal(1, Volatile.Read(ref obs.Connections));
        });
    }

    /// <summary>What the server side observed - the anti-vacuity half of every test above.</summary>
    private sealed class ServerObservations
    {
        public int Connections;
        public int Target;
        private readonly HashSet<long> _finnedUni = [];
        public readonly TaskCompletionSource AllSeen = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void RecordUniFin(long streamId)
        {
            lock (_finnedUni)
            {
                _finnedUni.Add(streamId);
                if (Target > 0 && _finnedUni.Count >= Target)
                {
                    AllSeen.TrySetResult();
                }
            }
        }

        public int SeenUniCount()
        {
            lock (_finnedUni)
            {
                return _finnedUni.Count;
            }
        }
    }

    // Echo every data delivery back on its stream, fin included - the server shape whose sent fin,
    // once acked, is what lets ngtcp2 close the stream and the shim hand the allowance back.
    private static Func<Reactor, QuicConnection, Task> EchoServer(ServerObservations obs)
        => async (_, conn) =>
        {
            Interlocked.Increment(ref obs.Connections);
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data)
                        {
                            conn.SendStream(item.StreamId, item.AsSpan(), item.Fin);
                        }
                        conn.ReturnBuffer(in item);
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
                conn.DecRef();
            }
        };

    // Uni streams cannot be answered; drain them and record each stream id whose FIN arrived.
    private static Func<Reactor, QuicConnection, Task> UniDrainServer(ServerObservations obs)
        => async (_, conn) =>
        {
            Interlocked.Increment(ref obs.Connections);
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data && item.Fin && (item.StreamId & 0x3) == 0x2)
                        {
                            obs.RecordUniFin(item.StreamId);
                        }
                        conn.ReturnBuffer(in item);
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
                conn.DecRef();
            }
        };
}

/// <summary>
/// A minimal ngtcp2 client built for stream-credit probing: opens streams until the peer's
/// allowance says no, tracks per-stream echoes and its own stream closures, and services the
/// loss/ack timer (unlike <see cref="QuicTestClient"/>, whose single echo never needs it).
/// Uses the shim's test-only client entry points over a real loopback UDP socket.
/// </summary>
internal sealed unsafe class CreditProbeClient : IDisposable
{
    private sealed class EchoState
    {
        public long Bytes;
        public ulong Sum;
        public bool Fin;
    }

    private readonly UdpClient _udp;
    private readonly IPEndPoint _server;
    private readonly byte[] _scratch = new byte[1452];
    private nint _clientEngine;
    private nint _conn;
    private GCHandle _self;

    private readonly Dictionary<long, EchoState> _echo = [];

    /// <summary>Streams whose echo has arrived complete (server fin seen).</summary>
    public int FinCount { get; private set; }

    /// <summary>This client's own streams that closed fully (everything sent and acked).</summary>
    public int ClosedCount { get; private set; }

    private static ulong NowNs() => (ulong)(Stopwatch.GetTimestamp() *
                                            (1_000_000_000.0 / Stopwatch.Frequency));

    public CreditProbeClient(string host, int port)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveBufferSize = 1 << 20;   // absorb echo bursts; a drop only costs an RTO
        _server = new IPEndPoint(IPAddress.Parse(host), port);
        _udp.Connect(_server);
    }

    public void Connect()
    {
        var cbs = new IqCallbacks
        {
            StructSize = (nuint)sizeof(IqCallbacks),
            OnStreamData = &OnStreamData,
            OnStreamClose = &OnStreamClose,
        };
        _clientEngine = iq_client_engine_new_mtls("echo", null, null, cbs);
        Assert.True(_clientEngine != 0, "client engine init failed");

        Span<byte> local = stackalloc byte[16];
        Span<byte> remote = stackalloc byte[16];
        FillSockaddrIn(local, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port);
        FillSockaddrIn(remote, (ushort)_server.Port);

        _self = GCHandle.Alloc(this);
        fixed (byte* l = local)
        fixed (byte* r = remote)
        {
            _conn = iq_client_connect(_clientEngine, l, 16, r, 16, "localhost", "echo",
                                      16, NowNs(), (void*)GCHandle.ToIntPtr(_self), null);
        }
        Assert.True(_conn != 0, "client connect failed");
    }

    public bool CompleteHandshake(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (iq_conn_is_established(_conn) != 0)
            {
                return true;
            }
            Pump(waitMs: 5);
        }
        return false;
    }

    public long TryOpenBidi() => iq_client_open_bidi(_conn);

    public long TryOpenUni() => iq_conn_open_uni(_conn);

    /// <summary>
    /// Write the whole payload with FIN, pumping while the engine is congestion- or
    /// flow-control-blocked. False only when no byte was accepted for the whole timeout - the
    /// wedge the caller is probing for.
    /// </summary>
    public bool TrySendAll(long sid, byte[] payload, int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        int off = 0;
        long consumed;
        fixed (byte* dest = _scratch)
        fixed (byte* src = payload)
        {
            while (true)
            {
                nint n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, sid,
                                       src + off, (nuint)(payload.Length - off), 1, &consumed, NowNs());
                if (consumed > 0)
                {
                    off += (int)consumed;
                }
                if (n > 0)
                {
                    _udp.Send(_scratch, (int)n);
                    if (off >= payload.Length)
                    {
                        return true;   // fin rode the packet that consumed the last byte
                    }
                    continue;
                }

                // n == 0: cwnd- or window-blocked; n < 0 with bytes left: likewise transient.
                if (off >= payload.Length)
                {
                    return true;
                }
                if (Environment.TickCount64 >= deadline)
                {
                    return false;
                }
                Pump(waitMs: 1);
            }
        }
    }

    /// <summary>
    /// One engine service cycle: fire the loss/ack timer if due, flush pending packets, ingest
    /// whatever the server sent (waiting at most <paramref name="waitMs"/> if nothing is queued),
    /// then flush again so acks leave now - the server cannot close a stream, and so cannot
    /// return its allowance, until this client's acks reach it.
    /// </summary>
    public void Pump(int waitMs)
    {
        ulong now = NowNs();
        ulong expiry = iq_conn_expiry(_conn);
        if (expiry != ulong.MaxValue && expiry <= now)
        {
            iq_conn_handle_expiry(_conn, now);
        }
        FlushOut();

        if (_udp.Client.Available == 0 && waitMs > 0)
        {
            _udp.Client.Poll(waitMs * 1000, SelectMode.SelectRead);
        }
        bool any = false;
        while (_udp.Client.Available > 0)
        {
            IPEndPoint? from = null;
            byte[] pkt = _udp.Receive(ref from);
            fixed (byte* p = pkt)
            {
                iq_conn_read(_conn, null, 0, p, (nuint)pkt.Length, 0, NowNs());
            }
            any = true;
        }
        if (any)
        {
            FlushOut();
        }
    }

    public bool TryGetEcho(long sid, out long bytes, out ulong sum, out bool fin)
    {
        if (_echo.TryGetValue(sid, out EchoState? s))
        {
            bytes = s.Bytes;
            sum = s.Sum;
            fin = s.Fin;
            return true;
        }
        bytes = 0;
        sum = 0;
        fin = false;
        return false;
    }

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

    private static void FillSockaddrIn(Span<byte> sa, ushort port)
    {
        sa.Clear();
        sa[0] = 2;   // AF_INET (x86 little-endian: family low byte)
        sa[2] = (byte)(port >> 8);
        sa[3] = (byte)(port & 0xff);
        sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;
    }

    [UnmanagedCallersOnly]
    private static void OnStreamData(void* user, long streamId, byte* data, nuint len, int fin)
    {
        var self = (CreditProbeClient)GCHandle.FromIntPtr((nint)user).Target!;
        if (!self._echo.TryGetValue(streamId, out EchoState? s))
        {
            self._echo[streamId] = s = new EchoState();
        }
        for (nuint i = 0; i < len; i++)
        {
            s.Sum += data[i];
        }
        s.Bytes += (long)len;
        if (fin != 0 && !s.Fin)
        {
            s.Fin = true;
            self.FinCount++;
        }
    }

    [UnmanagedCallersOnly]
    private static void OnStreamClose(void* user, long streamId, ulong appErrorCode)
    {
        _ = streamId;
        _ = appErrorCode;
        var self = (CreditProbeClient)GCHandle.FromIntPtr((nint)user).Target!;
        self.ClosedCount++;
    }

    public void Dispose()
    {
        if (_conn != 0)
        {
            iq_conn_free(_conn);
        }
        if (_clientEngine != 0)
        {
            iq_client_engine_free(_clientEngine);
        }
        if (_self.IsAllocated)
        {
            _self.Free();
        }
        _udp.Dispose();
    }

    // --- shim client entry points (test-only); layout mirrors the shim's iq_callbacks ---

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
    [DllImport(Lib)] private static extern nint iq_client_connect(nint e, byte* localSa, nuint localLen, byte* remoteSa, nuint remoteLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string serverName, [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn, nuint scidLen, ulong ts, void* user, byte* scidOut);
    [DllImport(Lib)] private static extern long iq_client_open_bidi(nint conn);
    [DllImport(Lib)] private static extern long iq_conn_open_uni(nint conn);
    [DllImport(Lib)] private static extern nint iq_conn_write(nint conn, byte* dest, nuint destLen, long streamId, byte* data, nuint dataLen, int fin, long* pConsumed, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_read(nint conn, void* remoteSa, nuint remoteLen, byte* pkt, nuint pktLen, byte ecn, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_is_established(nint conn);
    [DllImport(Lib)] private static extern ulong iq_conn_expiry(nint conn);
    [DllImport(Lib)] private static extern int  iq_conn_handle_expiry(nint conn, ulong ts);
    [DllImport(Lib)] private static extern void iq_conn_free(nint conn);
}
