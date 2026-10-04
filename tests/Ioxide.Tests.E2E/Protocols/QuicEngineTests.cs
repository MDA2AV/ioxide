using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Full QUIC engine (ngtcp2 + picotls, bundled): a real TLS 1.3 handshake and an encrypted stream
/// echo end to end - the ioxide reactor runs the server engine, a bare ngtcp2 client (via the shim's
/// test-only client entry points) drives it over a real loopback UDP socket. No external QUIC stack.
/// </summary>
internal static class QuicEngineTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic: the ngtcp2 error constants match the shipped library", () =>
        {
            // These are hand-copied from a header the build script fetches by ref, so a wrong value
            // does not fail to compile - it makes a branch match a DIFFERENT error. Two were wrong:
            // CLOSING held TRANSPORT_PARAM's value and INTERNAL held CALLBACK_FAILURE's, so a
            // transport-parameter violation - which a client triggers with one edited parameter -
            // was classified as a quiet ending and the peer got no CONNECTION_CLOSE at all. That is
            // the exact gap the farewell exists to close, reintroduced by a typo.
            //
            // ngtcp2_strerror returns the symbolic name for a code, so the shipped library can be
            // asked rather than trusted. Reflecting over every NGTCP2_ERR_* field means a constant
            // added later is covered without anyone remembering to extend this test.
            Type interop = typeof(QuicEngine).Assembly.GetType("ioxide.ngtcp2.Ngtcp2")
                ?? throw new Exception("could not reflect the ngtcp2 interop type");

            MethodInfo strError =
                interop.GetMethod("StrError", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)
                ?? throw new Exception("could not reflect Ngtcp2.StrError");

            FieldInfo[] codes = interop
                .GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)
                .Where(f => f.IsLiteral && f.Name.StartsWith("NGTCP2_ERR_", StringComparison.Ordinal))
                .ToArray();

            // Vacuity guard: a renamed prefix would otherwise make this pass by checking nothing.
            Assert.True(codes.Length >= 7, $"expected the interop to declare error codes, found {codes.Length}");

            var wrong = new List<string>();
            foreach (FieldInfo code in codes)
            {
                int value = (int)code.GetRawConstantValue()!;
                string expected = code.Name["NGTCP2_".Length..];          // NGTCP2_ERR_CLOSING -> ERR_CLOSING
                string actual = (string)strError.Invoke(null, [value])!;

                if (actual != expected)
                {
                    wrong.Add($"{code.Name} = {value}, but the library calls {value} {actual}");
                }
            }

            Assert.True(wrong.Count == 0,
                "constants disagree with the shipped ngtcp2: " + string.Join("; ", wrong));
        });

        runner.Test("quic: full ngtcp2 handshake + encrypted stream echo (loopback)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoHandler);

            using var client = new QuicTestClient("127.0.0.1", udpPort);
            client.Connect();

            // Pump the handshake to completion (each side answers the other's datagrams).
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            byte[] sent = Encoding.ASCII.GetBytes("hello-quic-echo");
            string echoed = client.RequestEcho(sent, timeoutMs: 5000);
            Assert.Equal("hello-quic-echo", echoed);
        });

        runner.Test("quic: a handshake that never finishes is dropped", () =>
        {
            // The one part of a QUIC server reachable before anything is authenticated. ngtcp2
            // leaves handshake_timeout at UINT64_MAX and max_idle_timeout disabled, so the only
            // bound used to be the transport's idle sweep - which is keyed on last-seen and so is
            // refreshed by any datagram, including ones ngtcp2 discards. A peer sending one packet
            // under the interval held an ngtcp2 conn, a picotls session and its CID routes forever.
            //
            // Asserted on the HANDLER exiting, not on the client failing to reconnect: a dropped
            // half-open handshake does not stop the client's retransmit from starting a fresh one
            // that completes perfectly well, so "the client cannot connect afterwards" would be
            // false even with a working bound. The handler runs from accept, and it returns when
            // the connection is torn down.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, handshakeTimeoutMs: 1_000);

            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: SignalOnExit(torndown));

            using var client = new QuicTestClient("127.0.0.1", udpPort);
            client.Connect();
            client.SendFirstFlight();   // the server now holds a handshake that will never finish

            Assert.True(torndown.Task.Wait(TimeSpan.FromSeconds(6)),
                "the server should have torn down a handshake that stalled past its bound");
        });

        runner.Test("control: with the bound disabled the same stalled handshake is kept", () =>
        {
            // The control that makes the test above mean something: same silence, same client. If
            // the connection went away here too, that assertion would be proving nothing about the
            // bound - only that a quiet peer gets dropped by something, somewhere.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, handshakeTimeoutMs: 0);

            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: SignalOnExit(torndown));

            using var client = new QuicTestClient("127.0.0.1", udpPort);
            client.Connect();
            client.SendFirstFlight();

            Assert.True(!torndown.Task.Wait(TimeSpan.FromSeconds(4)),
                "with no bound the half-open handshake should still be held");
        });

        runner.Test("quic: a handler that answers and closes in one cycle still delivers the answer", () =>
        {
            // The ordinary shape of a server that answers and says goodbye - an h3 graceful
            // shutdown is exactly this. The handler is resumed inline from inside the engine cycle,
            // so its response is COALESCED into the GSO batch rather than sent; teardown then frees
            // the peer address, after which the flush is a silent no-op. Pre-fix the peer received
            // only the CONNECTION_CLOSE and the response was dropped on the floor.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: EchoThenCloseHandler);

            using var client = new QuicTestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            byte[] sent = Encoding.ASCII.GetBytes("answer-then-close");
            Assert.Equal("answer-then-close", client.RequestEcho(sent, timeoutMs: 5000));
        });

        runner.Test("quic: a FIN parked behind a full congestion window is still sent", () =>
        {
            // With the window full and an ACK due, ngtcp2 sends the ACK alone and reports the stream
            // frame unwritten (-1). A bare FIN was counted as sent on any packet, so that ACK
            // swallowed it and nothing retried it: ~20 in 1.5M streamed h3 responses never ended.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: FinBehindFullWindowHandler);

            using var client = new QuicTestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            long first = client.Send("a"u8.ToArray(), fin: true);
            Assert.True(client.PumpUntil(() => client.BytesOn(first) == 1, timeoutMs: 5000), "the first stream was not answered");

            // The server fills its window and parks the first stream's FIN behind it. A packet that
            // arrives after a lost one makes its ACK due at once (RFC 9000 13.2.1), so the parked FIN
            // is the next write - with the window still full, as nothing has been read and acked.
            client.Send("fill"u8.ToArray(), fin: true);
            client.Send("x"u8.ToArray(), fin: false, lost: true);
            client.Send("y"u8.ToArray(), fin: false);

            Assert.True(client.PumpUntil(() => client.FinOn(first), timeoutMs: 5000),
                "the first stream never ended: its FIN was counted as sent in an ACK-only packet");
        });

        runner.Test("quic: dual-pipe (PipeReader/PipeWriter) stream echo (loopback)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: PipeEchoHandler);

            using var client = new QuicTestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            byte[] sent = Encoding.ASCII.GetBytes("hello-quic-pipe-echo");
            string echoed = client.RequestEcho(sent, timeoutMs: 5000);
            Assert.Equal("hello-quic-pipe-echo", echoed);
        });
    }

    // Server side, the dual-pipe model: auto-bind to the client's stream, echo until fin, then
    // Complete() half-closes with the server's own fin (which RequestEcho waits for).
    private static async Task PipeEchoHandler(Reactor reactor, QuicConnection conn)
    {
        try
        {
            var pipe = new QuicConnectionDualPipe(conn);

            while (true)
            {
                System.IO.Pipelines.ReadResult result = await pipe.Input.ReadAsync();

                foreach (ReadOnlyMemory<byte> segment in result.Buffer)
                {
                    pipe.Output.Write(segment.Span);
                }
                await pipe.Output.FlushAsync();

                pipe.Input.AdvanceTo(result.Buffer.End);

                if (result.IsCompleted)
                {
                    break;
                }
            }

            pipe.Output.Complete();
            pipe.Input.Complete();
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Server side, the delegate model: await stream events, echo each back on its own stream.
    /// <summary>
    /// Echoes, then closes the connection in the SAME engine cycle. The close is what makes this
    /// different from <see cref="EchoHandler"/>: the response is still sitting in the coalesced GSO
    /// batch when teardown runs, so it only reaches the wire if teardown flushes that batch before
    /// the connection stops being sendable.
    /// </summary>
    private static async Task EchoThenCloseHandler(Reactor reactor, QuicConnection conn)
    {
        try
        {
            while (true)
            {
                QuicRecvSnapshot snap = await conn.ReadAsync();

                bool answered = false;
                while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                {
                    conn.SendStream(item.StreamId, item.AsSpan(), item.Fin);
                    conn.ReturnBuffer(in item);
                    answered = true;
                }

                if (answered)
                {
                    conn.Close(0);   // same cycle as the SendStream above
                    return;
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
    }

    /// <summary>
    /// Drains and discards, and reports when it RETURNS - which happens when the transport tears
    /// the connection down. The handler starts at accept, so it is already running while the
    /// handshake is in flight, which is what makes it an observer of a pre-handshake teardown.
    /// </summary>
    private static Func<Reactor, QuicConnection, Task> SignalOnExit(TaskCompletionSource torndown)
        => async (_, conn) =>
        {
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
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
                torndown.TrySetResult();
                conn.DecRef();
            }
        };

    /// <summary>
    /// Answers stream 0 without ending it. Stream 4 then fills the congestion window and is reset,
    /// so that stream 0's bare FIN, sent right after, is the only thing waiting for the window.
    /// </summary>
    private static async Task FinBehindFullWindowHandler(Reactor reactor, QuicConnection conn)
    {
        try
        {
            while (true)
            {
                QuicRecvSnapshot snap = await conn.ReadAsync();

                while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                {
                    if (item.Kind == QuicStreamEvent.Data && item.Fin && item.StreamId == 0)
                    {
                        conn.SendStream(0, "A"u8, fin: false);
                    }
                    else if (item.Kind == QuicStreamEvent.Data && item.Fin && item.StreamId == 4)
                    {
                        conn.SendStream(4, new byte[1 << 20], fin: true);
                        conn.ResetStream(4, 0);
                        conn.SendStream(0, ReadOnlySpan<byte>.Empty, fin: true);
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
    }

    private static async Task EchoHandler(Reactor reactor, QuicConnection conn)
    {
        try
        {
            while (true)
            {
                QuicRecvSnapshot snap = await conn.ReadAsync();

                while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                {
                    conn.SendStream(item.StreamId, item.AsSpan(), item.Fin);
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
    }
}

/// <summary>
/// A minimal ngtcp2 client for the test, using the shim's client entry points and a real loopback
/// UDP socket. Not production code - it exists purely to drive the server engine.
/// </summary>
internal sealed unsafe class QuicTestClient : IDisposable
{
    private readonly UdpClient _udp;
    private readonly IPEndPoint _server;
    private nint _clientEngine;
    private nint _conn;
    private long _streamId = -1;
    private readonly List<byte> _echo = [];
    private bool _echoFin;
    private readonly Dictionary<long, int> _bytesOn = [];
    private readonly HashSet<long> _finOn = [];

    public int BytesOn(long streamId) => _bytesOn.GetValueOrDefault(streamId);

    public bool FinOn(long streamId) => _finOn.Contains(streamId);

    private static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                            (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

    public QuicTestClient(string host, int port)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveTimeout = 250;
        _server = new IPEndPoint(IPAddress.Parse(host), port);
        _udp.Connect(_server);   // fixes the local port so the server's replies come back here
    }

    public void Connect()
    {
        var cbs = new IqCallbacks
        {
            StructSize = (nuint)sizeof(IqCallbacks),
            OnStreamData = &OnClientStreamData,
        };
        _clientEngine = iq_client_engine_new_mtls("echo", null, null, cbs);
        Assert.True(_clientEngine != 0, "client engine init failed");

        // Local + remote sockaddr_in (loopback). ngtcp2 needs both for the path.
        Span<byte> local = stackalloc byte[16];
        Span<byte> remote = stackalloc byte[16];
        FillSockaddrIn(local, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port, IPAddress.Loopback);
        FillSockaddrIn(remote, (ushort)_server.Port, IPAddress.Loopback);

        fixed (byte* l = local)
        fixed (byte* r = remote)
        {
            // See H3TestClient: one connection per socket, so the length only has to be legal.
            _conn = iq_client_connect(_clientEngine, l, 16, r, 16, "localhost", "echo",
                                      16, NowNs(), (void*)GCHandle.ToIntPtr(GCHandle.Alloc(this)), null);
        }
        Assert.True(_conn != 0, "client connect failed");
    }

    // Drive the handshake: write client datagrams out, read server datagrams in, until established.
    /// <summary>
    /// Sends the client's first flight and stops, leaving the server holding a handshake that will
    /// never finish - the state a pre-authentication bound exists to reclaim.
    /// </summary>
    public void SendFirstFlight() => FlushOut();

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

    // Open a bidi stream, send the payload with FIN, and collect the echoed bytes.
    public string RequestEcho(byte[] payload, int timeoutMs)
    {
        _streamId = iq_client_open_bidi(_conn);
        Assert.True(_streamId >= 0, "failed to open client stream");

        long consumed;
        fixed (byte* dest = _sendScratch)
        fixed (byte* src = payload)
        {
            // Loop the engine until the payload is fully accepted and its datagrams are sent.
            int off = 0;
            long sid = _streamId;
            while (true)
            {
                byte* dataPtr = sid >= 0 ? src + off : null;
                nuint dataLen = sid >= 0 ? (nuint)(payload.Length - off) : 0;
                nint n = iq_conn_write(_conn, dest, (nuint)_sendScratch.Length, sid,
                                       dataPtr, dataLen, 1, &consumed, NowNs());
                int code = (int)n;
                if (code < 0)
                {
                    sid = -1;   // stream done/blocked - keep flushing the connection's own packets
                    continue;
                }
                if (consumed > 0)
                {
                    off += (int)consumed;
                }
                if (n > 0)
                {
                    _udp.Send(_sendScratch, (int)n);
                }
                if (n == 0)
                {
                    if (sid >= 0 && off < payload.Length)
                    {
                        sid = -1;
                        continue;
                    }
                    break;
                }
            }
        }

        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && !_echoFin)
        {
            FlushOut();
            PumpIn();
        }
        return Encoding.ASCII.GetString(_echo.ToArray());
    }

    private readonly byte[] _sendScratch = new byte[1452];

    /// <summary>Open a stream and send <paramref name="data"/> on it in its own packet, reading nothing.
    /// A <paramref name="lost"/> packet is built but never sent, so the next one arrives after a gap.</summary>
    public long Send(byte[] data, bool fin, bool lost = false)
    {
        long streamId = iq_client_open_bidi(_conn);
        Assert.True(streamId >= 0, "failed to open client stream");

        long consumed;
        fixed (byte* dest = _sendScratch)
        fixed (byte* src = data)
        {
            nint n = iq_conn_write(_conn, dest, (nuint)_sendScratch.Length, streamId,
                                   src, (nuint)data.Length, fin ? 1 : 0, &consumed, NowNs());
            Assert.True(n > 0 && consumed == data.Length, $"client write failed: {n}, consumed {consumed}");
            if (!lost)
            {
                _udp.Send(_sendScratch, (int)n);
            }
        }
        return streamId;
    }

    /// <summary>Read and ack until <paramref name="done"/>.</summary>
    public bool PumpUntil(Func<bool> done, int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (!done())
        {
            if (Environment.TickCount64 >= deadline)
            {
                return false;
            }
            FlushOut();
            PumpIn();
        }
        return true;
    }

    // Drain the client engine's pending datagrams (ACKs, handshake) to the wire.
    private void FlushOut()
    {
        long consumed;
        fixed (byte* dest = _sendScratch)
        {
            while (true)
            {
                nint n = iq_conn_write(_conn, dest, (nuint)_sendScratch.Length, -1, null, 0, 0, &consumed, NowNs());
                if (n <= 0)
                {
                    break;
                }
                _udp.Send(_sendScratch, (int)n);
            }
        }
    }

    // Read one server datagram (if any within the socket timeout) and feed it to the engine.
    private void PumpIn()
    {
        try
        {
            IPEndPoint? from = null;
            byte[] pkt = _udp.Receive(ref from);
            fixed (byte* p = pkt)
            {
                iq_conn_read(_conn, null, 0, p, (nuint)pkt.Length, 0, NowNs());
            }
        }
        catch (SocketException)
        {
            // timeout - the engine timer may still need pumping; the caller loops
        }
    }

    private static void FillSockaddrIn(Span<byte> sa, ushort port, IPAddress addr)
    {
        sa.Clear();
        sa[0] = 2;   // AF_INET (x86 little-endian: family low byte)
        sa[2] = (byte)(port >> 8);
        sa[3] = (byte)(port & 0xff);
        addr.GetAddressBytes().CopyTo(sa[4..]);
    }

    [UnmanagedCallersOnly]
    private static void OnClientStreamData(void* user, long streamId, byte* data, nuint len, int fin)
    {
        var self = (QuicTestClient)GCHandle.FromIntPtr((nint)user).Target!;
        self._echo.AddRange(new ReadOnlySpan<byte>(data, (int)len).ToArray());
        self._bytesOn[streamId] = self.BytesOn(streamId) + (int)len;
        if (fin != 0)
        {
            self._echoFin = true;
            self._finOn.Add(streamId);
        }
    }

    public void Dispose()
    {
        if (_conn != 0) iq_conn_free(_conn);
        if (_clientEngine != 0) iq_client_engine_free(_clientEngine);
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
    [DllImport(Lib)] private static extern nint iq_client_connect(nint e, byte* localSa, nuint localLen, byte* remoteSa, nuint remoteLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string serverName, [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn, nuint scidLen, ulong ts, void* user, byte* scidOut);
    [DllImport(Lib)] private static extern long iq_client_open_bidi(nint conn);
    [DllImport(Lib)] private static extern nint iq_conn_write(nint conn, byte* dest, nuint destLen, long streamId, byte* data, nuint dataLen, int fin, long* pConsumed, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_read(nint conn, void* remoteSa, nuint remoteLen, byte* pkt, nuint pktLen, byte ecn, ulong ts);
    [DllImport(Lib)] private static extern int  iq_conn_is_established(nint conn);
    [DllImport(Lib)] private static extern void iq_conn_free(nint conn);
}
