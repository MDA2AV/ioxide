using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The HTTP/3 error codes RFC 9114 section 8.1 defines, and which of them ever reach a peer.
/// </summary>
/// <remarks>
/// Two seams, deliberately paired:
///
/// The CODE seam - a <see cref="QuicConnection"/> subclass that records what the h3 layer asked
/// the transport to do. <c>Close(code)</c> is the single call every fatal path funnels into, so
/// asserting on it pins WHICH RFC 9114 code each protocol error carries; the fake's read surface
/// is the real base-class implementation, so the run loop under test is the production one.
///
/// The WIRE seam - a raw ngtcp2 client (the shim's test-only client entry points, like
/// QuicTestClient) that hand-frames h3 bytes nghttp3 would refuse to send, and observes whether a
/// CONNECTION_CLOSE ever comes back. The shim exposes no way to read the RECEIVED close code, so
/// the wire tests prove the close happens promptly and the code seam proves which code it was.
///
/// One site was examined and disproven rather than tested: <c>Fatal("oversized frame header")</c>
/// (and its control-stream twin) cannot fire. The 16-byte carry is exactly two maximal varints
/// (8 + 8), and a QUIC varint is at most 8 bytes, so by the time <c>have == 16</c> both type and
/// length always parse. Dead defensive code, not a reachable behaviour.
/// </remarks>
internal static class H3ErrorCodeTests
{
    // RFC 9114 section 8.1, plus RFC 9204 section 8.3 for the QPACK space.
    private const ulong H3NoError                = 0x0100;
    private const ulong H3GeneralProtocolError   = 0x0101;
    private const ulong H3ClosedCriticalStream   = 0x0104;
    private const ulong H3FrameUnexpected        = 0x0105;
    private const ulong H3FrameError             = 0x0106;
    private const ulong H3ExcessiveLoad          = 0x0107;
    private const ulong H3RequestIncomplete      = 0x010d;
    private const ulong QpackDecompressionFailed = 0x0200;

    // A GET framed by hand: HEADERS(len 6), field-section prefix 00 00 (Required Insert Count 0,
    // base 0), then static-table indexed lines :method GET (17), :scheme https (23), :path / (1),
    // :authority "" (0). Static-only on purpose - the server advertises QPACK capacity 0.
    private static readonly byte[] WellFormedGet = [0x01, 0x06, 0x00, 0x00, 0xD1, 0xD7, 0xC1, 0xC0];

    // SETTINGS(len 0) - legal only on a control stream; on a request stream RFC 9114 section 7.2.4
    // demands H3_FRAME_ERROR. Two bytes of malformed h3 that both stacks must refuse.
    private static readonly byte[] SettingsOnRequestStream = [0x04, 0x00];

    public static void Register(Runner runner)
    {
        RegisterCodeSeam(runner);
        RegisterCriticalStream(runner);
        RegisterIncompleteRequest(runner);
        RegisterWire(runner);
        RegisterNghttp3(runner);
    }

    // --- the code seam: which RFC 9114 code each pure-C# Fatal site closes with -----------------

    private static void RegisterCodeSeam(Runner runner)
    {
        runner.Test("http3/codes: control - a hand-framed GET is served through the recording transport", () =>
        {
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: true, (0, WellFormedGet, true));

            Assert.True(run.IsCompleted, "the run loop should complete inline once the transport closes");
            Assert.Equal(1, served.Count);
            Assert.True(quic.ClosedWith is null,
                $"a served connection must not be closed, got 0x{quic.ClosedWith:x}");
            Assert.True(quic.Sent.Any(s => s.StreamId == 0 && s.Fin && s.Bytes.Length > 0 && s.Bytes[0] == 0x01),
                "the response (a HEADERS frame, fin) should have gone out on the request stream");
        });

        runner.Test("http3/codes: DATA before HEADERS closes with H3_FRAME_UNEXPECTED", () =>
        {
            // Named by the RFC rather than inferred: 9114 section 4.1 says receipt of an invalid
            // SEQUENCE of frames is H3_FRAME_UNEXPECTED and calls out "a DATA frame before any
            // HEADERS frame" as the example. The distinction in section 8.1 is why the frame is
            // wrong, not how badly - UNEXPECTED is a frame not permitted in this state or on this
            // stream, ERROR is one whose layout or size is invalid. This frame is well formed; it
            // is merely too early, and a peer debugging its own framing is told two different
            // things by the two codes. This test pinned 0x0106 until the difference was noticed.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: false,
                (0, new byte[] { 0x00, 0x03, 0x61, 0x62, 0x63 }, false));   // DATA(len 3) as the first frame

            Assert.True(run.IsCompleted, "a fatal protocol error must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, H3FrameUnexpected, "H3_FRAME_UNEXPECTED");
        });


        runner.Test("http3/codes: an empty HEADERS frame closes with H3_FRAME_ERROR", () =>
        {
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: false,
                (0, new byte[] { 0x01, 0x00 }, false));                     // HEADERS(len 0)

            Assert.True(run.IsCompleted, "a fatal protocol error must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, H3FrameError, "H3_FRAME_ERROR");
        });

        runner.Test("http3/codes: SETTINGS on a request stream closes with H3_FRAME_UNEXPECTED", () =>
        {
            // The other half of the rule above. SETTINGS is a perfectly legal frame - on the
            // CONTROL stream. Arriving on a request stream it is not malformed, it is not permitted
            // here, which RFC 9114 section 8.1 gives a different code for. This pinned 0x0106 too.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: false,
                (0, SettingsOnRequestStream, false));

            Assert.True(run.IsCompleted, "a fatal protocol error must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, H3FrameUnexpected, "H3_FRAME_UNEXPECTED");
        });

        runner.Test("http3/codes: a stream ending mid-frame closes with H3_FRAME_ERROR", () =>
        {
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: false,
                (0, new byte[] { 0x01, 0x0A, 0x01, 0x02, 0x03 }, true));    // HEADERS claims 10, fin after 3

            Assert.True(run.IsCompleted, "a fatal protocol error must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, H3FrameError, "H3_FRAME_ERROR");
        });

        runner.Test("http3/codes: a header section past the limit closes with H3_EXCESSIVE_LOAD", () =>
        {
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: false,
                (0, new byte[] { 0x01, 0x80, 0x01, 0x00, 0x01 }, false));   // HEADERS(len 65537) > 64 KiB

            Assert.True(run.IsCompleted, "a fatal protocol error must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, H3ExcessiveLoad, "H3_EXCESSIVE_LOAD");
        });

        runner.Test("http3/codes: a dynamic-table reference closes with QPACK_DECOMPRESSION_FAILED", () =>
        {
            // Prefix 00 00, then 0x80: an Indexed Field Line with T=0 - a dynamic-table reference,
            // against a decoder that advertised capacity 0. RFC 9204 section 3.2.5 territory.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: false,
                (0, new byte[] { 0x01, 0x03, 0x00, 0x00, 0x80 }, false));

            Assert.True(run.IsCompleted, "a fatal protocol error must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, QpackDecompressionFailed, "QPACK_DECOMPRESSION_FAILED");
        });

        runner.Test("http3/codes: a non-h3 ALPN closes with H3_GENERAL_PROTOCOL_ERROR", () =>
        {
            var quic = new RecordingQuic(alpn: "echo");
            Task run = StartPure(quic, out Served served, closeTransport: true);

            Assert.True(run.IsCompleted, "the ALPN backstop must end the run loop");
            Assert.Equal(0, served.Count);
            AssertClosedWith(quic, H3GeneralProtocolError, "H3_GENERAL_PROTOCOL_ERROR");
        });
    }

    // --- RFC 9114 section 6.2.1: critical streams ------------------------------------------------

    private static void RegisterCriticalStream(Runner runner)
    {
        runner.Test("http3/codes: control - a client control stream is parsed and requests still serve", () =>
        {
            // The premise for the Pending below: the uni-stream feed path genuinely runs (type
            // varint, SETTINGS walk) and an OPEN control stream is not an error. The Pending
            // differs from this rig by exactly one bit - the fin.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: true,
                (2, new byte[] { 0x00, 0x04, 0x00 }, false),   // stream type 0x00 (control) + SETTINGS(len 0)
                (0, WellFormedGet, true));

            Assert.True(run.IsCompleted, "the run loop should complete inline once the transport closes");
            Assert.Equal(1, served.Count);
            Assert.True(quic.ClosedWith is null, "an open control stream is not an error");
        });

        runner.Pending("http3/codes: closing the peer's control stream is a connection error H3_CLOSED_CRITICAL_STREAM", () =>
        {
            // RFC 9114 section 6.2.1: "If either control stream is closed at any point, this MUST
            // be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM."
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out _, closeTransport: true,
                (2, new byte[] { 0x00, 0x04, 0x00 }, false),   // the same control stream as above...
                (2, Array.Empty<byte>(), true));               // ...now fin'd - a critical stream closed

            Assert.True(run.IsCompleted, "the run loop should have ended");
            AssertClosedWith(quic, H3ClosedCriticalStream, "H3_CLOSED_CRITICAL_STREAM");
        }, "RFC 9114 6.2.1 - FeedUni swallows the fin (drops the stream record, keeps serving), and "
         + "a RESET of the control stream is swallowed the same way by Feed's lifecycle branch");
    }

    // --- RFC 9114 section 4.1: a request stream that ends without a request ---------------------

    private static void RegisterIncompleteRequest(Runner runner)
    {
        runner.Test("http3/codes: an empty request stream is aborted with H3_REQUEST_INCOMPLETE and the connection serves on", () =>
        {
            // Nothing will ever answer it, so it is reset rather than left open: an open stream the
            // peer has finished counts as owed, and keeps the connection alive past its read timeout.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: true,
                (0, Array.Empty<byte>(), true),
                (4, WellFormedGet, true));

            Assert.True(run.IsCompleted, "the run loop should complete inline once the transport closes");
            Assert.Equal(1, served.Count);
            Assert.True(quic.ClosedWith is null,
                $"a stream error must not close the connection, got 0x{quic.ClosedWith:x}");
            AssertResetIncomplete(quic, 0);
        });

        runner.Test("http3/codes: a request stream that ends before its HEADERS is aborted with H3_REQUEST_INCOMPLETE", () =>
        {
            // Reserved frame types (0x1f * N + 0x21) are skipped on a request stream, so a stream of
            // nothing else ends with no request in it.
            var quic = new RecordingQuic();
            Task run = StartPure(quic, out Served served, closeTransport: true,
                (0, new byte[] { 0x21, 0x00 }, true),               // reserved frame, no payload
                (4, new byte[] { 0x21, 0x02, 0xAA, 0xBB }, true),   // reserved frame, payload skipped
                (8, WellFormedGet, true));

            Assert.True(run.IsCompleted, "the run loop should complete inline once the transport closes");
            Assert.Equal(1, served.Count);
            Assert.True(quic.ClosedWith is null,
                $"a stream error must not close the connection, got 0x{quic.ClosedWith:x}");
            AssertResetIncomplete(quic, 0, 4);
        });

        runner.Test("h3/codes: nghttp3 - a request stream that ends before its HEADERS ends the connection", () =>
        {
            // The other stack refuses the same streams as a connection error, so it never leaves one
            // owed either. Pinned: were it to reset them instead, the request would go through the
            // shim's reset_stream callback, which is not wired, and the stream would stay owed.
            foreach (byte[] bytes in new[] { Array.Empty<byte>(), new byte[] { 0x21, 0x00 } })
            {
                var quic = new RecordingQuic();
                Assert.True(quic.EnqueueStreamData(0, bytes, true), "the recv ring rejected the item");

                Task run = new Nghttp3Connection(quic).RunBufferedAsync(static _ => Nghttp3Response.Text("ok"));

                Assert.True(run.IsCompleted,
                    $"nghttp3 kept serving after a {bytes.Length}-byte request stream ended: it is left owed");
                Assert.True(quic.ClosedWith is ulong code && code != H3NoError,
                    $"expected an h3 error on the close, got " + (quic.ClosedWith is ulong c ? $"0x{c:x}" : "no Close at all"));
            }
        });
    }

    // --- the wire seam: does the close actually reach a real peer, and when ----------------------

    private static void RegisterWire(Runner runner)
    {
        runner.Test("http3/wire: control - a hand-framed GET over real QUIC is served and the connection stays open", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Http3Connection(conn).RunAsync(
                    static _ => Http3Response.Text("raw served")));

            using var peer = new RawH3Peer("127.0.0.1", udpPort);
            peer.Connect();
            Assert.True(peer.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            long sid = peer.OpenBidi();
            peer.SendRaw(sid, WellFormedGet, fin: true);

            Assert.True(peer.PumpUntilStreamFin(sid, timeoutMs: 5000),
                "no response arrived for a well-formed hand-framed GET - the wire rig is not serving");
            byte[] response = peer.ReceivedOn(sid);
            Assert.True(response.Length > 0 && response[0] == 0x01,
                "the response should begin with a HEADERS frame");

            peer.PumpFor(1500);
            Assert.True(!peer.Closed, "a served connection must not be closed out from under the client");
        });

        runner.Test("http3/wire: a malformed request stream draws a CONNECTION_CLOSE promptly, not at the idle sweep", () =>
        {
            // Until recently a protocol error only set a flag: nothing went on the wire, and the
            // connection stayed registered and routable until the transport's 60 s idle sweep.
            // The control above proves this exact rig serves; the only difference here is the two
            // malformed bytes. 15 s is a generous bound for "now" and far from the sweep.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Http3Connection(conn).RunAsync(
                    static _ => Http3Response.Text("unreached")));

            using var peer = new RawH3Peer("127.0.0.1", udpPort);
            peer.Connect();
            Assert.True(peer.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            long sid = peer.OpenBidi();
            peer.SendRaw(sid, SettingsOnRequestStream, fin: false);   // and hold the stream open

            Assert.True(peer.PumpUntilClosed(timeoutMs: 15_000),
                "a fatal h3 protocol error must CONNECTION_CLOSE the peer promptly - "
                + "nothing arrived, which is the old sit-until-the-idle-sweep behaviour");
        });
    }

    // --- the other stack: ioxide.nghttp3 ---------------------------------------------------------

    private static void RegisterNghttp3(Runner runner)
    {
        runner.Test("h3/codes: nghttp3 - a malformed request stream ends the connection handler", () =>
        {
            // The premise for the Pending below: nghttp3 does reject SETTINGS on a request stream
            // (ih3_read_stream goes negative, _protocolFailed trips, the run loop exits).
            var quic = new RecordingQuic();
            Assert.True(quic.EnqueueStreamData(0, SettingsOnRequestStream, false), "the recv ring rejected the item");

            int served = 0;
            Task run = new Nghttp3Connection(quic).RunBufferedAsync(req =>
            {
                served++;
                return Nghttp3Response.Text("ok");
            });

            Assert.True(run.IsCompleted, "nghttp3 should reject SETTINGS on a request stream and end the run");
            Assert.Equal(0, served);
        });

        runner.Test("h3/codes: nghttp3 - a protocol error tells the peer why", () =>
        {
            var quic = new RecordingQuic();
            Assert.True(quic.EnqueueStreamData(0, SettingsOnRequestStream, false), "the recv ring rejected the item");

            Task run = new Nghttp3Connection(quic).RunBufferedAsync(static _ => Nghttp3Response.Text("ok"));
            Assert.True(run.IsCompleted, "premise: nghttp3 rejected the stream and the run ended");

            Assert.True(quic.ClosedWith is ulong code && code != H3NoError,
                "the peer is entitled to an h3 error code on a CONNECTION_CLOSE; "
                + (quic.ClosedWith is null
                    ? "Close was never called - the connection sits registered until the idle sweep"
                    : $"it closed with 0x{quic.ClosedWith:x}"));
        });
    }

    // --- helpers ---------------------------------------------------------------------------------

    private sealed class Served { public int Count; }

    /// <summary>
    /// Enqueue the items, optionally close the transport (the wake for rigs that never go fatal),
    /// and run the pure-C# h3 layer over the recording fake. Every await completes synchronously,
    /// so for a fatal or closed transport the returned task is already finished - asserting
    /// IsCompleted is the proof the path under test actually ran.
    /// </summary>
    private static Task StartPure(RecordingQuic quic, out Served served, bool closeTransport,
        params (long Sid, byte[] Bytes, bool Fin)[] items)
    {
        foreach ((long sid, byte[] bytes, bool fin) in items)
        {
            Assert.True(quic.EnqueueStreamData(sid, bytes, fin), "the recv ring rejected a test item");
        }
        if (closeTransport)
        {
            quic.MarkClosed();
        }

        Served count = new();
        served = count;
        return new Http3Connection(quic).RunAsync(req =>
        {
            count.Count++;
            return Http3Response.Text("ok");
        });
    }

    private static void AssertResetIncomplete(RecordingQuic quic, params long[] streams)
    {
        string got = string.Join(", ", quic.Resets.Select(r => $"{r.StreamId}:0x{r.Code:x}"));
        Assert.True(quic.Resets.Count == streams.Length
                    && streams.All(s => quic.Resets.Contains((s, H3RequestIncomplete))),
            $"expected stream(s) {string.Join(", ", streams)} reset with H3_REQUEST_INCOMPLETE "
            + $"(0x{H3RequestIncomplete:x}) and nothing else, got [{got}]");
    }

    private static void AssertClosedWith(RecordingQuic quic, ulong code, string name)
        => Assert.True(quic.ClosedWith == code,
            $"expected the connection to close with {name} (0x{code:x}), got "
            + (quic.ClosedWith is ulong got ? $"0x{got:x}" : "no Close at all"));

    /// <summary>
    /// A <see cref="QuicConnection"/> that records what the h3 layer asks of its transport -
    /// SendStream payloads, stream resets and, above all, the application error code passed to Close. The read
    /// surface (EnqueueStreamData / MarkClosed / ReadAsync) is the real base implementation, so
    /// the run loop under test is the production one; only the engine underneath is absent.
    /// </summary>
    private sealed class RecordingQuic : QuicConnection
    {
        public readonly List<(long StreamId, byte[] Bytes, bool Fin)> Sent = [];
        public readonly List<(long StreamId, ulong Code)> Resets = [];
        public ulong? ClosedWith;
        public int CloseCalls;
        private long _nextUni = 3;   // server-initiated uni ids: 3, 7, 11, ...

        public RecordingQuic(string? alpn = "h3")
        {
            NegotiatedProtocol = alpn;
        }

        public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos) { }
        public override long GetNextTimeout(long nowMs) => long.MaxValue;
        public override void OnTimer(long nowMs) { }
        public override void OnEvicted(QuicEvictReason reason) { }

        public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin)
            => Sent.Add((streamId, data.ToArray(), fin));

        public override void ResetStream(long streamId, ulong applicationErrorCode)
            => Resets.Add((streamId, applicationErrorCode));

        public override long OpenUniStream()
        {
            long id = _nextUni;
            _nextUni += 4;
            return id;
        }

        public override void Close(ulong applicationErrorCode)
        {
            CloseCalls++;
            ClosedWith ??= applicationErrorCode;
            MarkClosed();   // what the real engine does: parked reads resume with a closed snapshot
        }
    }

    /// <summary>
    /// A raw ngtcp2 client over a real loopback UDP socket (the shim's test-only client entry
    /// points, like QuicTestClient) that hand-frames h3 bytes nghttp3 would refuse to send. The
    /// shim never surfaces the code inside a RECEIVED CONNECTION_CLOSE, so this observes THAT the
    /// peer was told and when; the code itself is pinned at the Close seam above.
    /// </summary>
    private sealed unsafe class RawH3Peer : IDisposable
    {
        private readonly UdpClient _udp;
        private readonly IPEndPoint _server;
        private nint _engine;
        private nint _conn;
        private GCHandle _self;
        private readonly byte[] _scratch = new byte[1452];

        private readonly Dictionary<long, List<byte>> _received = new();
        private readonly HashSet<long> _finished = [];

        /// <summary>The engine reported the connection over - how a server's CONNECTION_CLOSE lands here.</summary>
        public bool Closed { get; private set; }

        private static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                                (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

        public RawH3Peer(string host, int port)
        {
            _udp = new UdpClient();
            _udp.Client.ReceiveTimeout = 250;
            _server = new IPEndPoint(IPAddress.Parse(host), port);
            _udp.Connect(_server);
        }

        public void Connect()
        {
            _self = GCHandle.Alloc(this);
            var cbs = new IqCallbacks { StructSize = (nuint)sizeof(IqCallbacks), OnStreamData = &OnStreamData };
            _engine = iq_client_engine_new_mtls("h3", null, null, cbs);
            Assert.True(_engine != 0, "client engine init failed");

            Span<byte> local = stackalloc byte[16];
            Span<byte> remote = stackalloc byte[16];
            FillSockaddrIn(local, (ushort)((IPEndPoint)_udp.Client.LocalEndPoint!).Port, IPAddress.Loopback);
            FillSockaddrIn(remote, (ushort)_server.Port, IPAddress.Loopback);

            fixed (byte* l = local)
            fixed (byte* r = remote)
            {
                _conn = iq_client_connect(_engine, l, 16, r, 16, "localhost", "h3",
                                          16, NowNs(), (void*)GCHandle.ToIntPtr(_self), null);
            }
            Assert.True(_conn != 0, "client connect failed");
        }

        public bool CompleteHandshake(int timeoutMs)
        {
            long deadline = Environment.TickCount64 + timeoutMs;
            while (Environment.TickCount64 < deadline && !Closed)
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

        public long OpenBidi()
        {
            long sid = iq_client_open_bidi(_conn);
            Assert.True(sid >= 0, "failed to open a client bidi stream");
            return sid;
        }

        /// <summary>Push raw bytes - h3-framed by the TEST, not by nghttp3 - onto one stream.</summary>
        public void SendRaw(long sid, ReadOnlySpan<byte> data, bool fin)
        {
            long deadline = Environment.TickCount64 + 10_000;
            int off = 0;
            bool finPending = fin;

            while ((off < data.Length || finPending) && !Closed)
            {
                Assert.True(Environment.TickCount64 < deadline, "raw client write stalled");

                long consumed;
                nint n;
                fixed (byte* dest = _scratch)
                fixed (byte* src = data)
                {
                    byte* ptr = off < data.Length ? src + off : null;
                    n = iq_conn_write(_conn, dest, (nuint)_scratch.Length, sid,
                                      ptr, (nuint)(data.Length - off), finPending ? 1 : 0, &consumed, NowNs());
                }

                if ((int)n < 0)
                {
                    FlushOut();
                    PumpIn();
                    continue;
                }
                if (consumed > 0)
                {
                    off += (int)consumed;
                    if (off >= data.Length)
                    {
                        finPending = false;
                    }
                }
                else if (finPending && off >= data.Length && n > 0)
                {
                    finPending = false;
                }

                if (n > 0)
                {
                    _udp.Send(_scratch, (int)n);
                }
                else if (consumed <= 0)
                {
                    FlushOut();
                    PumpIn();
                }
            }
        }

        public bool PumpUntilClosed(int timeoutMs)
        {
            long deadline = Environment.TickCount64 + timeoutMs;
            while (Environment.TickCount64 < deadline && !Closed)
            {
                FlushOut();
                PumpIn();
            }
            return Closed;
        }

        public bool PumpUntilStreamFin(long sid, int timeoutMs)
        {
            long deadline = Environment.TickCount64 + timeoutMs;
            while (Environment.TickCount64 < deadline && !Closed && !_finished.Contains(sid))
            {
                FlushOut();
                PumpIn();
            }
            return _finished.Contains(sid);
        }

        public void PumpFor(int ms)
        {
            long deadline = Environment.TickCount64 + ms;
            while (Environment.TickCount64 < deadline && !Closed)
            {
                FlushOut();
                PumpIn();
            }
        }

        public byte[] ReceivedOn(long sid)
            => _received.TryGetValue(sid, out List<byte>? bytes) ? bytes.ToArray() : [];

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

        private void PumpIn()
        {
            try
            {
                IPEndPoint? from = null;
                byte[] pkt = _udp.Receive(ref from);
                fixed (byte* p = pkt)
                {
                    // Nonzero covers draining/closing and every protocol error: the connection is
                    // finished, which after a server-side abort is the CONNECTION_CLOSE landing.
                    if (iq_conn_read(_conn, null, 0, p, (nuint)pkt.Length, 0, NowNs()) != 0)
                    {
                        Closed = true;
                    }
                }
            }
            catch (SocketException)
            {
                // receive timeout - the caller's loop decides whether to keep pumping
            }
        }

        private static RawH3Peer From(void* user)
            => (RawH3Peer)GCHandle.FromIntPtr((nint)user).Target!;

        [UnmanagedCallersOnly]
        private static void OnStreamData(void* user, long streamId, byte* data, nuint len, int fin)
        {
            RawH3Peer self = From(user);
            if (!self._received.TryGetValue(streamId, out List<byte>? bytes))
            {
                self._received[streamId] = bytes = [];
            }
            bytes.AddRange(new ReadOnlySpan<byte>(data, (int)len).ToArray());
            if (fin != 0)
            {
                self._finished.Add(streamId);
            }
        }

        private static void FillSockaddrIn(Span<byte> sa, ushort port, IPAddress addr)
        {
            sa.Clear();
            sa[0] = 2;   // AF_INET
            sa[2] = (byte)(port >> 8);
            sa[3] = (byte)(port & 0xff);
            addr.GetAddressBytes().CopyTo(sa[4..]);
        }

        public void Dispose()
        {
            if (_conn != 0) iq_conn_free(_conn);
            if (_engine != 0) iq_client_engine_free(_engine);
            if (_self.IsAllocated) _self.Free();
            _udp.Dispose();
        }

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

        private const string QuicLib = "ioxide_ngtcp2";
        [DllImport(QuicLib)] private static extern nint iq_client_engine_new_mtls(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string? certPath,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, IqCallbacks cbs);
        [DllImport(QuicLib)] private static extern void iq_client_engine_free(nint e);
        [DllImport(QuicLib)] private static extern nint iq_client_connect(nint e, byte* localSa, nuint localLen, byte* remoteSa, nuint remoteLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string serverName, [MarshalAs(UnmanagedType.LPUTF8Str)] string alpn, nuint scidLen, ulong ts, void* user, byte* scidOut);
        [DllImport(QuicLib)] private static extern long iq_client_open_bidi(nint conn);
        [DllImport(QuicLib)] private static extern nint iq_conn_write(nint conn, byte* dest, nuint destLen, long streamId, byte* data, nuint dataLen, int fin, long* pConsumed, ulong ts);
        [DllImport(QuicLib)] private static extern int  iq_conn_read(nint conn, void* remoteSa, nuint remoteLen, byte* pkt, nuint pktLen, byte ecn, ulong ts);
        [DllImport(QuicLib)] private static extern int  iq_conn_is_established(nint conn);
        [DllImport(QuicLib)] private static extern void iq_conn_free(nint conn);
    }
}
