using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A request body that stops early, on the pure-C# HTTP/3 stack: a stream that ends inside a DATA
/// frame it already sized, and a body shorter than the content-length that announced it. Both ask
/// the same question - can the handler that receives the bytes tell a body that ENDED from one
/// that was CUT. For the first the answer is no, as pinned below. For the second it is yes, on
/// either overload: the request is refused with H3_MESSAGE_ERROR, and a handler already reading
/// the body is told by its next read.
/// </summary>
internal static class H3BodyTruncationTests
{
    public static void Register(Runner runner)
    {
        runner.Test("control: a body that ends where its DATA frame said reads as a clean end", () =>
        {
            // The half that is correct, and what makes the PEND below a finding rather than a
            // guess: the same client, the same frames, the same handler, ten bytes promised and ten
            // delivered. Its read ends cleanly, and it must - a body that finished is exactly what
            // an empty chunk is for. The point is that the next test produces this same string.
            Assert.Equal("ended after 10", StreamedBodyOutcome(promised: 10));
        });

        runner.Test("http3: a body cut mid-frame kills the connection, and the reader signals an ordinary end", () =>
        {
            // The same ten bytes, under a DATA frame header that promised a hundred: the stream
            // ends 90 bytes inside a frame the client itself sized. No h3 client library will send
            // that, so it is driven with hand-written frames over a raw QUIC client.
            //
            // The parser DOES see it: FeedRequest's fin branch finds the walk mid-payload and calls
            // Fatal("stream ended mid-frame"), which closes the connection with H3_FRAME_ERROR. But
            // the handler has been running since end-of-headers, has already been handed the ten
            // bytes, and is parked in ReadAsync - and the teardown ends its sink through the same
            // Drop/End the run loop uses for a clean fin. The next read returns an empty chunk,
            // which Http3BodyReader documents as "end of body". A handler that commits what it
            // received commits ten bytes as though they were the whole request.
            string outcome = StreamedBodyOutcome(promised: 100);

            // Reviewed as a defect and kept. The protocol obligation is already met one layer up:
            // a stream that ends mid-frame is a CONNECTION error of type H3_FRAME_ERROR (RFC 9114
            // 7.1), which Http3Connection raises, and the response is never sent - so no client is
            // served partial data, which is what the rule is for. H3_REQUEST_INCOMPLETE covers a
            // different case. And "an empty chunk means end of body" is not an ioxide.http3
            // shortcoming: all three body readers document it identically for a stream that stops,
            // the nghttp3 one included, so a truncation flag would have to land in all three or the
            // two stacks would disagree about what a read returning nothing means. What is pinned
            // is the contract as written. A body that contradicts its content-length is the one case
            // this reader does flag, below: the request itself said how long the body was.
            Assert.True(outcome.StartsWith("ended", StringComparison.Ordinal),
                $"the reader should signal an ordinary end, as all three body readers document, got: {outcome}");
        });

        runner.Test("http3: a body shorter than its content-length is refused, not served whole", () =>
        {
            // The other way a body stops early, and the one a real client can produce: well-formed
            // DATA frames whose payloads add up to less than the content-length the request
            // announced. RFC 9114 4.1.2 makes that malformed - "a request or response is malformed
            // if the value of a content-length header field does not equal the sum of the DATA frame
            // payload lengths" - and malformed messages must be a stream error of H3_MESSAGE_ERROR.
            //
            // This is the BUFFERED overload, the one believed protected because it reassembles
            // before dispatching. Reassembly protects it against a stream that ends mid-frame (that
            // is Fatal, before _ready ever gets the id) and against nothing else: without the
            // content-length check the handler is handed a ten-byte Body for a request that said
            // one hundred, and cannot tell the difference.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            int served = -1;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Http3Connection(conn).RunAsync(
                    req =>
                    {
                        Volatile.Write(ref served, req.Body.Length);
                        return Http3Response.Text($"got {req.Body.Length}");
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string text) = client.Request("POST", "/short", "0123456789"u8.ToArray(),
                [("content-length", "100")], timeoutMs: 5000);

            Assert.True(status != 200,
                $"the request announced content-length: 100 and delivered 10 body bytes; the server "
                + $"answered {status} '{text}' and handed the handler a {Volatile.Read(ref served)}-byte "
                + "body as if that were the whole request");
        });

        runner.Test("control: a body that matches its content-length is served whole", () =>
        {
            // What makes the refusal above mean something: the same server, the same client, the
            // same POST of ten bytes - announced honestly - is served. Without this, "the server
            // did not answer 200" would be satisfied by a server that answers nothing at all.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            int served = -1;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Http3Connection(conn).RunAsync(
                    req =>
                    {
                        Volatile.Write(ref served, req.Body.Length);
                        return Http3Response.Text($"got {req.Body.Length}");
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string text) = client.Request("POST", "/whole", "0123456789"u8.ToArray(),
                [("content-length", "10")], timeoutMs: 5000);

            Assert.Equal(200, status);
            Assert.Equal("got 10", text);
            Assert.Equal(10, Volatile.Read(ref served));
        });

        runner.Test("http3: a streamed body shorter than its content-length raises on read instead of ending", () =>
        {
            // The streaming overload dispatched at end-of-headers, so refusing the request cannot
            // keep the handler from the ten bytes. What it can do is make the read after them say
            // the body was cut. Same frames as the clean-end control at the top; only the header differs.
            Assert.Equal("raised IOException after 10", StreamedBodyOutcome(promised: 10, contentLength: "100"));
        });

        runner.Test("control: a streamed body that matches its content-length reads as a clean end", () =>
        {
            Assert.Equal("ended after 10", StreamedBodyOutcome(promised: 10, contentLength: "10"));
        });

        runner.Test("http3: a body that runs past its content-length is refused with H3_MESSAGE_ERROR", () =>
        {
            // RFC 9114 4.1.2 again, from the other side: ten bytes of DATA under a content-length of
            // five. Refused at the DATA frame's header, before any of its payload is taken.
            Assert.Equal("reset 0x10e", BufferedOutcome("0123456789"u8.ToArray(), "5"));
        });

        runner.Test("http3: an invalid or repeated content-length is refused with H3_MESSAGE_ERROR", () =>
        {
            // Each with a ten-byte body, so only the header is wrong. A repeated content-length is
            // refused even when the values agree, as nghttp3 refuses it.
            foreach (string[] fields in new string[][] { ["ten"], ["-10"], ["+10"], ["10 "], ["10", "10"] })
            {
                string outcome = BufferedOutcome("0123456789"u8.ToArray(), fields);
                Assert.True(outcome == "reset 0x10e",
                    $"content-length {string.Join(" + ", fields.Select(f => $"'{f}'"))}: expected reset 0x10e, got {outcome}");
            }
        });
    }

    /// <summary>
    /// Drive one streaming request whose DATA frame header promises <paramref name="promised"/>
    /// bytes and then delivers ten of them before the fin, and report what the handler's body read
    /// told it: "ended after N" for the empty chunk, "raised X after N" if the read ever says the
    /// body was cut. Promise ten and the request is honest; promise more and it is truncated, and
    /// only the number differs between the two calls.
    /// </summary>
    /// <remarks>
    /// The writes are split and waited out because the ordering is the whole point: the handler
    /// must be dispatched and reading BEFORE the stream ends. Sent as one datagram, Fatal runs
    /// before dispatch and no handler ever sees the body - the safe case, which would make the
    /// truncation test prove nothing.
    /// </remarks>
    private static string StreamedBodyOutcome(long promised, string? contentLength = null)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var readTen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ended = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => new Http3Connection(conn).RunAsync(
                async req =>
                {
                    started.TrySetResult();

                    long total = 0;
                    try
                    {
                        while (true)
                        {
                            ReadOnlyMemory<byte> chunk = await req.BodyReader!.ReadAsync();
                            if (chunk.IsEmpty)
                            {
                                ended.TrySetResult($"ended after {total}");
                                break;
                            }
                            total += chunk.Length;
                            if (total >= 10)
                            {
                                readTen.TrySetResult();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        // The shape a fix would take: the read surface itself says it was cut.
                        ended.TrySetResult($"raised {e.GetType().Name} after {total}");
                    }

                    return Http3Response.Text($"got {total}");
                }));

        using var client = new RawH3Client("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        client.OpenRequestStream();

        client.Write(RawH3Client.RequestHeaders("POST", contentLength is null ? [] : [contentLength]), fin: false);
        Assert.True(client.WaitFor(started.Task, timeoutMs: 5000),
            "the streaming handler never ran, so nothing was reading a body at all");

        client.Write(RawH3Client.DataFrameHeader(promised), fin: false);
        client.Write("0123456789"u8, fin: false);
        Assert.True(client.WaitFor(readTen.Task, timeoutMs: 5000),
            "the handler never received the ten body bytes, so it has nothing it could commit");

        client.Write(default, fin: true);
        Assert.True(client.WaitFor(ended.Task, timeoutMs: 5000),
            "the handler's body read never completed after the stream ended");

        return ended.Task.Result;
    }

    /// <summary>
    /// POST <paramref name="body"/> as one DATA frame under the given content-length fields to a
    /// buffered handler, and report what became of the request: "reset 0x..." with the code the
    /// server reset its stream with, "served" if the handler ran, "nothing" if neither happened.
    /// </summary>
    private static string BufferedOutcome(byte[] body, params string[] contentLengths)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

        try
        {
            int served = 0;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Http3Connection(conn).RunAsync(
                    req =>
                    {
                        Interlocked.Increment(ref served);
                        return Http3Response.Text($"got {req.Body.Length}");
                    }));

            using var client = new RawH3Client("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
            client.OpenRequestStream();

            client.Write([.. RawH3Client.RequestHeaders("POST", contentLengths), .. RawH3Client.DataFrameHeader(body.Length), .. body],
                fin: true);
            ulong? code = client.WaitForReset(timeoutMs: 5000);

            return Volatile.Read(ref served) > 0 ? "served" : code is ulong c ? $"reset 0x{c:x}" : "nothing";
        }
        finally
        {
            // Called more than once per test, so the reactor comes down here, before the engine it
            // was handed: a reactor left running can still be inside native code the dispose freed.
            TestServer.StopAll();
            engine.Dispose();
        }
    }
}

/// <summary>
/// A QUIC client that writes HTTP/3 frames by hand, over the ngtcp2 shim's client entry points -
/// the same ones <see cref="QuicTestClient"/> and <see cref="H3TestClient"/> use. It exists because
/// the truncation under test is one no h3 library will produce: a DATA frame header that promises
/// a length the sender then does not deliver, with the writes split so the server dispatches the
/// handler before the stream is cut. Not production code, and it speaks only enough h3 to ask.
/// </summary>
/// <remarks>
/// It never opens a control stream: the server parses one if it arrives but requires none, and a
/// SETTINGS exchange this test does not read would only be one more thing to go wrong. It also
/// reports the code a request stream was reset with, which <see cref="H3TestClient"/> does not.
/// </remarks>
internal sealed unsafe class RawH3Client : IDisposable
{
    private readonly UdpClient _udp;
    private readonly IPEndPoint _server;
    private nint _engine;
    private nint _conn;
    private GCHandle _self;
    private long _streamId = -1;
    private bool _peerClosed;
    private ulong? _resetCode;

    /// <summary>Whether the peer ended the connection - the engine reports every terminal state.</summary>
    public bool PeerClosed => _peerClosed;

    private static ulong NowNs() => (ulong)(System.Diagnostics.Stopwatch.GetTimestamp() *
                                            (1_000_000_000.0 / System.Diagnostics.Stopwatch.Frequency));

    public RawH3Client(string host, int port)
    {
        _udp = new UdpClient();
        _udp.Client.ReceiveTimeout = 100;   // short: every wait below is a pump loop
        _server = new IPEndPoint(IPAddress.Parse(host), port);
        _udp.Connect(_server);
    }

    public void Connect()
    {
        _self = GCHandle.Alloc(this);
        var callbacks = new IqCallbacks
        {
            StructSize = (nuint)sizeof(IqCallbacks),
            OnStreamData = &OnStreamData,
            OnStreamReset = &OnStreamReset,
        };
        _engine = iq_client_engine_new_mtls("h3", null, null, callbacks);
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

    public void OpenRequestStream()
    {
        _streamId = iq_client_open_bidi(_conn);
        Assert.True(_streamId >= 0, "failed to open the request stream");
    }

    /// <summary>
    /// A HEADERS frame for POST / (or GET /) on localhost: a QPACK field section of static-table
    /// references plus literals with a static name reference, which is the whole encoder surface
    /// a capacity-0 advertisement leaves a client. One content-length field per value given.
    /// </summary>
    public static byte[] RequestHeaders(string method, params string[] contentLengths)
    {
        byte methodIndex = method == "POST" ? (byte)20 : (byte)17;   // static table 20/17
        byte[] authority = "localhost"u8.ToArray();

        var fields = new List<byte>
        {
            0x00, 0x00,                        // required insert count 0, delta base 0
            (byte)(0xC0 | methodIndex),        // indexed, static: :method
            0xC0 | 23,                         // indexed, static: :scheme https
            0xC0 | 1,                          // indexed, static: :path /
            0x50,                              // literal, name = static 0 (:authority)
            (byte)authority.Length,            // value length, not Huffman-coded
        };
        fields.AddRange(authority);

        foreach (string contentLength in contentLengths)
        {
            fields.Add(0x50 | 4);                    // literal, name = static 4 (content-length)
            fields.Add((byte)contentLength.Length);
            fields.AddRange(Encoding.ASCII.GetBytes(contentLength));
        }

        var frame = new List<byte>();
        AppendVarint(frame, 0x1);              // HEADERS
        AppendVarint(frame, fields.Count);
        frame.AddRange(fields);
        return frame.ToArray();
    }

    /// <summary>A DATA frame header promising <paramref name="length"/> payload bytes to follow.</summary>
    public static byte[] DataFrameHeader(long length)
    {
        var frame = new List<byte>();
        AppendVarint(frame, 0x0);              // DATA
        AppendVarint(frame, length);
        return frame.ToArray();
    }

    private static void AppendVarint(List<byte> into, long value)
    {
        if (value < 64)
        {
            into.Add((byte)value);
            return;
        }
        if (value < 16384)
        {
            into.Add((byte)(0x40 | (value >> 8)));
            into.Add((byte)value);
            return;
        }
        into.Add((byte)(0x80 | (value >> 24)));
        into.Add((byte)(value >> 16));
        into.Add((byte)(value >> 8));
        into.Add((byte)value);
    }

    /// <summary>
    /// Write raw bytes, and/or a bare fin, on the request stream. Never drops a tail: while the
    /// engine is blocked it pumps the wire, since the server's credits arrive as datagrams.
    /// </summary>
    public void Write(ReadOnlySpan<byte> data, bool fin)
    {
        long deadline = Environment.TickCount64 + 10_000;
        int off = 0;
        bool finPending = fin;

        while ((off < data.Length || finPending) && !_peerClosed)
        {
            Assert.True(Environment.TickCount64 < deadline, "client write stalled (window never reopened)");

            long consumed;
            nint n;
            fixed (byte* dest = _sendScratch)
            fixed (byte* src = data)
            {
                byte* ptr = off < data.Length ? src + off : null;
                n = iq_conn_write(_conn, dest, (nuint)_sendScratch.Length, _streamId,
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
                    finPending = false;   // the fin rode out with the final bytes
                }
            }
            else if (finPending && off >= data.Length && n > 0)
            {
                finPending = false;       // bare-fin frame went out
            }

            if (n > 0)
            {
                _udp.Send(_sendScratch, (int)n);
            }
            else if (consumed <= 0)
            {
                FlushOut();
                PumpIn();
            }
        }
    }

    /// <summary>
    /// Pump the wire until <paramref name="signal"/> completes or the deadline passes. The signal
    /// is set on the reactor, so this is a bound on a wait, not a measurement of one.
    /// </summary>
    public bool WaitFor(Task signal, int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && !signal.IsCompleted)
        {
            FlushOut();
            PumpIn();
        }
        return signal.IsCompleted;
    }

    /// <summary>
    /// Pump the wire until the server resets the request stream, and return the code it used;
    /// null if the deadline passed or the connection ended first.
    /// </summary>
    public ulong? WaitForReset(int timeoutMs)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline && _resetCode is null && !_peerClosed)
        {
            FlushOut();
            PumpIn();
        }
        return _resetCode;
    }

    private readonly byte[] _sendScratch = new byte[1452];

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

    private void PumpIn()
    {
        try
        {
            IPEndPoint? from = null;
            byte[] packet = _udp.Receive(ref from);
            fixed (byte* p = packet)
            {
                if (iq_conn_read(_conn, null, 0, p, (nuint)packet.Length, 0, NowNs()) != 0)
                {
                    _peerClosed = true;
                }
            }
        }
        catch (SocketException)
        {
            // socket timeout - the caller loops
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

    // The response is never read: this client asks a question the server answers by closing.
    [UnmanagedCallersOnly]
    private static void OnStreamData(void* user, long streamId, byte* data, nuint len, int fin) { }

    [UnmanagedCallersOnly]
    private static void OnStreamReset(void* user, long streamId, ulong appError)
    {
        var self = (RawH3Client)GCHandle.FromIntPtr((nint)user).Target!;
        if (streamId == self._streamId)
        {
            self._resetCode = appError;
        }
    }

    public void Dispose()
    {
        if (_conn != 0) iq_conn_free(_conn);
        if (_engine != 0) iq_client_engine_free(_engine);
        if (_self.IsAllocated) _self.Free();
        _udp.Dispose();
    }

    // --- shim entry points (test-only client surfaces) ---

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
