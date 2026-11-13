using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using ioxide;
using ioxide.http2;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A streamed response its handler aborts (#572), on ioxide.http2 and nghttp3. The stream is reset
/// rather than ended, so a truncated body cannot pass for a whole one, and nothing is reported as a
/// fault: until #572 throwing was the only way to have it reset, and every deliberate reset was also
/// a line on stderr. Once the response has ended some other way, an abort sends nothing.
///
/// On HTTP/2 the server's frames are read off its own transport, because "sends nothing" cannot be
/// seen from HttpClient, which ignores frames on a stream it has closed. On HTTP/3 the raw QUIC client
/// reports each stream's FIN and RESET_STREAM, and the server's resets are counted where it makes them.
/// </summary>
internal static class StreamAbortTests
{
    // RFC 9113 section 7, and RFC 9114 section 8.1.
    private const uint Cancel = 0x8;
    private const ulong H3InternalError = 0x102;
    private const ulong H3RequestCancelled = 0x10c;

    private const byte DataFrame = 0x0, HeadersFrame = 0x1, RstStreamFrame = 0x3;

    private const int ExchangeMs = 10_000;

    public static void Register(Runner runner)
    {
        RegisterHttp2(runner);
        RegisterNghttp3(runner);
    }

    private static void RegisterHttp2(Runner runner)
    {
        runner.Test("abort (ioxide.http2): a response aborted mid-body is reset with INTERNAL_ERROR, sends nothing more, and the connection serves on", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, server.Port, "/abort"));
            Assert.Equal("ended", server.Seen("/abort"));

            // Stream 1: the headers and the part of the body flushed before the abort, then the reset - and
            // nothing after it, though the handler wrote and flushed again.
            Frame[] frames = server.Frames.On(1);
            Assert.Equal("HEADERS, DATA, RST_STREAM 0x2", Describe(frames));

            Assert.Equal("200: partial whole", Fetch(client, server.Port, "/ok"));
            Assert.True(Volatile.Read(ref server.Faults) == 0, "the abort was reported as a handler fault");
        });

        runner.Test("abort (ioxide.http2): the peer is told the code the handler passes", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x8", Fetch(client, server.Port, "/cancel"));
        });

        runner.Test("abort (ioxide.http2): a response aborted before its headers is reset, not answered", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, server.Port, "/abort-early"));
            Assert.Equal("ended", server.Seen("/abort-early"));
            Assert.Equal("RST_STREAM 0x2", Describe(server.Frames.On(1)));

            Assert.Equal("200: partial whole", Fetch(client, server.Port, "/ok"));
        });

        runner.Test("abort (ioxide.http2): an abort once the response has completed, or once the peer has reset the stream, sends nothing", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("200: whole", Fetch(client, server.Port, "/complete"));
            Assert.Equal("aborted", server.Seen("/complete"));
            Assert.True(!Describe(server.Frames.On(1)).Contains("RST_STREAM"),
                $"an abort after the response completed reset it anyway: {Describe(server.Frames.On(1))}");

            // Unread until the stream window is spent, then dropped: RST_STREAM CANCEL. The handler learns
            // it from a flush, and only then aborts - which must not answer a reset with a reset (RFC 9113 5.4.2).
            HttpResponseMessage endless = client.SendAsync(
                new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{server.Port}/endless")
                {
                    Version = HttpVersion.Version20,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                },
                HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
            Thread.Sleep(700);
            endless.Dispose();

            Assert.Equal("aborted once the peer reset it", server.Seen("/endless"));
            Assert.True(!Describe(server.Frames.On(3)).Contains("RST_STREAM"),
                $"an abort after the peer reset the stream answered with a reset: {Describe(server.Frames.On(3))}");
        });

        runner.Test("abort (ioxide.http2): a body read parked when its response is aborted ends there, cut off", () =>
        {
            // A duplex handler - an upstream proxy, say - reads the upload in one task and aborts the
            // response from another once the upstream fails. The reset ends the body reader, but a read
            // parked on it is woken by a read pass, and a peer told of the reset sends nothing to start one.
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(async (reactor, conn) =>
            {
                var timer = new RingTimer(reactor);
                try
                {
                    await new Http2Connection(conn).RunAsync(async (_, body, writer) =>
                    {
                        await body.ReadAsync();                // what the client sends at once
                        Task<string> parked = ReadOn(body);    // the rest, which it holds back
                        await timer.DelayAsync(50);            // out of the read pass, as an upstream's failure would be
                        await writer.AbortAsync();
                        outcome.TrySetResult(await parked);
                    });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using HttpClient client = H2Client();
            var held = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _ = client.SendAsync(new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{port}/upload")
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new HeldContent(held.Task),
            });

            bool ended = outcome.Task.Wait(ExchangeMs);
            held.TrySetResult();
            Assert.True(ended, "the body read stayed parked after its stream was reset");
            Assert.Equal("cut off", outcome.Task.Result);
        });
    }

    private static void RegisterNghttp3(Runner runner)
    {
        runner.Test("abort (nghttp3): a response aborted mid-body is reset with H3_INTERNAL_ERROR, sends nothing more, and the connection serves on", () =>
        {
            H3Server server = StartH3();
            using TeardownWireClient client = ConnectWire(server);

            long aborted = client.SendRequest(GetFor("/abort"));
            AssertReset(client, aborted, H3InternalError);
            Assert.Equal("ended", server.Seen("/abort"));

            long next = client.SendRequest(GetFor("/ok"));
            Assert.True(client.ConverseUntil(() => client.SawFin(next), ExchangeMs), "the connection stopped serving after a response was aborted");
            Assert.True(Volatile.Read(ref server.Faults) == 0, "the abort was reported as a handler fault");
        });

        runner.Test("abort (nghttp3): the peer is told the code the handler passes, and one QUIC cannot carry is refused", () =>
        {
            H3Server server = StartH3();
            using TeardownWireClient client = ConnectWire(server);

            AssertReset(client, client.SendRequest(GetFor("/cancel")), H3RequestCancelled);
            Assert.Equal("ended", server.Seen("/cancel"));
        });

        runner.Test("abort (nghttp3): a response aborted before its headers is reset, not answered", () =>
        {
            H3Server server = StartH3();
            using TeardownWireClient client = ConnectWire(server);

            AssertReset(client, client.SendRequest(GetFor("/abort-early")), H3InternalError);
            Assert.Equal("ended", server.Seen("/abort-early"));

            long next = client.SendRequest(GetFor("/ok"));
            Assert.True(client.ConverseUntil(() => client.SawFin(next), ExchangeMs), "the connection stopped serving after a response was aborted");
        });

        runner.Test("abort (nghttp3): an abort once the response has completed, or once the peer has stopped the stream, sends nothing", () =>
        {
            H3Server server = StartH3();
            using var client = new H3TestClient("127.0.0.1", server.Port);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5_000), "handshake did not complete");

            // CompleteAsync returns before nghttp3 has taken the end, so a reset here would cost the
            // response its FIN, and possibly its body.
            (int status, string body) = client.Get("/complete", timeoutMs: 5_000);
            Assert.Equal("aborted", server.Seen("/complete"));
            Assert.True(server.Resets.Count == 0, $"an abort after the response completed reset it anyway: {server.Resets}");
            Assert.True(status == 200 && body == "whole", $"the completed response arrived as {status} [{body}]");

            // STOP_SENDING and RESET_STREAM, as a closed tab sends them. The handler learns it from a flush,
            // and only then aborts.
            Assert.True(client.RequestThenCancel("/endless", readMs: 500) > 0, "none of the endless response arrived, so no stream was in flight to stop");
            long until = Environment.TickCount64 + ExchangeMs;
            while (!server.HasSeen("/endless") && Environment.TickCount64 < until)
            {
                client.Pump(50);   // the server learns from the peer's frames, so the connection has to keep turning
            }
            Assert.Equal("aborted once the peer stopped it", server.Seen("/endless"));
            Assert.True(server.Resets.Count == 0, $"an abort after the peer stopped the stream reset it: {server.Resets}");
        });
    }

    // ---- HTTP/2 -------------------------------------------------------------------------------

    private sealed class H2Server : Reports
    {
        public readonly FrameLog Frames = new();
        public int Faults;
        public int Port;
    }

    private static H2Server StartH2()
    {
        var server = new H2Server();
        var options = new Http2Options { OnHandlerFault = (_, _) => Interlocked.Increment(ref server.Faults) };

        server.Port = TestServer.Start(async (reactor, conn) =>
        {
            try
            {
                await new Http2Connection(server.Frames.Wrap(new TcpConnectionDualPipe(conn)), options).RunAsync(Route(server, reactor));
            }
            finally
            {
                conn.DecRef();
            }
        });
        return server;
    }

    /// <summary>
    /// "/abort" and "/cancel" abort after part of the body, then write and flush again; "/abort-early"
    /// aborts before its headers, "/complete" once it has completed, "/endless" once its peer has reset
    /// it. Anything else is answered whole.
    /// </summary>
    private static Func<Http2Request, Http2ResponseWriter, ValueTask> Route(H2Server server, Reactor reactor)
    {
        var timer = new RingTimer(reactor);

        return async (request, writer) =>
        {
            string path = Encoding.ASCII.GetString(request.Path.Span);
            switch (path)
            {
                case "/abort-early":
                    await writer.AbortAsync();
                    server.Saw(path, writer.IsCompleted ? "ended" : "the writer has not ended");
                    return;

                case "/complete":
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    writer.Write("whole"u8);
                    await writer.CompleteAsync();
                    await writer.AbortAsync();
                    server.Saw(path, "aborted");
                    return;

                case "/endless":
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    for (int i = 0; i < 6_000; i++)
                    {
                        writer.Write(Chunk);
                        if ((await writer.FlushAsync()).IsCompleted)
                        {
                            await writer.AbortAsync();
                            server.Saw(path, "aborted once the peer reset it");
                            return;
                        }
                        await timer.DelayAsync(5);
                    }
                    server.Saw(path, "never learned the peer had reset it");
                    return;
            }

            writer.WriteHeaders(new Http2Response { Status = 200 });
            writer.Write("partial"u8);
            await writer.FlushAsync();

            if (path is "/abort" or "/cancel")
            {
                await (path == "/cancel" ? writer.AbortAsync(Cancel) : writer.AbortAsync());
                writer.Write(" more"u8);
                FlushResult after = await writer.FlushAsync();
                server.Saw(path, Ended(after, writer.IsCompleted));
                return;
            }

            writer.Write(" whole"u8);
        };
    }

    // What a writer says once it has been aborted: nobody is reading, and the response is over.
    private static string Ended(FlushResult after, bool writerCompleted)
        => after.IsCompleted && writerCompleted
            ? "ended"
            : $"after the abort a flush reported IsCompleted={after.IsCompleted} and the writer IsCompleted={writerCompleted}";

    private static readonly byte[] Chunk = new byte[1024];

    // Cleartext HTTP/2 with prior knowledge, one connection for every request of a test.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(10),
    };

    // "status: body" for a response read to its end, "reset 0xN" for one whose stream was reset under it.
    private static string Fetch(HttpClient client, int port, string path)
    {
        try
        {
            using HttpResponseMessage response = client.GetAsync($"http://127.0.0.1:{port}{path}").GetAwaiter().GetResult();
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return $"{(int)response.StatusCode}: {body}";
        }
        catch (Exception caught)
        {
            for (Exception? e = caught; e is not null; e = e.InnerException)
            {
                if (e is HttpProtocolException protocol)
                {
                    return $"reset 0x{protocol.ErrorCode:x}";
                }
            }
            return caught is TaskCanceledException ? "no answer in time" : $"failed: {caught.GetBaseException().Message}";
        }
    }

    // The rest of the body after the first chunk, as the handler that parked on it saw it end.
    private static async Task<string> ReadOn(Http2BodyReader body)
    {
        try
        {
            ReadOnlyMemory<byte> chunk = await body.ReadAsync();
            return chunk.IsEmpty ? "ended whole" : $"read {chunk.Length} more bytes";
        }
        catch (IOException)
        {
            return "cut off";
        }
    }

    // An upload that sends its first bytes at once and holds the rest back until the test lets go.
    private sealed class HeldContent(Task held) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            await stream.WriteAsync("first"u8.ToArray(), cancellationToken);
            await stream.FlushAsync(cancellationToken);
            await held.WaitAsync(cancellationToken);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private readonly record struct Frame(byte Type, byte Flags, int StreamId, uint ErrorCode)
    {
        public override string ToString() => Type switch
        {
            HeadersFrame => (Flags & 0x1) != 0 ? "HEADERS END_STREAM" : "HEADERS",
            DataFrame => (Flags & 0x1) != 0 ? "DATA END_STREAM" : "DATA",
            RstStreamFrame => $"RST_STREAM 0x{ErrorCode:x}",
            _ => $"frame 0x{Type:x}",
        };
    }

    // The stream's frames in order, DATA frames that follow each other folded into one: how the body was
    // cut into frames is the window's business, not what is being asserted.
    private static string Describe(Frame[] frames)
    {
        var described = new List<string>();
        foreach (Frame frame in frames)
        {
            string name = frame.ToString();
            if (name == "DATA" && described.Count > 0 && described[^1] == "DATA")
            {
                continue;
            }
            described.Add(name);
        }
        return string.Join(", ", described);
    }

    /// <summary>
    /// The frames a server wrote, read off its transport: every connection's, so a stream id names one
    /// only while a test's requests share a connection - which HttpClient's HTTP/2 does, and the
    /// harness's listen probe sends none. Written on the reactor, read by the test.
    /// </summary>
    private sealed class FrameLog
    {
        private readonly List<Frame> _frames = [];

        public IDuplexPipe Wrap(IDuplexPipe inner) => new Pipe(inner.Input, new Recorder(inner.Output, this));

        public Frame[] On(int streamId)
        {
            lock (_frames)
            {
                return [.. _frames.Where(frame => frame.StreamId == streamId)];
            }
        }

        private void Add(Frame frame)
        {
            lock (_frames)
            {
                _frames.Add(frame);
            }
        }

        private sealed class Pipe(PipeReader input, PipeWriter output) : IDuplexPipe
        {
            public PipeReader Input => input;
            public PipeWriter Output => output;
        }

        // Splits what is written into frames, however the writes fall across them.
        private sealed class Recorder(PipeWriter inner, FrameLog log) : PipeWriter
        {
            private Memory<byte> _handedOut;
            private byte[] _pending = new byte[1024];
            private int _pendingUsed;

            public override Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

            public override Memory<byte> GetMemory(int sizeHint = 0) => _handedOut = inner.GetMemory(sizeHint);

            public override void Advance(int bytes)
            {
                Take(_handedOut.Span[..bytes]);
                inner.Advance(bytes);
            }

            public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
                => inner.FlushAsync(cancellationToken);

            public override void CancelPendingFlush() => inner.CancelPendingFlush();

            public override void Complete(Exception? exception = null) => inner.Complete(exception);

            private void Take(ReadOnlySpan<byte> bytes)
            {
                if (_pending.Length - _pendingUsed < bytes.Length)
                {
                    Array.Resize(ref _pending, Math.Max(_pending.Length * 2, _pendingUsed + bytes.Length));
                }
                bytes.CopyTo(_pending.AsSpan(_pendingUsed));
                _pendingUsed += bytes.Length;

                int at = 0;
                while (_pendingUsed - at >= 9)
                {
                    ReadOnlySpan<byte> header = _pending.AsSpan(at, 9);
                    int length = (header[0] << 16) | (header[1] << 8) | header[2];
                    if (_pendingUsed - at < 9 + length)
                    {
                        break;
                    }

                    byte type = header[3];
                    int streamId = (int)(BinaryPrimitives.ReadUInt32BigEndian(header[5..]) & 0x7FFFFFFF);
                    uint code = type == RstStreamFrame && length == 4 ? BinaryPrimitives.ReadUInt32BigEndian(_pending.AsSpan(at + 9, 4)) : 0;
                    log.Add(new Frame(type, header[4], streamId, code));
                    at += 9 + length;
                }

                _pending.AsSpan(at, _pendingUsed - at).CopyTo(_pending);
                _pendingUsed -= at;
            }
        }
    }

    // ---- HTTP/3 -------------------------------------------------------------------------------

    private sealed class H3Server : Reports
    {
        public readonly ResetLog Resets = new();
        public int Faults;
        public int Port;
    }

    private static H3Server StartH3()
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
        var server = new H3Server();
        var options = new Nghttp3Options { OnHandlerFault = (_, _) => Interlocked.Increment(ref server.Faults) };

        (_, server.Port) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(_ => new ResetCounting(engine, server.Resets)),
            quicHandle: (reactor, conn) => new Nghttp3Connection(conn, options).RunAsync(Route(server, reactor)));
        return server;
    }

    /// <summary>The paths of the HTTP/2 route, on nghttp3; "/cancel" first tries a code past 62 bits.</summary>
    private static Func<Nghttp3Request, Nghttp3ResponseWriter, ValueTask> Route(H3Server server, Reactor reactor)
    {
        var timer = new RingTimer(reactor);

        return async (request, writer) =>
        {
            string path = Encoding.ASCII.GetString(request.Path.Span);
            switch (path)
            {
                case "/abort-early":
                    await writer.AbortAsync();
                    server.Saw(path, writer.IsCompleted ? "ended" : "the writer has not ended");
                    return;

                case "/complete":
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                    writer.Write("whole"u8);
                    await writer.CompleteAsync();
                    await writer.AbortAsync();
                    server.Saw(path, "aborted");
                    return;

                case "/endless":
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                    for (int i = 0; i < 6_000; i++)
                    {
                        writer.Write(Chunk);
                        if ((await writer.FlushAsync()).IsCompleted)
                        {
                            await writer.AbortAsync();
                            server.Saw(path, "aborted once the peer stopped it");
                            return;
                        }
                        await timer.DelayAsync(5);
                    }
                    server.Saw(path, "never learned the peer had stopped it");
                    return;
            }

            writer.WriteHeaders(new Nghttp3Response { Status = 200 });
            writer.Write("partial"u8);
            await writer.FlushAsync();

            if (path == "/abort")
            {
                await writer.AbortAsync();
                writer.Write(" more"u8);
                server.Saw(path, Ended(await writer.FlushAsync(), writer.IsCompleted));
                return;
            }

            if (path == "/cancel")
            {
                bool refused = false;
                try
                {
                    await writer.AbortAsync(1UL << 62);
                }
                catch (ArgumentOutOfRangeException)
                {
                    refused = true;
                }

                await writer.AbortAsync(H3RequestCancelled);
                server.Saw(path, refused ? "ended" : "a code past 62 bits was taken");
                return;
            }

            writer.Write(" whole"u8);
        };
    }

    private static TeardownWireClient ConnectWire(H3Server server)
    {
        var client = new TeardownWireClient(server.Port, alpn: "h3");
        Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");
        return client;
    }

    private static void AssertReset(TeardownWireClient client, long streamId, ulong expected)
    {
        Assert.True(client.ConverseUntil(() => client.SawFin(streamId) || client.SawReset(streamId, out _), ExchangeMs),
            "the aborted response never ended at all");
        Assert.True(!client.SawFin(streamId),
            "the aborted response ended cleanly: its truncated body cannot be told apart from a whole one");
        Assert.True(client.SawReset(streamId, out ulong code) && code == expected,
            $"expected RESET_STREAM 0x{expected:x}, got 0x{code:x}");
    }

    // A GET for the path, framed by hand: HEADERS, the field-section prefix 00 00, static-table :method
    // GET and :scheme https, then :path and :authority "localhost" as literals on their static names.
    private static byte[] GetFor(string path)
    {
        byte[] fields = [0x00, 0x00, 0xD1, 0xD7, 0x51, (byte)path.Length, .. Encoding.ASCII.GetBytes(path), 0x50, 0x09, .. "localhost"u8.ToArray()];
        return [0x01, (byte)fields.Length, .. fields];
    }

    /// <summary>Every stream the stack reset, with its code: where the server makes the call, so a reset is seen whatever the peer makes of it.</summary>
    private sealed class ResetLog
    {
        private readonly List<string> _resets = [];

        public int Count
        {
            get
            {
                lock (_resets)
                {
                    return _resets.Count;
                }
            }
        }

        public void Add(long streamId, ulong code)
        {
            lock (_resets)
            {
                _resets.Add($"stream {streamId} with 0x{code:x}");
            }
        }

        public override string ToString()
        {
            lock (_resets)
            {
                return string.Join(", ", _resets);
            }
        }
    }

    private sealed class ResetCounting(QuicEngine engine, ResetLog resets) : QuicEngineConnection(engine)
    {
        public override void ResetStream(long streamId, ulong applicationErrorCode)
        {
            resets.Add(streamId, applicationErrorCode);
            base.ResetStream(streamId, applicationErrorCode);
        }
    }

    // ---- shared -------------------------------------------------------------------------------

    /// <summary>What each path's handler reported once it was done, for the test to wait on.</summary>
    private abstract class Reports
    {
        private readonly Dictionary<string, TaskCompletionSource<string>> _seen = [];

        public void Saw(string path, string what) => For(path).TrySetResult(what);

        public bool HasSeen(string path) => For(path).Task.IsCompleted;

        public string Seen(string path)
            => For(path).Task.Wait(ExchangeMs) ? For(path).Task.Result : "nothing: the handler never got there";

        private TaskCompletionSource<string> For(string path)
        {
            lock (_seen)
            {
                if (!_seen.TryGetValue(path, out TaskCompletionSource<string>? seen))
                {
                    seen = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _seen[path] = seen;
                }
                return seen;
            }
        }
    }
}
