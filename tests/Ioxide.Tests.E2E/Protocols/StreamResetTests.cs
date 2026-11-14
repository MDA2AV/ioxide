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
/// ResetStreamAsync on a streamed response (#572), on ioxide.http2 and nghttp3. The stream is reset
/// rather than ended, so a truncated body cannot pass for a whole one, and nothing is reported as a
/// fault: until #572 throwing was the only way to have it reset, and every deliberate reset was also
/// a line on stderr. Once the response has ended some other way, ResetStreamAsync sends nothing.
///
/// On HTTP/2 the server's frames are read off its own transport, because "sends nothing" cannot be
/// seen from HttpClient, which ignores frames on a stream it has closed. On HTTP/3 the raw QUIC client
/// reports each stream's FIN and RESET_STREAM, and the server's resets are counted where it makes them.
/// </summary>
internal static class StreamResetTests
{
    private const byte DataFrame = 0x0, HeadersFrame = 0x1, RstStreamFrame = 0x3;

    private const int ExchangeMs = 10_000;

    public static void Register(Runner runner)
    {
        RegisterHttp2(runner);
        RegisterNghttp3(runner);
    }

    private static void RegisterHttp2(Runner runner)
    {
        runner.Test("ResetStreamAsync (ioxide.http2): mid-body, the stream is reset with INTERNAL_ERROR, nothing more is sent, and the connection serves on", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, server.Port, "/reset"));
            Assert.Equal("ended", server.Seen("/reset"));

            // Stream 1: the headers and the part of the body flushed before ResetStreamAsync, then the reset - and
            // nothing after it, though the handler wrote and flushed again.
            Frame[] frames = server.Frames.On(1);
            Assert.Equal("HEADERS, DATA, RST_STREAM 0x2", Describe(frames));

            Assert.Equal("200: partial whole", Fetch(client, server.Port, "/ok"));
            Assert.True(Volatile.Read(ref server.Faults) == 0, "ResetStreamAsync was reported as a handler fault");
        });

        runner.Test("ResetStreamAsync (ioxide.http2): the peer is told the code the handler passes", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x8", Fetch(client, server.Port, "/cancel"));
        });

        runner.Test("ResetStreamAsync (ioxide.http2): before its headers, the stream is reset, not answered, and a flush after it reports the peer gone", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, server.Port, "/reset-early"));
            Assert.Equal("ended", server.Seen("/reset-early"));
            Assert.Equal("RST_STREAM 0x2", Describe(server.Frames.On(1)));

            Assert.Equal("200: partial whole", Fetch(client, server.Port, "/ok"));
        });

        runner.Test("ResetStreamAsync (ioxide.http2): once the response has completed, or once the peer has reset the stream, it sends nothing", () =>
        {
            H2Server server = StartH2();
            using HttpClient client = H2Client();

            Assert.Equal("200: whole", Fetch(client, server.Port, "/complete"));
            Assert.Equal("reset", server.Seen("/complete"));
            Assert.True(!Describe(server.Frames.On(1)).Contains("RST_STREAM"),
                $"ResetStreamAsync after the response completed reset it anyway: {Describe(server.Frames.On(1))}");

            // Unread until the stream window is spent, then dropped: RST_STREAM CANCEL. The handler learns
            // it from a flush, and only then calls ResetStreamAsync, which must not answer a reset with a reset (RFC 9113 5.4.2).
            HttpResponseMessage endless = client.SendAsync(
                new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{server.Port}/endless")
                {
                    Version = HttpVersion.Version20,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                },
                HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
            Thread.Sleep(700);
            endless.Dispose();

            Assert.Equal("reset once the peer reset it", server.Seen("/endless"));
            Assert.True(!Describe(server.Frames.On(3)).Contains("RST_STREAM"),
                $"ResetStreamAsync after the peer reset the stream answered with a reset: {Describe(server.Frames.On(3))}");
        });

        runner.Test("ResetStreamAsync (ioxide.http2): a body read parked when its stream is reset ends there, cut off", () =>
        {
            // A duplex handler - an upstream proxy, say - reads the upload in one task and resets the
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
                        Task<string> parked = ReadOn(body.ReadAsync);   // the rest, which it holds back
                        await timer.DelayAsync(50);            // out of the read pass, as an upstream's failure would be
                        await writer.ResetStreamAsync();
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

        runner.Test("ResetStreamAsync (ioxide.http2): once the reactor has stopped it returns, and the writer has ended", () =>
        {
            // ResetStreamAsync is usually called from a catch, where a throw would replace what the caller is handling.
            var handed = new TaskCompletionSource<Http2ResponseWriter>(TaskCreationOptions.RunContinuationsAsynchronously);
            var never = new TaskCompletionSource();
            int port = TestServer.Start(async (_, conn) =>
            {
                try
                {
                    await new Http2Connection(conn).RunAsync(async (_, writer) =>
                    {
                        writer.WriteHeaders(new Http2Response { Status = 200 });
                        await writer.FlushAsync();
                        handed.TrySetResult(writer);
                        await never.Task;   // still running when its reactor stops
                    });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using HttpClient client = H2Client();
            _ = client.GetAsync($"http://127.0.0.1:{port}/", HttpCompletionOption.ResponseHeadersRead);
            Assert.True(handed.Task.Wait(ExchangeMs), "the handler never got its response under way");

            TestServer.StopAll();
            Http2ResponseWriter writer = handed.Task.Result;
            Assert.Equal("ended", ResetAfterStop(() => writer.ResetStreamAsync(), () => writer.IsCompleted, writer.FlushAsync));
        });
    }

    private static void RegisterNghttp3(Runner runner)
    {
        runner.Test("ResetStreamAsync (nghttp3): mid-body, the stream is reset with H3_INTERNAL_ERROR, nothing more is sent, and the connection serves on", () =>
        {
            H3Server server = StartH3();
            using TeardownWireClient client = ConnectWire(server);

            long reset = client.SendRequest(GetFor("/reset"));
            AssertReset(client, reset, Nghttp3ErrorCode.InternalError);
            Assert.Equal("ended", server.Seen("/reset"));

            long next = client.SendRequest(GetFor("/ok"));
            Assert.True(client.ConverseUntil(() => client.SawFin(next), ExchangeMs), "the connection stopped serving after a stream was reset");
            Assert.True(Volatile.Read(ref server.Faults) == 0, "ResetStreamAsync was reported as a handler fault");
        });

        runner.Test("ResetStreamAsync (nghttp3): the peer is told the code the handler passes, and one QUIC cannot carry is refused", () =>
        {
            H3Server server = StartH3();
            using TeardownWireClient client = ConnectWire(server);

            AssertReset(client, client.SendRequest(GetFor("/cancel")), Nghttp3ErrorCode.RequestCancelled);
            Assert.Equal("ended", server.Seen("/cancel"));
        });

        runner.Test("ResetStreamAsync (nghttp3): before its headers, the stream is reset, not answered, and a flush after it reports the peer gone", () =>
        {
            H3Server server = StartH3();
            using TeardownWireClient client = ConnectWire(server);

            AssertReset(client, client.SendRequest(GetFor("/reset-early")), Nghttp3ErrorCode.InternalError);
            Assert.Equal("ended", server.Seen("/reset-early"));

            long next = client.SendRequest(GetFor("/ok"));
            Assert.True(client.ConverseUntil(() => client.SawFin(next), ExchangeMs), "the connection stopped serving after a stream was reset");
        });

        runner.Test("ResetStreamAsync (nghttp3): once the response has completed, or once the peer has stopped the stream, it sends nothing", () =>
        {
            H3Server server = StartH3();
            using var client = new H3TestClient("127.0.0.1", server.Port);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5_000), "handshake did not complete");

            // CompleteAsync returns before nghttp3 has taken the end, so a reset here would cost the
            // response its FIN, and possibly its body.
            (int status, string body) = client.Get("/complete", timeoutMs: 5_000);
            Assert.Equal("reset", server.Seen("/complete"));
            Assert.True(server.Resets.Count == 0, $"ResetStreamAsync after the response completed reset it anyway: {server.Resets}");
            Assert.True(status == 200 && body == "whole", $"the completed response arrived as {status} [{body}]");

            // STOP_SENDING and RESET_STREAM, as a closed tab sends them. The handler learns it from a flush,
            // and only then calls ResetStreamAsync.
            Assert.True(client.RequestThenCancel("/endless", readMs: 500) > 0, "none of the endless response arrived, so no stream was in flight to stop");
            long until = Environment.TickCount64 + ExchangeMs;
            while (!server.HasSeen("/endless") && Environment.TickCount64 < until)
            {
                client.Pump(50);   // the server learns from the peer's frames, so the connection has to keep turning
            }
            Assert.Equal("reset once the peer stopped it", server.Seen("/endless"));
            Assert.True(server.Resets.Count == 0, $"ResetStreamAsync after the peer stopped the stream reset it: {server.Resets}");
        });

        runner.Test("ResetStreamAsync (nghttp3): a body read parked when its stream is reset ends there, cut off", () =>
        {
            // As on HTTP/2. The reset asks the peer to stop sending as well, and its answering reset would
            // end the read too, so the client is not turned over after its request: it never answers.
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
            (_, int port) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (reactor, conn) =>
                {
                    var timer = new RingTimer(reactor);
                    return new Nghttp3Connection(conn).RunAsync(async (_, body, writer) =>
                    {
                        await body.ReadAsync();                // what the client sends at once
                        Task<string> parked = ReadOn(body.ReadAsync);   // the rest, which it holds back
                        await timer.DelayAsync(50);            // out of the read pass, as an upstream's failure would be
                        await writer.ResetStreamAsync();
                        outcome.TrySetResult(await parked);
                    });
                });

            using var client = new TeardownWireClient(port, alpn: "h3");
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");
            client.SendRequest(PostFor("/upload", "first"u8.ToArray()), fin: false);

            Assert.True(outcome.Task.Wait(ExchangeMs), "the body read stayed parked after its stream was reset");
            Assert.Equal("cut off", outcome.Task.Result);
        });

        runner.Test("ResetStreamAsync (nghttp3): a flush waiting on a silent peer when another task resets the stream returns, and reports the peer gone", () =>
        {
            // As on HTTP/2, from a timeout on a peer that stopped reading. A parked flush wakes on a pass,
            // and a silent peer starts none, so the client sends nothing once the response is under way.
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
            (_, int port) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (reactor, conn) =>
                {
                    var timer = new RingTimer(reactor);
                    return new Nghttp3Connection(conn).RunAsync(async (_, writer) =>
                    {
                        writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                        long flushing = 0;   // when the flush under way began, or 0
                        Task timeout = ResetOnceParkedAsync(timer, () => flushing, () => writer.ResetStreamAsync());
                        for (int i = 0; i < 4_096; i++)
                        {
                            writer.Write(BigChunk);
                            flushing = Environment.TickCount64;
                            FlushResult flushed = await writer.FlushAsync();
                            flushing = 0;
                            if (flushed.IsCompleted)
                            {
                                await timeout;
                                outcome.TrySetResult(writer.IsCompleted ? "peer gone" : "the flush reported the peer gone, but the writer has not ended");
                                return;
                            }
                        }
                        outcome.TrySetResult("the peer took the whole response, so no flush waited on it");
                    });
                });

            using var client = new TeardownWireClient(port, alpn: "h3");
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");
            client.SendRequest(GetFor("/"));
            client.Converse(200);   // the response under way; from here on the client is silent

            Assert.True(outcome.Task.Wait(ExchangeMs), "the flush waiting on the silent peer slept through the reset");
            Assert.Equal("peer gone", outcome.Task.Result);
        });

        runner.Test("ResetStreamAsync (nghttp3): once the reactor has stopped it returns, and the writer has ended", () =>
        {
            var handed = new TaskCompletionSource<Nghttp3ResponseWriter>(TaskCreationOptions.RunContinuationsAsynchronously);
            var never = new TaskCompletionSource();
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
            (_, int port) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Nghttp3Connection(conn).RunAsync(async (_, writer) =>
                {
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                    await writer.FlushAsync();
                    handed.TrySetResult(writer);
                    await never.Task;   // still running when its reactor stops
                }));

            using (var client = new TeardownWireClient(port, alpn: "h3"))
            {
                Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");
                client.SendRequest(GetFor("/"));
                Assert.True(client.ConverseUntil(() => handed.Task.IsCompleted, ExchangeMs), "the handler never got its response under way");
            }

            TestServer.StopAll();
            Nghttp3ResponseWriter writer = handed.Task.Result;
            Assert.Equal("ended", ResetAfterStop(() => writer.ResetStreamAsync(), () => writer.IsCompleted, writer.FlushAsync));
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
    /// "/reset" and "/cancel" reset after part of the body, then write and flush again; "/reset-early"
    /// resets before its headers, then flushes, "/complete" once it has completed, "/endless" once its
    /// peer has reset it. Anything else is answered whole.
    /// </summary>
    private static Func<Http2Request, Http2ResponseWriter, ValueTask> Route(H2Server server, Reactor reactor)
    {
        var timer = new RingTimer(reactor);

        return async (request, writer) =>
        {
            string path = Encoding.ASCII.GetString(request.Path.Span);
            switch (path)
            {
                case "/reset-early":
                    await writer.ResetStreamAsync();
                    server.Saw(path, await EndedAfter(writer.FlushAsync, () => writer.IsCompleted));
                    return;

                case "/complete":
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    writer.Write("whole"u8);
                    await writer.CompleteAsync();
                    await writer.ResetStreamAsync();
                    server.Saw(path, "reset");
                    return;

                case "/endless":
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    for (int i = 0; i < 6_000; i++)
                    {
                        writer.Write(Chunk);
                        if ((await writer.FlushAsync()).IsCompleted)
                        {
                            await writer.ResetStreamAsync();
                            server.Saw(path, "reset once the peer reset it");
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

            if (path is "/reset" or "/cancel")
            {
                await (path == "/cancel" ? writer.ResetStreamAsync(Http2ErrorCode.Cancel) : writer.ResetStreamAsync());
                writer.Write(" more"u8);
                FlushResult after = await writer.FlushAsync();
                server.Saw(path, Ended(after, writer.IsCompleted));
                return;
            }

            writer.Write(" whole"u8);
        };
    }

    // What a writer says once its stream has been reset: nobody is reading, and the response is over.
    private static string Ended(FlushResult after, bool writerCompleted)
        => after.IsCompleted && writerCompleted
            ? "ended"
            : $"after the reset a flush reported IsCompleted={after.IsCompleted} and the writer IsCompleted={writerCompleted}";

    // Ended, for a flush that may throw instead.
    private static async Task<string> EndedAfter(Func<ValueTask<FlushResult>> flush, Func<bool> writerCompleted)
    {
        try
        {
            return Ended(await flush(), writerCompleted());
        }
        catch (Exception e)
        {
            return $"a flush after the reset threw {e.GetType().Name}: {e.Message}";
        }
    }

    // Ended, for a ResetStreamAsync made from the test once the server's reactor has stopped: it has to return, not throw.
    private static string ResetAfterStop(Func<ValueTask> reset, Func<bool> writerCompleted, Func<ValueTask<FlushResult>> flush)
    {
        try
        {
            if (!reset().AsTask().Wait(ExchangeMs))
            {
                return "ResetStreamAsync never returned";
            }
        }
        catch (AggregateException e)
        {
            return $"ResetStreamAsync threw {e.InnerException!.GetType().Name}: {e.InnerException.Message}";
        }

        Task<string> ended = EndedAfter(flush, writerCompleted);
        return ended.Wait(ExchangeMs) ? ended.Result : "a flush after the reset never returned";
    }

    private static readonly byte[] Chunk = new byte[1024];
    private static readonly byte[] BigChunk = new byte[64 * 1024];

    // The timeout: once a flush has waited on the peer for a while, the stream is reset from this other task.
    private static async Task ResetOnceParkedAsync(RingTimer timer, Func<long> flushing, Func<ValueTask> reset)
    {
        while (true)
        {
            await timer.DelayAsync(50);
            long since = flushing();
            if (since != 0 && Environment.TickCount64 - since > 300)
            {
                await reset();
                return;
            }
        }
    }

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
    private static async Task<string> ReadOn(Func<ValueTask<ReadOnlyMemory<byte>>> read)
    {
        try
        {
            ReadOnlyMemory<byte> chunk = await read();
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
                case "/reset-early":
                    await writer.ResetStreamAsync();
                    server.Saw(path, await EndedAfter(writer.FlushAsync, () => writer.IsCompleted));
                    return;

                case "/complete":
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                    writer.Write("whole"u8);
                    await writer.CompleteAsync();
                    await writer.ResetStreamAsync();
                    server.Saw(path, "reset");
                    return;

                case "/endless":
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                    for (int i = 0; i < 6_000; i++)
                    {
                        writer.Write(Chunk);
                        if ((await writer.FlushAsync()).IsCompleted)
                        {
                            await writer.ResetStreamAsync();
                            server.Saw(path, "reset once the peer stopped it");
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

            if (path == "/reset")
            {
                await writer.ResetStreamAsync();
                writer.Write(" more"u8);
                server.Saw(path, Ended(await writer.FlushAsync(), writer.IsCompleted));
                return;
            }

            if (path == "/cancel")
            {
                bool refused = false;
                try
                {
                    await writer.ResetStreamAsync(1UL << 62);
                }
                catch (ArgumentOutOfRangeException)
                {
                    refused = true;
                }

                await writer.ResetStreamAsync(Nghttp3ErrorCode.RequestCancelled);
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
            "the response that was reset never ended at all");
        Assert.True(!client.SawFin(streamId),
            "the response that was reset ended cleanly: its truncated body cannot be told apart from a whole one");
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

    // A POST framed the same way, :method POST being static entry 20, then one DATA frame of the body's first bytes.
    private static byte[] PostFor(string path, byte[] first)
    {
        byte[] fields = [0x00, 0x00, 0xD4, 0xD7, 0x51, (byte)path.Length, .. Encoding.ASCII.GetBytes(path), 0x50, 0x09, .. "localhost"u8.ToArray()];
        return [0x01, (byte)fields.Length, .. fields, 0x00, (byte)first.Length, .. first];
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
