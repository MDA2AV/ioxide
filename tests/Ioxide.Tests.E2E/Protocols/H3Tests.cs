using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// The full HTTP/3 stack end to end: the ioxide reactor runs ngtcp2 + the ioxide.nghttp3 (nghttp3)
/// layer behind a QuicHandle; the client is a bare ngtcp2 + nghttp3 driver over a real loopback
/// UDP socket (the shims' test-only client entry points). Handshake, SETTINGS/QPACK prefaces,
/// request and response all cross the wire encrypted.
/// </summary>
internal static class H3Tests
{
    public static void Register(Runner runner)
    {
        runner.Test("h3: GET request/response through ioxide.nghttp3 (loopback)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static req => Nghttp3Response.Text($"hello {Encoding.ASCII.GetString(req.Path.Span)} via {Encoding.ASCII.GetString(req.Method.Span)}")));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/greet", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("hello /greet via GET", body);
        });

        runner.Test("h3: streaming body upload (end-of-headers dispatch, paced window)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            // The async overload: dispatch fires at end-of-headers and the body is pulled through
            // BodyReader while the stream is flow-control paced.
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunStreamingAsync(
                    static async req =>
                    {
                        long total = 0;
                        while (true)
                        {
                            ReadOnlyMemory<byte> chunk = await req.BodyReader!.ReadAsync();
                            if (chunk.IsEmpty)
                            {
                                break;
                            }
                            total += chunk.Length;
                        }
                        return Nghttp3Response.Text($"got {total}");
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // 600 KB > the 256 KB stream window: the transfer only completes if consumed bytes
            // are credited back mid-flight - this exercises the whole pacing/consume path.
            var body = new byte[600_000];
            new Random(7).NextBytes(body);

            (int status, string text) = client.Request("POST", "/upload", body, timeoutMs: 10_000);
            Assert.Equal(200, status);
            Assert.Equal("got 600000", text);
        });

        runner.Test("h3: uploads a streaming handler never reads give their connection credit back", () =>
            Http3Tests.UnreadUploadsGiveCreditBack((conn, answer) => new Nghttp3Connection(conn).RunStreamingAsync(
                async req => new Nghttp3Response { Status = await answer(req.Path, req.BodyReader!.ReadAsync) })));

        runner.Test("h3: uploads a streamed-response handler never reads give their connection credit back", () =>
            Http3Tests.UnreadUploadsGiveCreditBack((conn, answer) => new Nghttp3Connection(conn).RunStreamedResponseAsync(
                async (req, writer) => writer.WriteHeaders(new Nghttp3Response { Status = await answer(req.Path, req.BodyReader!.ReadAsync) }))));

        runner.Test("h3: a streamed response whose handler awaits between chunks still arrives", () =>
        {
            // Every other streamed test writes its chunks in a tight loop, so the handler never
            // leaves the pass that dispatched it and DrainStreamed resumes it inline. A REAL
            // handler awaits something first - a file read, a query, an upstream - and comes back
            // outside that pass. There the flush used to park on a pass waiter that only inbound
            // packets release, while the peer sat waiting for the response that would have
            // provoked them: first chunk stalled, second hung outright.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunStreamedResponseAsync(
                    static async (_, writer) =>
                    {
                        writer.WriteHeaders(new Nghttp3Response { Status = 200 });

                        for (int i = 0; i < 4; i++)
                        {
                            // The point of the test. Task.Yield is the cheapest way to leave the
                            // dispatch pass; a file read or a database call lands in the same place.
                            await Task.Yield();

                            "chunk"u8.CopyTo(writer.GetSpan(5));
                            writer.Advance(5);
                            await writer.FlushAsync();
                        }

                        await writer.CompleteAsync();
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/streamed", timeoutMs: 10_000);
            Assert.Equal(200, status);
            Assert.Equal("chunkchunkchunkchunk", body);
        });

        runner.Test("h3: a streamed response past the send-retention high-water completes", () =>
        {
            // 20 MiB in 64 KiB flushes, from the dispatch pass: past the 16 MiB high-water the writer
            // has to wait for acks, and its flush spun on the reactor thread that reads them instead.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            const int Chunks = 320;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunStreamedResponseAsync(
                    static async (_, writer) =>
                    {
                        writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                        for (int i = 0; i < Chunks; i++)
                        {
                            writer.GetSpan(64 * 1024)[..(64 * 1024)].Fill((byte)'x');
                            writer.Advance(64 * 1024);
                            await writer.FlushAsync();
                        }
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/big", timeoutMs: 30_000);
            Assert.True(status == 200 && body.Length == Chunks * 64 * 1024,
                $"got status {status} and {body.Length} of {Chunks * 64 * 1024} bytes: the response stalled at the high-water");
        });

        runner.Test("h3: buffered-async handler (whole body in req.Body, handler may await)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static async req =>
                    {
                        // Dispatch fired at end-of-stream: the body is complete before we run.
                        await ValueTask.CompletedTask;   // where a db call would slot in
                        return Nghttp3Response.Text(
                            $"buffered got {req.Body.Length} first {req.Body.Span[0]} last {req.Body.Span[^1]}");
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            var body = new byte[200_000];
            new Random(21).NextBytes(body);

            (int status, string text) = client.Request("POST", "/upload", body, timeoutMs: 10_000);
            Assert.Equal(200, status);
            Assert.Equal($"buffered got 200000 first {body[0]} last {body[^1]}", text);
        });
        runner.Test("h3: QPACK dynamic table enabled (fat cookie decodes via insertions)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            var options = new Nghttp3Options
            {
                QpackDynamicTableCapacity = 4096,
                QpackBlockedStreams = 100,
            };

            // Handler echoes the cookie's length - proving the header survived the dynamic-table
            // encode/decode round trip (the client's nghttp3 encoder inserts eligible headers the
            // moment our SETTINGS advertise capacity).
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Nghttp3Connection(conn, options).RunBufferedAsync(
                    static req =>
                    {
                        // Byte-level cookie lookup - no strings, and it sees cookie field lines
                        // however h3 split them.
                        return req.TryGetCookie("session"u8, out ReadOnlyMemory<byte> session)
                            ? Nghttp3Response.Text($"cookie {session.Length}")
                            : Nghttp3Response.Text("no cookie", status: 400);
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // Two pairs in one field line: the parser must find "session" and stop at the ';'.
            string cookie = "session=" + new string('s', 400) + "; tracking=abc";
            (int status, string text) = client.Request("GET", "/", null,
                [("cookie", cookie)], timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("cookie 400", text);
        });

        runner.Test("h3: cookies split across multiple field lines (RFC 9114 4.2.1)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            // Echo every cookie found, in order - proves the enumerator walks BOTH field lines
            // (a Headers.TryGet("cookie") would only ever see the first).
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static req =>
                    {
                        var pairs = new List<string>();
                        foreach ((ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) in req.Cookies)
                        {
                            pairs.Add($"{Encoding.ASCII.GetString(name.Span)}={Encoding.ASCII.GetString(value.Span)}");
                        }
                        return Nghttp3Response.Text(string.Join('|', pairs));
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // Two separate cookie field lines, the second carrying two pairs - exactly the shape
            // h3 permits and h1 never produces.
            (int status, string text) = client.Request("GET", "/", null,
                [("cookie", "a=1"), ("cookie", "b=2; c=3")], timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("a=1|b=2|c=3", text);
        });
        runner.Test("h3: graceful shutdown (GOAWAY) still answers the in-flight request", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            // The handler calls Shutdown() while ITS OWN request is in flight: the GOAWAY goes
            // out, new streams are refused, and this response must still reach the client.
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) =>
                {
                    Nghttp3Connection h3 = new(conn);
                    return h3.RunBufferedAsync(req =>
                    {
                        h3.Shutdown();   // drain begins; this request completes normally
                        return Nghttp3Response.Text("bye after goaway");
                    });
                });

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string text) = client.Get("/last", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("bye after goaway", text);
        });

        RegisterLateAnswer(runner);
    }

    private static void RegisterLateAnswer(Runner runner)
    {
        runner.Test("h3: a late buffered answer to a cancelled request leaves the connection serving", () =>
            LateAnswerThenGet((conn, answer) => new Nghttp3Connection(conn).RunBufferedAsync(
                async req => Nghttp3Response.Text(await answer(req.Path, req.StreamId)))));

        runner.Test("h3: a late streaming answer to a cancelled request leaves the connection serving", () =>
            LateAnswerThenGet((conn, answer) => new Nghttp3Connection(conn).RunStreamingAsync(
                async req => Nghttp3Response.Text(await answer(req.Path, req.StreamId)))));

        runner.Test("control: a late answer to a cancelled request leaves an ioxide.http3 connection serving", () =>
            LateAnswerThenGet((conn, answer) => new Http3Connection(conn).RunAsync(
                async req => Http3Response.Text(await answer(req.Path, req.StreamId)))));
    }

    // "/slow" is cancelled by the client and answered only once its stream has closed on the server.
    private static void LateAnswerThenGet(Func<QuicConnection, Func<ReadOnlyMemory<byte>, long, ValueTask<string>>, Task> serve)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);
        var answeredLate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(_ => new ClosedStreamProbe(engine)),
            quicHandle: (reactor, conn) => serve(conn, async (path, streamId) =>
            {
                if (!path.Span.SequenceEqual("/slow"u8))
                {
                    return "ok";
                }

                HashSet<long> closed = ((ClosedStreamProbe)conn).Closed;
                var timer = new RingTimer(reactor);
                for (int i = 0; i < 1_000 && !closed.Contains(streamId); i++)
                {
                    await timer.DelayAsync(10);
                }
                answeredLate.TrySetResult(closed.Contains(streamId));
                return "late";
            }));

        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

        client.RequestThenCancel("/slow", readMs: 200);

        // The stream closes only once the client acks the server's RESET_STREAM, so keep the connection turning.
        long until = Environment.TickCount64 + 15_000;
        while (!answeredLate.Task.IsCompleted && Environment.TickCount64 < until)
        {
            client.Pump(50);
        }
        Assert.True(answeredLate.Task.IsCompleted, "the /slow handler never answered");
        Assert.True(answeredLate.Task.Result, "the cancelled stream never closed on the server, so its answer was not late and nothing was tested");

        (int status, string body) = client.Get("/ok", timeoutMs: 5000);
        Assert.True(status == 200 && body == "ok",
            $"the next request on the connection got {status} [{body}]" + (client.PeerClosed ? ": the server closed the connection" : ""));
    }

    // Filled and read on the reactor thread only.
    private sealed class ClosedStreamProbe(QuicEngine engine) : QuicEngineConnection(engine)
    {
        public readonly HashSet<long> Closed = [];

        protected override void OnStreamClosed(long streamId, ulong appErrorCode) => Closed.Add(streamId);
    }
}
