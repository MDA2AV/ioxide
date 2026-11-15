using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using static Ioxide.Tests.H3ErrorCodeTests;

namespace Ioxide.Tests;

/// <summary>
/// A whole-response HTTP/3 handler that answers null, on both stacks and from every buffered overload. A null answer
/// cannot be sent, so its request is answered as one whose handler threw: a bare 500 on its own stream, the fault
/// reported, and the connection's other requests served. Checked on a transport that records what the stack sends,
/// where two requests share one pass, and over QUIC.
/// </summary>
internal static class H3NullAnswerTests
{
    // A GET framed by hand: static :method GET, :scheme https and :path /, and a literal :authority, which nghttp3 requires.
    private static readonly byte[] Get = [0x01, 0x10, 0x00, 0x00, 0xD1, 0xD7, 0xC1, 0x50, 0x09, .. "localhost"u8];

    private enum Shape { Synchronous, Completed, Awaited, ReaderCompleted, ReaderAwaited }

    public static void Register(Runner runner)
    {
        foreach (Shape shape in Enum.GetValues<Shape>())
        {
            Shape s = shape;

            runner.Test($"h3 null answer (nghttp3, {Name(s)}): the request is answered 500, the hook hears the fault, and the next request in the pass is served", () =>
            {
                var faults = new List<string>();
                var options = new Nghttp3Options { OnHandlerFault = (request, fault) => faults.Add($"stream {request.StreamId}: {fault.GetType().Name}") };
                AssertAnsweredInPass((quic, gate) => ServeNghttp3(new Nghttp3Connection(quic, options), s, gate));
                Assert.Equal("stream 0: NullReferenceException", string.Join(", ", faults));
            });

            runner.Test($"h3 null answer (ioxide.http3, {Name(s)}): the request is answered 500, stderr hears the fault, and the next request in the pass is served", () =>
            {
                var stderr = new StringWriter();
                TextWriter original = Console.Error;
                Console.SetError(stderr);
                try
                {
                    AssertAnsweredInPass((quic, gate) => ServeHttp3(new Http3Connection(quic), s, gate));
                }
                finally
                {
                    Console.SetError(original);
                }

                int reported = stderr.ToString().Split('\n').Count(line => line.StartsWith("[ioxide.http3] request handler faulted"));
                Assert.True(reported == 1, $"stderr had: [{stderr}]");
            });
        }

        foreach (string stack in new[] { "nghttp3", "ioxide.http3" })
        {
            foreach (Shape shape in new[] { Shape.Synchronous, Shape.Awaited })
            {
                string at = stack;
                Shape s = shape;
                runner.Test($"h3 null answer ({at}, {Name(s)}, over QUIC): the request is answered 500, and the connection serves on", () =>
                {
                    using H3TestClient client = Connect(at, s);

                    (int status, string body) = client.Get("/null", timeoutMs: 5000);
                    Assert.True(status == 500 && body == "", $"the request whose handler answered null got {Describe(status, body)}, not a bare 500");

                    (status, body) = client.Get("/ok", timeoutMs: 5000);
                    Assert.True(status == 200 && body == "ok",
                        $"the next request on the connection got {Describe(status, body)}" + (client.PeerClosed ? ": the server closed the connection" : ""));
                });
            }
        }
    }

    private static string Name(Shape shape) => shape switch
    {
        Shape.Synchronous => "synchronous",
        Shape.Completed => "completed task",
        Shape.Awaited => "awaited",
        Shape.ReaderCompleted => "body reader, completed task",
        _ => "body reader, awaited",
    };

    // Stream 0 answers null, once the gate opens when its shape awaits; stream 4 answers "ok" at once. Both arrive in one pass.
    private static void AssertAnsweredInPass(Func<RecordingQuic, Task, Task> serve)
    {
        var quic = new RecordingQuic();
        Assert.True(quic.EnqueueStreamData(0, Get, fin: true) && quic.EnqueueStreamData(4, Get, fin: true), "the recv ring refused a request");

        var gate = new TaskCompletionSource();
        Task run = serve(quic, gate.Task);
        Assert.True(!run.IsCompleted, $"the run loop ended on a null answer: {Why(run)}");

        gate.SetResult();
        quic.MarkClosed();
        Assert.True(Task.WaitAny([run], 5000) == 0 && run.IsCompletedSuccessfully, $"the run loop did not end cleanly once the transport closed: {Why(run)}");

        Assert.Equal("500 []", Answer(quic, 0));
        Assert.Equal("200 [ok]", Answer(quic, 4));
        Assert.True(quic.ClosedWith is null, $"the connection was closed with 0x{quic.ClosedWith:x}");
    }

    private static Task ServeNghttp3(Nghttp3Connection connection, Shape shape, Task gate)
    {
        static Nghttp3Response? Respond(Nghttp3Request request) => request.StreamId == 0 ? null : Nghttp3Response.Text("ok");

        async ValueTask<Nghttp3Response> Later(Nghttp3Request request)
        {
            if (request.StreamId == 0)
            {
                await gate;
            }
            return Respond(request)!;
        }

        return shape switch
        {
            Shape.Synchronous => connection.RunAsync(request => Respond(request)!),
            Shape.Completed => connection.RunAsync(request => new ValueTask<Nghttp3Response>(Respond(request)!)),
            Shape.Awaited => connection.RunAsync(Later),
            Shape.ReaderCompleted => connection.RunAsync((Nghttp3Request request, Nghttp3BodyReader _) => new ValueTask<Nghttp3Response>(Respond(request)!)),
            _ => connection.RunAsync((Nghttp3Request request, Nghttp3BodyReader _) => Later(request)),
        };
    }

    private static Task ServeHttp3(Http3Connection connection, Shape shape, Task gate)
    {
        static Http3Response? Respond(Http3Request request) => request.StreamId == 0 ? null : Http3Response.Text("ok");

        async ValueTask<Http3Response> Later(Http3Request request)
        {
            if (request.StreamId == 0)
            {
                await gate;
            }
            return Respond(request)!;
        }

        return shape switch
        {
            Shape.Synchronous => connection.RunAsync(request => Respond(request)!),
            Shape.Completed => connection.RunAsync(request => new ValueTask<Http3Response>(Respond(request)!)),
            Shape.Awaited => connection.RunAsync(Later),
            Shape.ReaderCompleted => connection.RunAsync((Http3Request request, Http3BodyReader _) => new ValueTask<Http3Response>(Respond(request)!)),
            _ => connection.RunAsync((Http3Request request, Http3BodyReader _) => Later(request)),
        };
    }

    // "/null" answers null, after a later reactor pass when the shape awaits; anything else answers "ok".
    private static H3TestClient Connect(string stack, Shape shape)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => (stack, shape) switch
            {
                ("nghttp3", Shape.Synchronous) => new Nghttp3Connection(conn).RunAsync(request => IsNull(request.Path) ? null! : Nghttp3Response.Text("ok")),
                ("nghttp3", _) => new Nghttp3Connection(conn).RunAsync(async request =>
                {
                    await TestServer.LaterPass();
                    return IsNull(request.Path) ? null! : Nghttp3Response.Text("ok");
                }),
                (_, Shape.Synchronous) => new Http3Connection(conn).RunAsync(request => IsNull(request.Path) ? null! : Http3Response.Text("ok")),
                _ => new Http3Connection(conn).RunAsync(async request =>
                {
                    await TestServer.LaterPass();
                    return IsNull(request.Path) ? null! : Http3Response.Text("ok");
                }),
            });

        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;

        static bool IsNull(ReadOnlyMemory<byte> path) => path.Span.SequenceEqual("/null"u8);
    }

    // "status [body]" from what the stack sent on one stream, read off its HEADERS and DATA frames; "nothing" when it sent nothing.
    private static string Answer(RecordingQuic quic, long streamId)
    {
        List<(long StreamId, byte[] Bytes, bool Fin)> sent = [.. quic.Sent.Where(s => s.StreamId == streamId)];
        if (sent.Count == 0)
        {
            return "nothing";
        }

        byte[] stream = [.. sent.SelectMany(s => s.Bytes)];
        byte[]? fields = null;
        var body = new List<byte>();
        for (int at = 0; at < stream.Length;)
        {
            long type = ReadVarint(stream, ref at);
            int length = (int)ReadVarint(stream, ref at);
            if (type == 0x01)
            {
                fields ??= stream[at..(at + length)];
            }
            else if (type == 0x00)
            {
                body.AddRange(stream[at..(at + length)]);
            }
            at += length;
        }

        // :status follows the field section's two-byte prefix: static index 25 is 200, 71 is 500.
        string status = fields switch
        {
            null => "no HEADERS",
            [_, _, 0xD9, ..] => "200",
            [_, _, 0xFF, 0x08, ..] => "500",
            _ => Convert.ToHexString(fields),
        };
        return $"{status} [{System.Text.Encoding.ASCII.GetString(body.ToArray())}]" + (sent[^1].Fin ? "" : ", not ended");
    }

    private static long ReadVarint(byte[] bytes, ref int at)
    {
        int length = 1 << (bytes[at] >> 6);
        long value = bytes[at] & 0x3F;
        for (int i = 1; i < length; i++)
        {
            value = (value << 8) | bytes[at + i];
        }
        at += length;
        return value;
    }

    private static string Why(Task run) => run.Exception?.GetBaseException().Message ?? run.Status.ToString();

    private static string Describe(int status, string body) => status < 0 ? "no answer" : $"{status} [{body}]";
}
