using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// ioxide.http3 keeps a request stream whose body arrived whole, with its request, arena and lists, for the next
/// stream: on every dispatch path the next request must come back holding nothing of the one before, and a warm
/// connection's requests allocate none of those objects on the reactor.
/// </summary>
internal static class Http3RequestReuseTests
{
    private enum Shape { Synchronous, Parked, Streamed }

    public static void Register(Runner runner)
    {
        foreach (Shape shape in new[] { Shape.Synchronous, Shape.Parked, Shape.Streamed })
        {
            Shape s = shape;
            runner.Test($"h3 request (ioxide.http3, {s.ToString().ToLowerInvariant()} handler): the next stream's request holds nothing of the one before", () =>
            {
                var seen = new List<(Http3Request Request, string Fields)>();
                int udpPort = Start(s, request => seen.Add((request, Describe(request))));   // on the reactor's thread

                using H3TestClient client = Connect(udpPort);
                Assert.Equal(200, client.Request("POST", "/first", "hello"u8.ToArray(),
                    [("x-one", "1"), ("x-two", "2"), ("content-length", "5")], timeoutMs: 5000).Status);
                Assert.Equal(200, client.Get("/", timeoutMs: 5000).Status);
                // A content-length the request before it already counted down must not read as a repeated one.
                Assert.Equal(200, client.Request("POST", "/again", "world"u8.ToArray(), [("content-length", "5")], timeoutMs: 5000).Status);

                Assert.Equal(3, seen.Count);
                Assert.Equal("POST /first [x-one=1 x-two=2 content-length=5] hello", seen[0].Fields);
                Assert.Equal("GET / [] -", seen[1].Fields);
                Assert.Equal("POST /again [content-length=5] world", seen[2].Fields);
                Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request) && ReferenceEquals(seen[1].Request, seen[2].Request),
                    "each stream reuses the request of the one before");
            });
        }

        runner.Test("h3 request (ioxide.http3): a warm connection's request allocates none of the request objects", () =>
        {
            const int warm = 4;
            const int measured = 12;
            long[] marks = new long[2];
            int[] threads = new int[2];
            int served = 0;

            int udpPort = Start(Shape.Synchronous, _ =>
            {
                // On the reactor's thread: what it allocated between these two requests.
                int n = ++served;
                int mark = n == warm ? 0 : n == warm + measured ? 1 : -1;
                if (mark >= 0)
                {
                    marks[mark] = GC.GetAllocatedBytesForCurrentThread();
                    threads[mark] = Environment.CurrentManagedThreadId;
                }
            });

            using H3TestClient client = Connect(udpPort);
            for (int i = 0; i < warm + measured; i++)
            {
                (int status, string body) = client.Request("GET", $"/{i}", null, [("x-n", $"{i}")], timeoutMs: 5000);
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }

            Assert.True(threads[0] == threads[1] && marks[1] >= marks[0], "both marks come from the reactor's thread");

            // Before reuse, every request allocated about 1.8 KB of these. What may remain is the QUIC send queue's
            // per-stream state, about 185 B, which the engine reuses as well once that change is in.
            long perRequest = (marks[1] - marks[0]) / measured;
            Assert.True(perRequest < 400, $"a request on a warm connection allocated {perRequest} B on the reactor");
        });
    }

    private static readonly Http3Response Ok = Http3Response.Text("ok");   // shared, so the handler allocates nothing

    // One connection's server, answering "ok" through the handler shape asked for: a synchronous handler, one that
    // parks on a ring timer before it answers, or one that streams its response.
    private static int Start(Shape shape, Action<Http3Request> observe)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (reactor, conn) =>
            {
                var connection = new Http3Connection(conn);
                switch (shape)
                {
                    case Shape.Synchronous:
                        return connection.RunAsync(request =>
                        {
                            observe(request);
                            return Ok;
                        });

                    case Shape.Parked:
                        var timer = new RingTimer(reactor);
                        return connection.RunAsync(async request =>
                        {
                            observe(request);
                            await timer.DelayAsync(1);
                            return Ok;
                        });

                    default:
                        return connection.RunAsync(async (request, writer) =>
                        {
                            observe(request);
                            writer.WriteHeaders(new Http3Response { Status = 200 });
                            "ok"u8.CopyTo(writer.GetSpan(2));
                            writer.Advance(2);
                            await writer.FlushAsync();
                        });
                }
            });
        return udpPort;
    }

    private static H3TestClient Connect(int udpPort)
    {
        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;
    }

    private static string Describe(Http3Request request)
    {
        var fields = new List<string>();
        foreach ((ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) in request.Headers)
        {
            fields.Add($"{Ascii(name)}={Ascii(value)}");
        }

        return $"{Ascii(request.Method)} {Ascii(request.Path)} [{string.Join(' ', fields)}] "
             + (request.Body.IsEmpty ? "-" : Ascii(request.Body));
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);
}
