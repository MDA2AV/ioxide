using System.Text;
using ioxide.http3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// ioxide.http3 keeps a request stream whose body arrived whole, with its request, arena and lists, for the next
/// stream: the next request must come back holding nothing of the one before, and a warm connection's requests
/// allocate none of those objects on the reactor.
/// </summary>
internal static class Http3RequestReuseTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h3 request (ioxide.http3): the next stream's request holds nothing of the one before", () =>
        {
            var seen = new List<(Http3Request Request, string Fields)>();
            int udpPort = Start(request =>
            {
                seen.Add((request, Describe(request)));   // on the reactor's thread
                return Http3Response.Text("ok");
            });

            using H3TestClient client = Connect(udpPort);
            Assert.Equal(200, client.Request("POST", "/first", "hello"u8.ToArray(), [("x-one", "1"), ("x-two", "2")], timeoutMs: 5000).Status);
            Assert.Equal(200, client.Get("/", timeoutMs: 5000).Status);

            Assert.Equal(2, seen.Count);
            Assert.Equal("POST /first [x-one=1 x-two=2] hello", seen[0].Fields);
            Assert.Equal("GET / [] -", seen[1].Fields);
            Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request), "the second stream reuses the first one's request");
        });

        runner.Test("h3 request (ioxide.http3): a warm connection's request allocates none of the request objects", () =>
        {
            const int warm = 16;
            const int measured = 32;
            Http3Response response = Http3Response.Text("ok");   // shared, so the handler allocates nothing
            long[] marks = new long[2];
            int served = 0;

            int udpPort = Start(_ =>
            {
                // On the reactor's thread: what it allocated between these two requests.
                int n = ++served;
                if (n == warm)
                {
                    marks[0] = GC.GetAllocatedBytesForCurrentThread();
                }
                else if (n == warm + measured)
                {
                    marks[1] = GC.GetAllocatedBytesForCurrentThread();
                }
                return response;
            });

            using H3TestClient client = Connect(udpPort);
            for (int i = 0; i < warm + measured; i++)
            {
                (int status, string body) = client.Request("GET", $"/{i}", null, [("x-n", $"{i}")], timeoutMs: 5000);
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }

            // Before reuse, every request allocated about 1.8 KB of these. What may remain is the QUIC send queue's
            // per-stream state, about 185 B, which the engine reuses as well once that change is in.
            long perRequest = (marks[1] - marks[0]) / measured;
            Assert.True(perRequest < 400, $"a request on a warm connection allocated {perRequest} B on the reactor");
        });
    }

    private static int Start(Func<Http3Request, Http3Response> handler)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => new Http3Connection(conn).RunAsync(handler));
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
