using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// HTTP/3 request chaos: awkward requests carried end to end over a real ngtcp2 + nghttp3 stack -
/// an enormous path, a request fat with header fields, a body far past the stream window, and an
/// empty body. Each crosses the wire QPACK-encoded and encrypted; the assertion is that the server
/// frames it correctly and answers.
/// </summary>
internal static class H3ChaosTests
{
    private static int Start(QuicEngine engine, Func<Reactor, QuicConnection, Task> handle)
        => TestServer.StartDatagram(onDatagram: null, quicFactory: engine.CreateFactory(), quicHandle: handle).UdpPort;

    public static void Register(Runner runner)
    {
        runner.Test("h3: a very long request path is served", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
            int udpPort = Start(engine, static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static req => Nghttp3Response.Text($"len {req.Path.Length}")));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            string path = "/" + new string('a', 4000);
            (int status, string body) = client.Get(path, timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal($"len {path.Length}", body);
        });

        runner.Test("h3: a request fat with header fields is served", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
            int udpPort = Start(engine, static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static _ => Nghttp3Response.Text("ok")));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // 40 extra field lines (lowercase names, as h3 requires) on one request.
            var headers = new (string, string)[40];
            for (int i = 0; i < headers.Length; i++)
            {
                headers[i] = ($"x-chaos-{i}", new string('v', 32));
            }

            (int status, string body) = client.Request("GET", "/", null, headers, timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("ok", body);
        });

        runner.Test("h3: a body far past the stream window round-trips", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            // Streaming handler: drains the body, crediting the window mid-flight, so a body larger
            // than the 256 KB stream window completes rather than deadlocking.
            int udpPort = Start(engine, static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static async (_, body) =>
                {
                    long total = 0;
                    while (true)
                    {
                        ReadOnlyMemory<byte> chunk = await body.ReadAsync();
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

            var payload = new byte[512 * 1024];
            new Random(3).NextBytes(payload);

            (int status, string body) = client.Request("POST", "/upload", payload, timeoutMs: 15000);
            Assert.Equal(200, status);
            Assert.Equal($"got {payload.Length}", body);
        });

        runner.Test("h3: an empty-body request is served", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
            int udpPort = Start(engine, static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static req => Nghttp3Response.Text($"got {req.Body.Length}")));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Request("POST", "/", null, timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("got 0", body);
        });
    }
}
