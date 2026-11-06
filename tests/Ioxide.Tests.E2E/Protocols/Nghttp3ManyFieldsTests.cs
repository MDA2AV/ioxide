using System.Text;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A message's fields are not capped by the shim: each reaches the peer, however many there are.
/// </summary>
internal static class Nghttp3ManyFieldsTests
{
    public static void Register(Runner runner)
    {
        // 64 and 65 fields with :status are either side of the first growth, and 201 past the second.
        foreach (int fields in new[] { 63, 64, 200 })
        {
            foreach (bool asStream in new[] { false, true })
            {
                int count = fields;
                bool streamed = asStream;
                runner.Test($"nghttp3: a {(streamed ? "streamed" : "buffered")} response with {count} headers of its own reaches the peer whole", () =>
                {
                    var response = new Nghttp3Response { Status = 200 };
                    for (int i = 0; i < count; i++)
                    {
                        response.Headers.Add(Encoding.ASCII.GetBytes($"x-{i}"), "v"u8.ToArray());
                    }

                    int udpPort = Start(connection => streamed
                        ? connection.RunAsync(async (_, writer) =>
                        {
                            writer.WriteHeaders(response);
                            await writer.FlushAsync();
                        })
                        : connection.RunAsync(_ => response));

                    using H3TestClient client = Connect(udpPort);
                    Assert.Equal(200, client.Get("/", timeoutMs: 5000).Status);
                    Assert.Equal(count, client.ResponseHeaders.Count(h => h.Name.StartsWith("x-", StringComparison.Ordinal)));
                });
            }
        }

        runner.Test("nghttp3: a request past 64 fields reaches its handler whole", () =>
        {
            int seen = -1;
            var ok = new Nghttp3Response { Status = 200 };
            int udpPort = Start(connection => connection.RunAsync(request =>
            {
                seen = request.Headers.AsSpan().Length;
                return ok;
            }));

            using H3TestClient client = Connect(udpPort);
            (string, string)[] many = [.. Enumerable.Range(0, 70).Select(i => ($"x-{i}", "v"))];
            Assert.Equal(200, client.Request("GET", "/", null, many, timeoutMs: 5000).Status);
            Assert.Equal(70, seen);
        });
    }

    private static int Start(Func<Nghttp3Connection, Task> run)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => run(new Nghttp3Connection(conn)));
        return udpPort;
    }

    private static H3TestClient Connect(int udpPort)
    {
        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;
    }
}
