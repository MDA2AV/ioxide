using System.Net;
using System.Text;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// A response's fields are not capped by the shim: each reaches the peer, however many a handler sets.
/// </summary>
internal static class Nghttp2ManyHeadersTests
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
                runner.Test($"nghttp2: a {(streamed ? "streamed" : "buffered")} response with {count} headers of its own reaches the peer whole", () =>
                {
                    var response = new Nghttp2Response { Status = 200 };
                    for (int i = 0; i < count; i++)
                    {
                        response.Headers.Add(Encoding.ASCII.GetBytes($"x-{i}"), "v"u8.ToArray());
                    }

                    int port = TestServer.Start(async (_, conn) =>
                    {
                        try
                        {
                            var connection = new Nghttp2Connection(conn);
                            await (streamed
                                ? connection.RunAsync(async (_, writer) =>
                                {
                                    writer.WriteHeaders(response);
                                    await writer.FlushAsync();
                                })
                                : connection.RunAsync(_ => response));
                        }
                        finally
                        {
                            conn.DecRef();
                        }
                    });

                    using var client = new HttpClient(new SocketsHttpHandler())
                    {
                        DefaultRequestVersion = HttpVersion.Version20,
                        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
                        Timeout = TimeSpan.FromSeconds(10),
                    };

                    for (int request = 0; request < 2; request++)   // the same connection's fields again, on what the first grew
                    {
                        using HttpResponseMessage answer = client.GetAsync($"http://127.0.0.1:{port}/").GetAwaiter().GetResult();
                        Assert.Equal(HttpStatusCode.OK, answer.StatusCode);
                        Assert.Equal(count, answer.Headers.Count(h => h.Key.StartsWith("x-", StringComparison.Ordinal)));
                    }
                });
            }
        }
    }
}
