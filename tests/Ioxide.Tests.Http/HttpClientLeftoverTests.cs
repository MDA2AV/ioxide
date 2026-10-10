using System.Text;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// Bytes an origin sends past the end of a response. The client never pipelines, so nothing after a
/// complete response can belong to a later request; left in the receive buffer, those bytes were
/// parsed as the start of the next response on that pooled connection.
/// </summary>
internal static class HttpClientLeftoverTests
{
    private static int _connections;

    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: a stray response after a complete one is not handed to the next request", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (_, string first) = Client.Get(proxy, "/stray");
            Assert.Equal("200|hi", first);

            (_, string next) = Client.Get(proxy, "/next");
            Assert.Equal("200|next", next);
        });

        runner.Test("httpclient h1: bytes past a response's Content-Length do not fail the next request", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (_, string first) = Client.Get(proxy, "/overlong");
            Assert.Equal("200|hi", first);

            (_, string next) = Client.Get(proxy, "/next");
            Assert.Equal("200|next", next);
        });

        runner.Test("httpclient h1: control - a response that ends where its framing says keeps its connection", () =>
        {
            // A check that dropped every connection would pass the two above by reconnecting.
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (_, string first) = Client.Get(proxy, "/conn");
            (_, string second) = Client.Get(proxy, "/conn");
            Assert.True(first.StartsWith("200|connection "), $"expected a numbered connection, got: {first}");
            Assert.Equal(first, second);
        });
    }

    // One pooled connection, so the second request can only go to the one the first left behind. The
    // handler skips the request-less probe TestServer opens to see the proxy listening, which would
    // otherwise put a request nobody sent on that connection, between the two.
    private static int StartProxy(int originPort)
        => TestServer.Start(TlsClientTests.ProxyHandler, onStart: reactor => HttpClientPool.Start(reactor,
            new HttpClientOptions { Host = "127.0.0.1", Port = (ushort)originPort, PoolSize = 1 }));

    private static string Fixed(string body) => $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}";

    private static async Task OriginHandler(Reactor reactor, TcpConnection connection)
    {
        int number = 0;
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                string path = Wire.ReadPath(connection, snapshot);
                if (path == "/conn" && number == 0)
                {
                    number = Interlocked.Increment(ref _connections);
                }

                // One write each, so the extra bytes arrive in the same segment as the response and
                // sit in the client's buffer behind it.
                connection.Write(Encoding.ASCII.GetBytes(path switch
                {
                    "/stray" => Fixed("hi") + Fixed("STOLEN"),
                    "/overlong" => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiEXTRA",
                    "/conn" => Fixed($"connection {number}"),
                    "/next" => Fixed("next"),
                    _ => Fixed("ok"),
                }));
                await connection.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }
                connection.ResetRead();
            }
        }
        finally
        {
            connection.DecRef();
        }
    }
}
