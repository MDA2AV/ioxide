using System.Text;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// RFC 9112 6.1: a recipient of an HTTP/1.0 message with a Transfer-Encoding "MUST treat the message as if the framing
/// is faulty, even if a Content-Length is present, and close the connection after processing the message".
/// </summary>
internal static class HttpClientHttp10Tests
{
    private static int _connections;

    public static void Register(Runner runner)
    {
        (string Path, string What)[] refused =
        [
            ("/chunked",     "an HTTP/1.0 response with Transfer-Encoding"),
            ("/notmodified", "an HTTP/1.0 304 with Transfer-Encoding, though it has no body to frame"),
        ];

        foreach ((string path, string what) in refused)
        {
            runner.Test($"httpclient h1: refuses {what}", () =>
            {
                int origin = TestServer.Start(OriginHandler);
                int proxy = HttpClientTests.StartProxy(origin, poolSize: 1);

                (_, string body) = Client.Get(proxy, path);
                Assert.True(body.StartsWith("599|") && body.Contains("HTTP/1.0"),
                    $"{what} should have been refused, got: {body}");
            });
        }

        runner.Test("httpclient h1: control: an HTTP/1.0 response with Content-Length is read", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = HttpClientTests.StartProxy(origin, poolSize: 1);

            (_, string body) = Client.Get(proxy, "/length");
            Assert.Equal("200|hello", body);
        });

        runner.Test("httpclient h1: an HTTP/1.0 response with Transfer-Encoding closes its connection, though it asked for keep-alive", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            // Its handler skips TestServer's request-less probe, whose stray request could close the connection mid-test.
            int proxy = HttpClientDnsTests.StartProxy(new HttpClientOptions { Host = "127.0.0.1", Port = (ushort)origin, PoolSize = 1 });

            // Control: keep-alive holds an HTTP/1.0 connection, so a reuse would show.
            (_, string first) = Client.Get(proxy, "/conn");
            Assert.True(first.StartsWith("200|connection "), $"expected a numbered connection, got: {first}");
            Assert.Equal(first, Client.Get(proxy, "/conn").Body);

            (_, string body) = Client.Get(proxy, "/keepalive");
            Assert.True(body.StartsWith("599|"), $"its framing is faulty, and it was read as chunked: {body}");

            (_, string next) = Client.Get(proxy, "/conn");
            Assert.True(next.StartsWith("200|connection ") && next != first, $"its connection was reused: {next}");
        });
    }

    private static string KeptAlive(string body)
        => $"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: {body.Length}\r\n\r\n{body}";

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

                connection.Write(Encoding.ASCII.GetBytes(path switch
                {
                    "/chunked" => "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                    "/notmodified" => "HTTP/1.0 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
                    "/keepalive" => "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "5\r\nhello\r\n0\r\n\r\n",
                    "/conn" => KeptAlive($"connection {number}"),
                    _ => "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                }));

                await connection.FlushAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }
            }
        }
        finally
        {
            connection.DecRef();
        }
    }
}
