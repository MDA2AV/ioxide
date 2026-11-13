using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// What an origin can send in a response besides the body's payload: 1xx heads before it, chunk extensions in it
/// and a trailer section after it. MaxResponseBytes is the bound on what a response can cost, so each has to count
/// against it, as the body does, instead of running as long as the origin likes.
/// </summary>
internal static class HttpClientResponseLimitTests
{
    private const int MaxResponseBytes = 8 * 1024 * 1024;   // the default, and what the proxy's client has

    public static void Register(Runner runner)
    {
        (string Path, string What)[] refused =
        [
            ("/trailers",   "a trailer section"),
            ("/extensions", "chunk extensions"),
            ("/interim",    "1xx interim heads"),
        ];

        foreach ((string path, string what) in refused)
        {
            runner.Test($"httpclient h1: refuses {what} past MaxResponseBytes", () =>
            {
                int proxy = Start();
                (_, string body) = Client.Get(proxy, path, timeoutMs: 60_000);
                Assert.True(body.StartsWith("599|") && body.Contains("MaxResponseBytes"),
                    $"{2 * MaxResponseBytes} bytes of {what} went through a {MaxResponseBytes}-byte limit: {body[..Math.Min(80, body.Length)]}");
            });
        }

        runner.Test("httpclient h1: control: a body past MaxResponseBytes is refused", () =>
        {
            int proxy = Start();
            (_, string body) = Client.Get(proxy, "/body", timeoutMs: 60_000);
            Assert.True(body.StartsWith("599|") && body.Contains("MaxResponseBytes"), body);
        });

        runner.Test("httpclient h1: control: a body ended by the close is read to it, and refused past MaxResponseBytes", () =>
        {
            int proxy = Start();
            (_, string small) = Client.Get(proxy, "/close-small");
            Assert.Equal("200|hello", small);

            (_, string big) = Client.Get(proxy, "/close", timeoutMs: 60_000);
            Assert.True(big.StartsWith("599|") && big.Contains("MaxResponseBytes"), big[..Math.Min(80, big.Length)]);
        });
    }

    private static int Start() => HttpClientTests.StartProxy(TestServer.Start(OriginHandler), poolSize: 1);

    private static async Task OriginHandler(Reactor reactor, TcpConnection connection)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                switch (Wire.ReadPath(connection, snapshot))
                {
                    case "/trailers":
                        connection.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n"));
                        await WriteTwiceTheLimit(connection, "x-trailer: " + new string('y', 1000) + "\r\n");
                        connection.Write("\r\n"u8);
                        break;

                    case "/extensions":
                        connection.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"));
                        await WriteTwiceTheLimit(connection, "1;x-ext=" + new string('y', 1000) + "\r\nx\r\n");
                        connection.Write("0\r\n\r\n"u8);
                        break;

                    case "/interim":
                        await WriteTwiceTheLimit(connection, "HTTP/1.1 103 Early Hints\r\nlink: </" + new string('y', 1000) + ">; rel=preload\r\n\r\n");
                        connection.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
                        break;

                    case "/body":
                        connection.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"));
                        await WriteTwiceTheLimit(connection, $"3e8\r\n{new string('y', 1000)}\r\n");
                        connection.Write("0\r\n\r\n"u8);
                        break;

                    // No framing header: the body ends where the origin closes.
                    case "/close-small":
                        connection.Write("HTTP/1.1 200 OK\r\n\r\nhello"u8);
                        await connection.FlushAsync();
                        return;

                    case "/close":
                        connection.Write("HTTP/1.1 200 OK\r\n\r\n"u8);
                        await WriteTwiceTheLimit(connection, new string('y', 1000));
                        return;

                    default:
                        connection.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
                        break;
                }

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

    // The line repeated to twice the limit, flushed about a MiB at a time.
    private static async Task WriteTwiceTheLimit(TcpConnection connection, string line)
    {
        byte[] mib = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(line, 1024 * 1024 / line.Length)));
        for (int written = 0; written < 2 * MaxResponseBytes; written += mib.Length)
        {
            connection.Write(mib);
            await connection.FlushAsync();
        }
    }
}
