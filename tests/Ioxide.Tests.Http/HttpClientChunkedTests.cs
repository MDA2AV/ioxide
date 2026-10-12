using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Chunk-size lines a broken or hostile origin can send. The size is the framing, so one that is
/// read as some other number hands the caller the wrong body and leaves the connection at the
/// wrong offset; each must fail its response instead, and the connection with it.
/// </summary>
internal static class HttpClientChunkedTests
{
    public static void Register(Runner runner)
    {
        (string Path, string What)[] refused =
        [
            ("/negative", "a chunk size of 80000000 or more, which an int reads as negative"),
            ("/suffix",   "a chunk size followed by characters that are not hex"),
            ("/prefix",   "a chunk size written with a 0x prefix"),
            ("/barelf",   "a chunk size line ended by a bare LF"),
            ("/overlong", "chunk data that runs past its chunk size"),
        ];

        foreach ((string path, string what) in refused)
        {
            runner.Test($"httpclient h1: refuses {what}", () =>
            {
                int origin = TestServer.Start(OriginHandler);
                int proxy = HttpClientTests.StartProxy(origin, poolSize: 1);

                (_, string body) = Client.Get(proxy, path);
                Assert.True(body.StartsWith("599|") && body.Contains("chunk"),
                    $"{what} should have been refused, got: {body}");

                // The refused response took its connection with it, so the next one is read whole.
                (_, string next) = Client.Get(proxy, "/fine");
                Assert.Equal("200|hello", next);
            });
        }

        runner.Test("httpclient h1: control - leading zeros, an extension, whitespace before it and a trailer are read", () =>
        {
            // The tightened parse must still take every valid spelling RFC 9112 allows.
            int origin = TestServer.Start(OriginHandler);
            int proxy = HttpClientTests.StartProxy(origin, poolSize: 1);

            (_, string body) = Client.Get(proxy, "/valid");
            Assert.Equal("200|hello world", body);
        });
    }

    private static async Task OriginHandler(Reactor reactor, TcpConnection connection)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                string chunks = Wire.ReadPath(connection, snapshot) switch
                {
                    "/negative" => "FFFFFFFF\r\nhello\r\n0\r\n\r\n",
                    "/suffix" => "5zz\r\nhello\r\n0\r\n\r\n",
                    "/prefix" => "0x5\r\nhello\r\n0\r\n\r\n",
                    "/barelf" => "5\nhello\r\n0\r\n\r\n",
                    "/overlong" => "3\r\nhello\r\n0\r\n\r\n",
                    "/valid" => "0000a;name=value\r\nhello worl\r\n1 ;ext\r\nd\r\n0\r\nx-trailer: yes\r\n\r\n",
                    _ => "5\r\nhello\r\n0\r\n\r\n",
                };

                connection.Write(Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks));
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
