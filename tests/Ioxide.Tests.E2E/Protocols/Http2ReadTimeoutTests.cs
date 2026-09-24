using System.Net;

using ioxide;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// The read timeout under HTTP/2, for both engines. The connection's read loop stays parked for the
/// next frame the whole time a handler works, so the loop's read says nothing about waiting on the
/// peer: each engine suspends the clock while it owes a response and resumes it once it owes none.
/// A slow request must get its answer, and a connection left with nothing owed must still be
/// closed once its peer has been silent past the timeout.
/// </summary>
internal static class Http2ReadTimeoutTests
{
    private const int ReadTimeoutMs = 500;

    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string engine = ng ? "nghttp2" : "ioxide.http2";

            runner.Test($"h2 read timeout ({engine}): a request answered after longer than the read timeout still gets its response", () =>
            {
                (int port, _) = StartServer(ng, answerAfterMs: 4 * ReadTimeoutMs);

                using HttpClient client = H2Client();
                using HttpResponseMessage response = client.GetAsync($"http://127.0.0.1:{port}/").Result;
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal("slow-but-here", response.Content.ReadAsStringAsync().Result);
            });

            runner.Test($"h2 read timeout ({engine}): a connection with nothing owed is closed at the read timeout", () =>
            {
                (int port, Task ended) = StartServer(ng, answerAfterMs: 0);

                // One request, answered, and then the client keeps the connection open and says
                // nothing - SocketsHttpHandler sends no PINGs unless asked. Nothing is owed any more,
                // so the clock is back on and the server has to end the connection itself.
                using HttpClient client = H2Client();
                using HttpResponseMessage response = client.GetAsync($"http://127.0.0.1:{port}/").Result;
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);

                Assert.True(ended.Wait(4_000),
                    "the connection is still open well past the read timeout - the clock never resumed");
            });
        }
    }

    /// <summary>
    /// A server answering every request with <c>slow-but-here</c> after
    /// <paramref name="answerAfterMs"/>. The task completes when a connection that served a request
    /// ends - the listen probe serves none, so it cannot complete it early.
    /// </summary>
    private static (int Port, Task Ended) StartServer(bool nghttp2, int answerAfterMs)
    {
        var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (_, conn) =>
        {
            int served = 0;
            try
            {
                if (nghttp2)
                {
                    await new Nghttp2Connection(conn).RunBufferedAsync(async _ =>
                    {
                        served++;
                        await Answer(answerAfterMs);
                        return new Nghttp2Response { Status = 200, Body = "slow-but-here"u8.ToArray() };
                    });
                }
                else
                {
                    await new Http2Connection(conn).RunBufferedAsync(async _ =>
                    {
                        served++;
                        await Answer(answerAfterMs);
                        return new Http2Response { Status = 200, Body = "slow-but-here"u8.ToArray() };
                    });
                }
            }
            finally
            {
                if (served > 0)
                {
                    ended.TrySetResult();
                }
                conn.DecRef();
            }
        }, new ServerConfig
        {
            RecvBufferSize = 4096,
            RecvSlots = 256,
            Tcp = new TcpOptions
            {
                WriteSlabSize = 16 * 1024,
                PoolMax = 64,
                RecvQueueEntries = 64,
                ReadTimeoutMs = ReadTimeoutMs,
            },
        }).Port;

        return (port, ended.Task);
    }

    // Nothing crosses the wire while this runs - no data, no PING - which is the whole point.
    private static Task Answer(int afterMs) => afterMs > 0 ? Task.Delay(afterMs) : Task.CompletedTask;

    // Cleartext HTTP/2 with prior knowledge: no upgrade dance, exactly what an h2c peer sends.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(30),
    };
}
