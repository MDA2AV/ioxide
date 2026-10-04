using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using ioxide;
using ioxide.http2;
using ioxide.nghttp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A streamed response whose peer has gone (#269). An event source writes until a write fails, so
/// unless the writer can say "nobody is reading" it produces for a closed tab forever - or, once
/// the stream window is spent, parks forever on credit that will never come. A TCP pipe writer
/// says it with <see cref="FlushResult.IsCompleted"/>; the HTTP/2 and HTTP/3 writers now say it the
/// same way.
/// </summary>
internal static class StreamedPeerGoneTests
{
    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp2" : "ioxide.http2";

            runner.Test($"h2 peer gone ({stack}): a reset stream is reported by FlushAsync, and the connection serves on", () =>
            {
                var learned = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
                int connections = 0;
                int port = StartH2(ng, learned, () => Interlocked.Increment(ref connections));

                using HttpClient client = H2Client();
                HttpResponseMessage endless = client.SendAsync(
                    new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/endless")
                    {
                        Version = HttpVersion.Version20,   // a hand-built request ignores the client's default
                        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                    },
                    HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();

                // Unread for long enough to spend the 64 KiB stream window, so a writer that waits on
                // credit is parked by now; then dropped, which is RST_STREAM CANCEL.
                Thread.Sleep(700);
                endless.Dispose();

                Assert.True(learned.Task.Wait(5_000),
                    "the handler never learned its stream was reset: FlushAsync went on accepting chunks, "
                    + "or stayed parked on credit the peer will never send");
                Assert.Equal("200: ok", Fetch(client, port, "/ok"));
                Assert.True(Volatile.Read(ref connections) == 1,
                    $"{connections} connections served requests: the reset took the whole connection down "
                    + "with it, not just its own stream");
            });
        }
    }

    // "/endless" writes 1 KiB every 5 ms until a flush reports the peer gone; "/ok" answers at once.
    // Bounded, so a server that never learns cannot outlive the test.
    private static int StartH2(bool native, TaskCompletionSource<int> learned, Action onFirstRequest)
        => TestServer.Start(async (reactor, conn) =>
        {
            var timer = new RingTimer(reactor);
            bool counted = false;

            async ValueTask Serve(string path, Func<ReadOnlyMemory<byte>, ValueTask<FlushResult>> writeAndFlush, Action<int> headers)
            {
                if (!counted)
                {
                    counted = true;
                    onFirstRequest();
                }

                headers(200);
                if (path != "/endless")
                {
                    await writeAndFlush("ok"u8.ToArray());
                    return;
                }

                byte[] chunk = new byte[1024];
                for (int i = 0; i < 6_000; i++)
                {
                    if ((await writeAndFlush(chunk)).IsCompleted)
                    {
                        learned.TrySetResult(i);
                        return;
                    }
                    await timer.DelayAsync(5);
                }
            }

            try
            {
                if (native)
                {
                    await new Nghttp2Connection(conn).RunAsync((request, writer) => Serve(
                        System.Text.Encoding.ASCII.GetString(request.Path.Span),
                        body =>
                        {
                            writer.Write(body.Span);
                            return writer.FlushAsync();
                        },
                        status => writer.WriteHeaders(new Nghttp2Response { Status = status })));
                }
                else
                {
                    await new Http2Connection(conn).RunAsync((request, writer) => Serve(
                        System.Text.Encoding.ASCII.GetString(request.Path.Span),
                        body =>
                        {
                            writer.Write(body.Span);
                            return writer.FlushAsync();
                        },
                        status => writer.WriteHeaders(new Http2Response { Status = status })));
                }
            }
            finally
            {
                conn.DecRef();
            }
        });

    // Cleartext HTTP/2 with prior knowledge, one connection for every request of a test.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(10),
    };

    private static string Fetch(HttpClient client, int port, string path)
    {
        try
        {
            using HttpResponseMessage response = client.GetAsync($"http://127.0.0.1:{port}{path}").GetAwaiter().GetResult();
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return $"{(int)response.StatusCode}: {body}";
        }
        catch (HttpRequestException e)
        {
            return $"reset: {e.GetBaseException().Message}";
        }
    }
}
