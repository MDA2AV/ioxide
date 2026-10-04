using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using ioxide;
using ioxide.http2;
using ioxide.http3;
using ioxide.nghttp2;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A streamed response whose peer has gone (#269). An event source writes until a write fails, so
/// unless the writer can say "nobody is reading" it produces for a closed tab forever - or, once
/// the stream window is spent, parks forever on credit that will never come. A TCP pipe writer
/// says it with <see cref="FlushResult.IsCompleted"/>; the HTTP/2 and HTTP/3 writers now say it the
/// same way, on every stack.
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
                var server = new EndlessServer();
                int port = StartH2(ng, server);

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

                Assert.True(server.Learned.Task.Wait(5_000), NeverLearned);
                Assert.Equal("200: ok", Fetch(client, port, "/ok"));
                Assert.True(Volatile.Read(ref server.Connections) == 1, WholeConnection(server));
            });
        }

        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp3" : "ioxide.http3";

            runner.Test($"h3 peer gone ({stack}): a cancelled stream is reported by FlushAsync, and the connection serves on", () =>
            {
                (string certPath, string keyPath) = TestCert.Ensure();
                using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);
                var server = new EndlessServer();
                int port = StartH3(ng, engine, server);

                using var client = new H3TestClient("127.0.0.1", port);
                client.Connect();
                Assert.True(client.CompleteHandshake(timeoutMs: 5_000), "handshake did not complete");

                int received = client.RequestThenCancel("/endless", readMs: 500);
                Assert.True(received > 0, "none of the endless response arrived before the cancel, so no stream was in flight to stop");

                // The server learns from the peer's frames, so the connection has to keep turning.
                long until = Environment.TickCount64 + 5_000;
                while (!server.Learned.Task.IsCompleted && Environment.TickCount64 < until)
                {
                    client.Pump(50);
                }

                Assert.True(server.Learned.Task.IsCompleted, NeverLearned);
                (int status, string body) = client.Get("/ok", timeoutMs: 5_000);
                Assert.True(status == 200 && body == "ok", $"the next request on the connection got {status} [{body}]");
                Assert.True(Volatile.Read(ref server.Connections) == 1, WholeConnection(server));
            });
        }
    }

    private const string NeverLearned =
        "the handler never learned its stream was abandoned: FlushAsync went on accepting chunks, or stayed "
        + "parked waiting for a peer that will never read them";

    private static string WholeConnection(EndlessServer server)
        => $"{server.Connections} connections served requests: the abandoned stream took the whole connection "
           + "down with it";

    /// <summary>
    /// "/endless" writes 1 KiB every 5 ms until a flush reports the peer gone; anything else answers
    /// "ok". Bounded, so a server that never learns cannot outlive the test.
    /// </summary>
    private sealed class EndlessServer
    {
        public readonly TaskCompletionSource<int> Learned = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Connections;

        /// <summary>One per connection: counts it once it serves a request.</summary>
        public Func<string, Func<ReadOnlyMemory<byte>, ValueTask<FlushResult>>, Action<int>, ValueTask> For(Reactor reactor)
        {
            var timer = new RingTimer(reactor);
            bool counted = false;

            return async (path, writeAndFlush, headers) =>
            {
                if (!counted)
                {
                    counted = true;
                    Interlocked.Increment(ref Connections);
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
                        Learned.TrySetResult(i);
                        return;
                    }
                    await timer.DelayAsync(5);
                }
            };
        }
    }

    private static int StartH2(bool native, EndlessServer server)
        => TestServer.Start(async (reactor, conn) =>
        {
            var serve = server.For(reactor);
            try
            {
                if (native)
                {
                    await new Nghttp2Connection(conn).RunAsync((request, writer) => serve(Path(request.Path),
                        body =>
                        {
                            writer.Write(body.Span);
                            return writer.FlushAsync();
                        },
                        status => writer.WriteHeaders(new Nghttp2Response { Status = status })));
                }
                else
                {
                    await new Http2Connection(conn).RunAsync((request, writer) => serve(Path(request.Path),
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

    private static int StartH3(bool native, QuicEngine engine, EndlessServer server)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (reactor, conn) =>
            {
                var serve = server.For(reactor);
                return native
                    ? new Nghttp3Connection(conn).RunStreamedResponseAsync((request, writer) => serve(Path(request.Path),
                        body =>
                        {
                            writer.Write(body.Span);
                            return writer.FlushAsync();
                        },
                        status => writer.WriteHeaders(new Nghttp3Response { Status = status })))
                    : new Http3Connection(conn).RunStreamedResponseAsync((request, writer) => serve(Path(request.Path),
                        body =>
                        {
                            writer.Write(body.Span);
                            return writer.FlushAsync();
                        },
                        status => writer.WriteHeaders(new Http3Response { Status = status })));
            });
        return udpPort;
    }

    private static string Path(ReadOnlyMemory<byte> path) => System.Text.Encoding.ASCII.GetString(path.Span);

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
