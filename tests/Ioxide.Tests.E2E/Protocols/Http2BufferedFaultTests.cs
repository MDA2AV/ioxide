using System.Net;
using ioxide.http2;
using ioxide.nghttp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A whole-response HTTP/2 handler that throws, on both stacks. Throwing from its task or before it
/// has one - as every synchronous handler does - answers 500 on its own stream, and every other
/// stream on the connection carries on.
/// </summary>
internal static class Http2BufferedFaultTests
{
    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp2" : "ioxide.http2";

            runner.Test($"h2 fault ({stack}): a synchronous handler that throws answers 500, and the connection serves on", () =>
            {
                var server = new FaultServer();
                int port = Start(ng, server, synchronous: true);
                using HttpClient client = H2Client();

                Assert.Equal("500: ", Fetch(client, port, "/boom"));
                Assert.Equal("200: ok", Fetch(client, port, "/ok"));
                Assert.True(Volatile.Read(ref server.Connections) == 1, WholeConnection(server));
            });

            runner.Test($"h2 fault ({stack}): a request in flight beside a handler that throws before it has a task is answered", () =>
            {
                var server = new FaultServer();
                int port = Start(ng, server, synchronous: false);
                using HttpClient client = H2Client();

                Task<HttpResponseMessage> slow = client.GetAsync($"http://127.0.0.1:{port}/slow");
                Assert.True(server.SlowArrived.Task.Wait(5_000), "/slow never reached its handler");

                Assert.Equal("500: ", Fetch(client, port, "/boom"));
                Assert.Equal("200: slow", Describe(slow));
                Assert.True(Volatile.Read(ref server.Connections) == 1, WholeConnection(server));
            });
        }
    }

    private static string WholeConnection(FaultServer server)
        => $"{server.Connections} connections served requests: the handler that threw took its whole connection down";

    private sealed class FaultServer
    {
        public readonly TaskCompletionSource SlowArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Connections;   // the ones that served a request: the harness's listen probe serves none
        public bool BoomSeen;
    }

    // "/boom" throws before the handler returns, "/slow" parks until "/boom" has been dispatched,
    // anything else answers "ok". Synchronous serves through the synchronous overload; otherwise
    // through the asynchronous one, with a lambda that is not async and so throws before its task.
    private static int Start(bool native, FaultServer server, bool synchronous)
        => TestServer.Start(async (reactor, conn) =>
        {
            var timer = new RingTimer(reactor);
            bool counted = false;
            try
            {
                if (native)
                {
                    var connection = new Nghttp2Connection(conn);
                    await (synchronous
                        ? connection.RunAsync(request => Answer(request.Path) is { } body
                            ? new Nghttp2Response { Status = 200, Body = body }
                            : throw new InvalidOperationException("the handler failed"))
                        : connection.RunAsync(request => Answer(request.Path) is { } body
                            ? Park(timer, server, body, b => new Nghttp2Response { Status = 200, Body = b })
                            : throw new InvalidOperationException("the handler failed")));
                }
                else
                {
                    var connection = new Http2Connection(conn);
                    await (synchronous
                        ? connection.RunAsync(request => Answer(request.Path) is { } body
                            ? new Http2Response { Status = 200, Body = body }
                            : throw new InvalidOperationException("the handler failed"))
                        : connection.RunAsync(request => Answer(request.Path) is { } body
                            ? Park(timer, server, body, b => new Http2Response { Status = 200, Body = b })
                            : throw new InvalidOperationException("the handler failed")));
                }
            }
            finally
            {
                conn.DecRef();
            }

            // null for "/boom", noted first so a parked "/slow" knows it went through.
            byte[]? Answer(ReadOnlyMemory<byte> path)
            {
                if (!counted)
                {
                    counted = true;
                    Interlocked.Increment(ref server.Connections);
                }
                string at = System.Text.Encoding.ASCII.GetString(path.Span);
                if (at == "/boom")
                {
                    server.BoomSeen = true;
                    return null;
                }
                return at == "/slow" ? "slow"u8.ToArray() : "ok"u8.ToArray();
            }
        });

    private static async ValueTask<T> Park<T>(RingTimer timer, FaultServer server, byte[] body, Func<byte[], T> respond)
    {
        if (body.AsSpan().SequenceEqual("slow"u8))
        {
            server.SlowArrived.TrySetResult();
            for (int waited = 0; !server.BoomSeen && waited < 5_000; waited += 5)
            {
                await timer.DelayAsync(5);
            }
        }
        return respond(body);
    }

    // Cleartext HTTP/2 with prior knowledge, one connection for every request of a test.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(10),
    };

    // "status: body" for a response read to its end; "reset: why" when the stream died under it.
    private static string Fetch(HttpClient client, int port, string path)
        => Describe(client.GetAsync($"http://127.0.0.1:{port}{path}"));

    private static string Describe(Task<HttpResponseMessage> pending)
    {
        try
        {
            using HttpResponseMessage response = pending.GetAwaiter().GetResult();
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return $"{(int)response.StatusCode}: {body}";
        }
        catch (HttpRequestException e)
        {
            return $"reset: {e.GetBaseException().Message}";
        }
    }
}
