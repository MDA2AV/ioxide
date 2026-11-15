using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// The clients as their reactor stops. Its first pass disposes every pool and client started on it, before it closes
/// its connections: their idle connections close, their TLS context is freed, and the requests waiting on them fail
/// with ObjectDisposedException while the reactor still runs what that wakes.
/// </summary>
internal static class HttpClientStopTests
{
    // Generous against a close or an end that takes no time at all: the assertion is that it comes.
    private const int WithinMs = 5_000;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_tls")]
    private static extern ref TlsClientContext? TlsOf(RingHttpClient client);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_disposed")]
    private static extern ref bool DisposedOf(TlsClientContext context);

    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: a connection handed to a waiting request as its reactor stops is let go, and the requests queued behind it end", () =>
        {
            using var origin = new CountingOrigin();
            HttpClientPool pool = null!;
            (_, Reactor reactor, Thread thread) = StartReactor(r => pool = HttpClientPool.Start(r,
                new HttpClientOptions { Port = (ushort)origin.Port, PoolSize = 1, AcquireTimeoutMs = 30_000 }));

            // The first answer hands the one connection to the second request, whose continuation is posted, and the
            // stop comes in that same pass.
            (Task<string> second, Task<string> third) = RunOnReactor(reactor, async () =>
            {
                ValueTask<HttpClientResponse> first = pool.GetAsync("/");
                Task<string> second = EndOf(pool.GetAsync("/"));
                Task<string> third = EndOf(pool.GetAsync("/"));
                (await first).Dispose();
                reactor.Stop();
                return (second, third);
            });
            Assert.True(thread.Join(10_000), "the reactor did not stop");

            Assert.Equal("second: answered 200, third: ObjectDisposedException, origin connections closed: 1 of 1",
                $"second: {Ended(second)}, third: {Ended(third)}, origin connections closed: {origin.ClosedOf(1)}");
        });

        runner.Test("httpclient h1: a pool's idle connections are closed by its reactor's stop", () =>
        {
            using var origin = new CountingOrigin();
            HttpClientPool pool = null!;
            (_, Reactor reactor, Thread thread) = StartReactor(r => pool = HttpClientPool.Start(r,
                new HttpClientOptions { Port = (ushort)origin.Port, PoolSize = 2 }));

            int idle = RunOnReactor(reactor, async () =>
            {
                ValueTask<HttpClientResponse> a = pool.GetAsync("/"), b = pool.GetAsync("/");
                (await a).Dispose();
                (await b).Dispose();
                return pool.IdleCount;
            });
            reactor.Stop();
            Assert.True(thread.Join(10_000), "the reactor did not stop");

            Assert.Equal("idle 2, origin connections closed: 2 of 2", $"idle {idle}, origin connections closed: {origin.ClosedOf(2)}");
        });

        runner.Test("httpclient h1: a request a handler makes as its reactor stops is refused, and never reaches the origin", () =>
        {
            // The stop resumes a handler by closing its connection, after it has disposed the pool.
            using var origin = new CountingOrigin();
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task<string>? asked = null;
            HttpClientPool pool = null!;
            (int port, Reactor reactor, Thread thread) = StartReactor(
                r => pool = HttpClientPool.Start(r, new HttpClientOptions { Port = (ushort)origin.Port, PoolSize = 1 }),
                async (_, connection) =>
                {
                    try
                    {
                        if (await SentSomething(connection))
                        {
                            parked.TrySetResult();
                            await connection.ReadAsync();   // until the stop closes it
                            asked = FailureOf(pool);
                        }
                    }
                    finally
                    {
                        connection.DecRef();
                    }
                });

            RunOnReactor(reactor, async () =>
            {
                (await pool.GetAsync("/")).Dispose();   // the pool's one connection, idle
                return 0;
            });
            using var client = new TcpClient("127.0.0.1", port);
            client.GetStream().Write("hi"u8);
            Assert.True(parked.Task.Wait(WithinMs), "the handler never parked");
            reactor.Stop();
            Assert.True(thread.Join(10_000), "the reactor did not stop");

            string closed = origin.ClosedOf(1);
            Assert.Equal($"ObjectDisposedException: pool for 127.0.0.1:{origin.Port} is disposed Object name: 'HttpClientPool'.; origin requests 1, connections closed: 1 of 1",
                $"{(asked is null ? "never asked" : Ended(asked))}; origin requests {origin.Requests}, connections closed: {closed}");
        });

        runner.Test("ring client: its reactor's stop closes its origins' idle connections and frees its TLS context", () =>
        {
            using var origin = new CountingOrigin();
            using TlsTestOrigin secure = TlsTestOrigin.Start("http/1.1");
            (string certPath, _) = TestCert.Ensure();
            RingHttpClient http = null!;
            (_, Reactor reactor, Thread thread) = StartReactor(r => http = RingHttpClient.Start(r, new RingHttpClientOptions
            {
                Tls = new TlsClientOptions { CaFile = certPath, AlpnProtocols = ["http/1.1"] },
            }));

            string answered = RunOnReactor(reactor, async () =>
            {
                using HttpClientResponse plain = await http.GetAsync($"http://127.0.0.1:{origin.Port}/");
                using HttpClientResponse tls = await http.GetAsync($"https://localhost:{secure.Port}/");
                return $"{plain.Status} {tls.Status}, origins {http.OriginCount}";
            }, timeoutMs: 20_000);
            TlsClientContext context = TlsOf(http)!;
            reactor.Stop();
            Assert.True(thread.Join(10_000), "the reactor did not stop");

            Assert.Equal("200 200, origins 2; origin connections closed: 1 of 1, TLS context freed: True",
                $"{answered}; origin connections closed: {origin.ClosedOf(1)}, TLS context freed: {DisposedOf(context)}");
        });

        runner.Test("ring client: a request made once it is disposed fails with ObjectDisposedException", () =>
        {
            string outcome = OnReactor.Run(async reactor =>
            {
                RingHttpClient http = RingHttpClient.Start(reactor);
                http.Dispose();
                return await EndOf(http.GetAsync($"http://127.0.0.1:{TestServer.DeadPort()}/"));
            });

            Assert.Equal("ObjectDisposedException", outcome);
        });

        runner.Test("httpclient h1: a request waiting out the reconnect backoff ends when its reactor stops", () =>
        {
            string outcome = EndedByTheStop(reactor => HttpClientPool.Start(reactor, new HttpClientOptions
                { Port = (ushort)TestServer.DeadPort(), PoolSize = 1, AcquireTimeoutMs = 30_000 }).GetAsync("/"));

            Assert.True(outcome.StartsWith("ObjectDisposedException: pool for 127.0.0.1:"), $"expected the stop to dispose the pool under the request, got: {outcome}");
        });

        runner.Test("ring client: a request waiting out the reconnect backoff ends when its reactor stops", () =>
        {
            string outcome = EndedByTheStop(reactor => RingHttpClient.Start(reactor, new RingHttpClientOptions
                    { Pool = new HttpClientOptions { PoolSize = 1, AcquireTimeoutMs = 30_000 } })
                .GetAsync($"http://127.0.0.1:{TestServer.DeadPort()}/"));

            Assert.True(outcome.StartsWith("ObjectDisposedException: pool for 127.0.0.1:"), $"expected the stop to dispose the pool under the request, got: {outcome}");
        });

        runner.Test("tls client: a connect that completes after its TLS context was freed is refused, and closes its socket", () =>
        {
            // A RingHttpClient its reactor's stop disposes frees the context while an open of its can still be connecting.
            using var origin = new CountingOrigin();
            TlsClientContext tls = TlsClientContext.Create(new TlsClientOptions { ServerName = "localhost" });
            tls.Dispose();

            string outcome = OnReactor.Run(async reactor =>
            {
                try
                {
                    await ClientTransport.ConnectAsync(reactor, [IPAddress.Loopback], (ushort)origin.Port, tls, "localhost", connectTimeoutMs: 0);
                    return "connected";
                }
                catch (Exception e)
                {
                    return e.GetType().Name;
                }
            });

            Assert.Equal("ObjectDisposedException, origin connections closed: 1 of 1", $"{outcome}, origin connections closed: {origin.ClosedOf(1)}");
        });
    }

    private static (int Port, Reactor Reactor, Thread Thread) StartReactor(Action<Reactor> onStart,
        Func<Reactor, TcpConnection, Task>? handle = null)
        => TestServer.StartConfigured(
            handle ?? ((_, connection) => { connection.DecRef(); return Task.CompletedTask; }),
            new ServerConfig
            {
                RecvBufferSize = 4096,
                RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 8, RecvQueueEntries = 64 },
            },
            onStart);

    // From the reactor's post queue rather than OnStart, so a body that stops the reactor cannot do it before the
    // harness has seen it listen.
    private static T RunOnReactor<T>(Reactor reactor, Func<Task<T>> body, int timeoutMs = 10_000)
    {
        var outcome = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        reactor.ScheduleOnReactor(_ => _ = RunAsync(), null);
        Assert.True(outcome.Task.Wait(timeoutMs), $"the code on the reactor did not finish within {timeoutMs} ms");
        return outcome.Task.Result;

        async Task RunAsync()
        {
            try
            {
                outcome.TrySetResult(await body());
            }
            catch (Exception e)
            {
                outcome.TrySetException(e);
            }
        }
    }

    // Makes the request on a reactor of its own and stops that reactor once 50 ms have passed: the refused connect is
    // long done, and the backoff after it, 200 ms at least, has the request waiting. How the request ended, once stopped.
    private static string EndedByTheStop(Func<Reactor, ValueTask<HttpClientResponse>> request)
    {
        var made = new TaskCompletionSource<Task<HttpClientResponse>>(TaskCreationOptions.RunContinuationsAsynchronously);
        (_, Reactor reactor, Thread thread) = StartReactor(r => _ = MakeAsync(r));

        Assert.True(made.Task.Wait(10_000), "the request was never made");
        reactor.Stop();
        Assert.True(thread.Join(10_000), "the reactor did not stop");

        Task<HttpClientResponse> call = made.Task.Result;
        try
        {
            return call.Wait(2_000) ? $"answered {call.Result.Status}" : "still waiting 2 s after its reactor stopped";
        }
        catch (AggregateException e)
        {
            return $"{e.InnerException!.GetType().Name}: {e.InnerException.Message.ReplaceLineEndings(" ")}";
        }

        async Task MakeAsync(Reactor r)
        {
            Task<HttpClientResponse> pending = request(r).AsTask();
            await new RingTimer(r).DelayAsync(50);
            made.SetResult(pending);
        }
    }

    // How a request ended: the status it was answered with, or the type of what it threw.
    private static async Task<string> EndOf(ValueTask<HttpClientResponse> request)
    {
        try
        {
            using HttpClientResponse response = await request;
            return $"answered {response.Status}";
        }
        catch (Exception e)
        {
            return e.GetType().Name;
        }
    }

    private static string Ended(Task<string> request) => request.Wait(WithinMs) ? request.Result : "never ended";

    // Why a request made now fails, or the status it was answered with.
    private static async Task<string> FailureOf(HttpClientPool pool)
    {
        try
        {
            using HttpClientResponse response = await pool.GetAsync("/");
            return $"answered {response.Status}";
        }
        catch (Exception e)
        {
            return $"{e.GetType().Name}: {e.Message.ReplaceLineEndings(" ")}";
        }
    }

    // The harness's listen probe connects and closes without sending anything.
    private static async Task<bool> SentSomething(TcpConnection connection)
    {
        while (true)
        {
            RecvSnapshot snapshot = await connection.ReadAsync();

            bool received = false;
            while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    received = true;
                    connection.ReturnBuffer(in item);
                }
            }

            if (received || snapshot.IsClosed)
            {
                return received;
            }
        }
    }

    // Answers every request with 200, and counts them and the connections its client closed.
    private sealed class CountingOrigin : IDisposable
    {
        private readonly FakeServer _server;
        private int _requests;
        private int _closed;

        public CountingOrigin() => _server = new FakeServer((_, socket) =>
        {
            try
            {
                var buffer = new byte[4096];
                var received = new StringBuilder();
                int n;
                while ((n = socket.Receive(buffer)) > 0)
                {
                    received.Append(Encoding.Latin1.GetString(buffer, 0, n));
                    for (int end; (end = received.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal)) >= 0;)
                    {
                        received.Remove(0, end + 4);
                        Interlocked.Increment(ref _requests);
                        socket.Send("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"u8);
                    }
                }
            }
            catch (SocketException)
            {
                // reset by its client: closed too
            }
            finally
            {
                Interlocked.Increment(ref _closed);
            }
        });

        public int Port => _server.Port;

        public int Requests => Volatile.Read(ref _requests);

        // How many of `expected` connections it saw closed, given until WithinMs to see them all.
        public string ClosedOf(int expected)
        {
            long deadline = Environment.TickCount64 + WithinMs;
            while (Volatile.Read(ref _closed) < expected && Environment.TickCount64 < deadline)
            {
                Thread.Sleep(20);
            }
            return $"{Volatile.Read(ref _closed)} of {expected}";
        }

        public void Dispose() => _server.Dispose();
    }
}
