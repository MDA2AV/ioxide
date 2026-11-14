using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.httpclient;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A request that finds no connection while its pool backs off after a failed open waits behind a retry that waits
/// the backoff out on the ring. The retries keep the backoff's pace, and the reactor's stop ends the request, as it
/// ends one waiting on a connect or a response.
/// </summary>
internal static class HttpClientBackoffTests
{
    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: a request waiting out the reconnect backoff ends when its reactor stops", () =>
        {
            string outcome = EndedByTheStop(reactor => HttpClientPool.Start(reactor, new HttpClientOptions
                { Port = (ushort)TestServer.DeadPort(), PoolSize = 1, AcquireTimeoutMs = 30_000 }).GetAsync("/"));

            Assert.Equal("ObjectDisposedException: The reactor has stopped. Object name: 'Reactor'.", outcome);
        });

        runner.Test("ring client: a request waiting out the reconnect backoff ends when its reactor stops", () =>
        {
            string outcome = EndedByTheStop(reactor => RingHttpClient.Start(reactor, new RingHttpClientOptions
                    { Pool = new HttpClientOptions { PoolSize = 1, AcquireTimeoutMs = 30_000 } })
                .GetAsync($"http://127.0.0.1:{TestServer.DeadPort()}/"));

            Assert.Equal("ObjectDisposedException: The reactor has stopped. Object name: 'Reactor'.", outcome);
        });

        runner.Test("httpclient h1: a request waiting on an origin whose every open fails retries at the backoff's pace", () =>
        {
            // Accepted, then closed before the handshake: the open fails as a refused one does, and the origin counts it.
            using var origin = new TcpListener(IPAddress.Loopback, 0);
            origin.Start();
            int opens = 0;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        using Socket accepted = await origin.AcceptSocketAsync();
                        Interlocked.Increment(ref opens);
                    }
                }
                catch (Exception)
                {
                    // The listener stopped.
                }
            });

            TlsClientContext tls = TestServer.Own(TlsClientContext.Create(new TlsClientOptions { ServerName = "localhost" }));
            string outcome = OnReactor.Run(async reactor =>
            {
                HttpClientPool pool = HttpClientPool.Start(reactor, new HttpClientOptions
                {
                    Port = (ushort)((IPEndPoint)origin.LocalEndpoint).Port,
                    Tls = tls,
                    PoolSize = 1,
                    AcquireTimeoutMs = 2_000,
                });
                try
                {
                    using HttpClientResponse response = await pool.GetAsync("/");
                    return $"answered {response.Status}";
                }
                catch (HttpClientException e)
                {
                    return e.Message;
                }
            });
            int counted = Volatile.Read(ref opens);

            Assert.True(outcome.StartsWith("no connection to "), $"expected the acquire to time out, got: {outcome}");

            // The first open, then one per backoff of 200 to 400 ms, while the request waits its 2 s.
            Assert.True(counted is >= 3 and <= 12, $"{counted} opens in the request's 2 s, where its backoff allows 6 to 11");
        });
    }

    // Makes the request on a reactor of its own and stops that reactor once 50 ms have passed: the refused connect is
    // long done, and the backoff after it, 200 ms at least, has the request waiting. How the request ended, once stopped.
    private static string EndedByTheStop(Func<Reactor, ValueTask<HttpClientResponse>> request)
    {
        var made = new TaskCompletionSource<Task<HttpClientResponse>>(TaskCreationOptions.RunContinuationsAsynchronously);
        (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(
            (_, connection) => { connection.DecRef(); return Task.CompletedTask; },
            new ServerConfig
            {
                RecvBufferSize = 4096, RecvSlots = 256,
                Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
            },
            r => _ = MakeAsync(r));

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
}
