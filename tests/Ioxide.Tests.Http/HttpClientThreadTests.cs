using ioxide;
using ioxide.httpclient;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// The clients and threads other than their reactor's: a call made on one, and a completion that arrives on one.
/// A pool, its connections and a client's origins belong to the reactor and take no lock, so each has to be
/// carried there.
/// </summary>
internal static class HttpClientThreadTests
{
    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: a pool disposed from another thread is disposed on its reactor", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(_ => (200, "", "ok")));
            string outcome = OnReactor.Run(async reactor =>
            {
                HttpClientPool pool = HttpClientPool.Start(reactor, new HttpClientOptions { Port = (ushort)origin, PoolSize = 1 });
                (await pool.GetAsync("/")).Dispose();   // its one connection is idle again

                int idle = pool.IdleCount;
                OnReactor.CallFromAnotherThread(pool.Dispose);
                int held = pool.IdleCount;
                await TestServer.LaterPass();
                return $"idle {idle}, while the reactor was held {held}, after {pool.IdleCount}";
            });

            Assert.Equal("idle 1, while the reactor was held 1, after 0", outcome);
        });

        runner.Test("ring client: a request made on another thread opens its origin's pool on the reactor", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(_ => (200, "", "ok")));
            string outcome = OnReactor.Run(async reactor =>
            {
                RingHttpClient http = RingHttpClient.Start(reactor);
                ValueTask<HttpClientResponse> call = OnReactor.CallFromAnotherThread(() => http.GetAsync($"http://127.0.0.1:{origin}/"));
                int held = http.OriginCount;
                using HttpClientResponse response = await call;
                return $"{response.Status}, origins while the reactor was held {held}, after {http.OriginCount}";
            });

            Assert.Equal("200, origins while the reactor was held 0, after 1", outcome);
        });

        runner.Test("ring client: a client disposed from another thread is disposed on its reactor", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(_ => (200, "", "ok")));
            string outcome = OnReactor.Run(async reactor =>
            {
                RingHttpClient http = RingHttpClient.Start(reactor);
                (await http.GetAsync($"http://127.0.0.1:{origin}/")).Dispose();

                int origins = http.OriginCount;
                OnReactor.CallFromAnotherThread(http.Dispose);
                int held = http.OriginCount;
                await TestServer.LaterPass();
                return $"origins {origins}, while the reactor was held {held}, after {http.OriginCount}";
            });

            Assert.Equal("origins 1, while the reactor was held 1, after 0", outcome);
        });

        runner.Test("ring client: requests to a name whose lookup fails on the resolver's thread all fail with its reason, and its pool is dropped", () =>
        {
            // A .test name fails in the resolver after the call has returned, where .invalid fails before it does, so
            // the failure comes back on the resolver's thread while the other requests wait on the same pool. The
            // trailing dot makes it absolute, so no search domain is looked up too, and the acquire budget leaves a
            // slow resolver room to answer before it runs out.
            const string Name = "ioxide-unresolvable.test.";
            const int Requests = 512;
            string outcome = OnReactor.Run(async reactor =>
            {
                RingHttpClient http = RingHttpClient.Start(reactor, new RingHttpClientOptions
                    { Pool = new HttpClientOptions { PoolSize = 64, AcquireTimeoutMs = 5_000 } });
                Task<string>[] failures = [.. Enumerable.Range(0, Requests).Select(_ => FailureOf(http, $"http://{Name}/"))];

                var timer = new RingTimer(reactor);
                long deadline = Native.MonotonicMs + 40_000;
                while ((failures.Any(f => !f.IsCompleted) || http.OriginCount > 0) && Native.MonotonicMs < deadline)
                {
                    await timer.DelayAsync(20);
                }

                string[] ended = [.. failures.Where(f => f.IsCompleted).Select(f => f.Result)];
                string[] others = [.. ended.Where(failure => !failure.Contains($"could not resolve {Name}"))];
                return $"{ended.Length - others.Length} failed with the reason, {Requests - ended.Length} never ended, "
                     + $"origins {http.OriginCount}{(others.Length == 0 ? "" : $"; {others.Length} ended otherwise, first: {others[0]}")}";
            }, timeoutMs: 80_000);

            Assert.Equal($"{Requests} failed with the reason, 0 never ended, origins 0", outcome);
        });
    }

    // How a request ended: the message it failed with, or the status it was answered with.
    private static async Task<string> FailureOf(RingHttpClient http, string url)
    {
        try
        {
            using HttpClientResponse response = await http.GetAsync(url);
            return $"answered {response.Status}";
        }
        catch (Exception e)
        {
            return $"{e.GetType().Name}: {e.Message}";
        }
    }
}
