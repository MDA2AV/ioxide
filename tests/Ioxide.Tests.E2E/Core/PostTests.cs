using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="Reactor.ScheduleOnReactor"/> from other threads, many at once: each post runs once, on the
/// reactor's own thread, and one producer's posts run in the order it made them.
/// </summary>
/// <remarks>
/// AffinityTests races a single post against the drain and counts eventfd writes; neither looks at what
/// a burst of posts from several threads does once it is queued.
/// </remarks>
internal static class PostTests
{
    private const int Producers = 4;
    private const int PerProducer = 10_000;

    public static void Register(Runner runner)
    {
        runner.Test("post: 10,000 posts from each of four threads run once each, on the reactor thread, in their producer's order", () =>
        {
            (_, Reactor reactor, Thread reactorThread) = TestServer.StartConfigured(Handlers.Raw, new ServerConfig
            {
                RecvBufferSize = 4096, RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            });

            // Per producer, the number its next post must carry, so a post run twice, skipped or early shows.
            var next = new int[Producers];
            int ran = 0, offThread = 0;
            string? outOfOrder = null;

            using var go = new ManualResetEventSlim();
            var producers = new Thread[Producers];
            for (int p = 0; p < Producers; p++)
            {
                int producer = p;
                producers[p] = new Thread(() =>
                {
                    go.Wait();
                    for (int s = 0; s < PerProducer; s++)
                    {
                        int number = s;
                        reactor.ScheduleOnReactor(_ =>
                        {
                            // The harness's thread, not the reactor's own record of it.
                            if (Environment.CurrentManagedThreadId != reactorThread.ManagedThreadId)
                            {
                                Interlocked.Increment(ref offThread);
                            }

                            if (next[producer] != number)
                            {
                                Interlocked.CompareExchange(ref outOfOrder,
                                    $"producer {producer}'s post {number} ran when {next[producer]} was next", null);
                            }

                            next[producer] = number + 1;
                            Interlocked.Increment(ref ran);
                        }, null);
                    }
                })
                {
                    IsBackground = true,
                    Name = $"post-producer-{p}",
                };
                producers[p].Start();
            }

            go.Set();
            foreach (Thread producer in producers)
            {
                Assert.True(producer.Join(TimeSpan.FromSeconds(30)), "a producer never finished posting");
            }

            long deadline = Environment.TickCount64 + 30_000;
            while (Volatile.Read(ref ran) < Producers * PerProducer && Environment.TickCount64 < deadline)
            {
                Thread.Sleep(5);
            }

            // Time for a post run twice to show.
            Thread.Sleep(50);

            Assert.True(Volatile.Read(ref outOfOrder) is null, outOfOrder ?? "");
            Assert.Equal(Producers * PerProducer, Volatile.Read(ref ran));
            for (int p = 0; p < Producers; p++)
            {
                Assert.True(Volatile.Read(ref next[p]) == PerProducer, $"producer {p}: {next[p]} of its {PerProducer} posts ran");
            }
            Assert.True(offThread == 0, $"{offThread} posts ran off the reactor thread");
        });
    }
}
