using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="Mpsc{T}"/>, the bounded queue other threads hand a reactor its recv buffers back through
/// (#427): values from concurrent producers arrive once each and in each producer's order, and a full
/// queue refuses rather than overwrites.
/// </summary>
internal static class MpscTests
{
    private const int Producers = 4;
    private const int PerProducer = 100_000;

    // Each value names its producer and its place: producer * Stride + sequence.
    private const long Stride = 1_000_000;

    public static void Register(Runner runner)
    {
        runner.Test("mpsc: four producers' values each arrive once and in their producer's order", () =>
        {
            // Small, so the producers find it full again and again and retry, as EnqueueReturnQ's callers do.
            var queue = new Mpsc<long>(1024);
            int go = 0, stop = 0;

            var threads = new Thread[Producers];
            for (int p = 0; p < Producers; p++)
            {
                long producer = p;
                threads[p] = new Thread(() =>
                {
                    while (Volatile.Read(ref go) == 0)
                    {
                        if (Volatile.Read(ref stop) != 0)
                        {
                            return;
                        }
                        Thread.SpinWait(1);
                    }

                    for (long s = 0; s < PerProducer; s++)
                    {
                        while (!queue.TryEnqueue(producer * Stride + s))
                        {
                            if (Volatile.Read(ref stop) != 0)
                            {
                                return;
                            }
                            Thread.SpinWait(1);
                        }
                    }
                }) { IsBackground = true, Name = $"mpsc-producer-{p}" };
                threads[p].Start();
            }

            var next = new long[Producers];
            int received = 0, stuck;
            string? wrong = null;
            try
            {
                Volatile.Write(ref go, 1);
                long deadline = Environment.TickCount64 + 60_000;
                while (received < Producers * PerProducer && Environment.TickCount64 < deadline)
                {
                    if (!queue.TryDequeue(out long value))
                    {
                        Thread.SpinWait(1);
                        continue;
                    }

                    long p = value / Stride, s = value % Stride;
                    if (p is < 0 or >= Producers || s != next[p])
                    {
                        wrong = $"after {received} values, producer {p}'s value {s} arrived where "
                                + (p is < 0 or >= Producers ? "no producer has one" : $"{next[p]} was next");
                        break;
                    }

                    next[p]++;
                    received++;
                }
            }
            finally
            {
                Volatile.Write(ref stop, 1);
                stuck = threads.Count(thread => !thread.Join(10_000));
            }

            Assert.True(wrong is null, wrong!);
            Assert.True(stuck == 0, $"{stuck} producers did not stop");
            Assert.True(received == Producers * PerProducer,
                $"{received} of {Producers * PerProducer} values arrived; per producer: {string.Join(", ", next)}");
            Assert.True(!queue.TryDequeue(out long extra), $"value {extra} arrived after every producer's last");
        });

        runner.Test("mpsc: an enqueue is refused when full, and taken again after a dequeue", () =>
        {
            var queue = new Mpsc<long>(4);
            for (long v = 10; v < 14; v++)
            {
                Assert.True(queue.TryEnqueue(v), $"value {v} was refused with room for it");
            }

            Assert.True(!queue.TryEnqueue(14), "a fifth value fit in four slots");
            Assert.True(!queue.TryEnqueue(14), "a fifth value fit in four slots on the second try");

            Assert.True(queue.TryDequeue(out long first), "a full queue gave nothing back");
            Assert.Equal(10L, first);
            Assert.True(queue.TryEnqueue(14), "the slot the dequeue freed was not taken");
            Assert.True(!queue.TryEnqueue(15), "a fifth value fit after the freed slot was taken");

            // The refused attempts left no trace.
            for (long v = 11; v <= 14; v++)
            {
                Assert.True(queue.TryDequeue(out long value), $"value {v} was lost");
                Assert.Equal(v, value);
            }
            Assert.True(!queue.TryDequeue(out _), "a value came out of a drained queue");
        });
    }
}
