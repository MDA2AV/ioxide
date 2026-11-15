using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A buffer return from another thread that finds the reactor's return queue full. While the reactor runs, the loop
/// drains the queue and the return waits for room; once it has stopped nothing drains it, and the return must not wait.
/// </summary>
/// <remarks>
/// The real returns, on a reactor that never runs, with this test setting the flag the end of Teardown sets.
/// </remarks>
internal static class StoppedReturnTests
{
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_postsClosed")]
    private static extern ref bool PostsClosedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "InitIncremental")]
    private static extern void InitIncremental(Reactor reactor);

    public static void Register(Runner runner)
    {
        foreach (bool incremental in new[] { false, true })
        {
            string mode = incremental ? "incremental" : "shared ring";

            runner.Test($"reactor: a buffer return that finds its queue full waits while the reactor runs, and leaves when it stops ({mode})", () =>
            {
                Reactor reactor = NeverRunning(incremental);
                int capacity = incremental ? 1 << 16 : 1 << 14;
                for (int i = 0; i < capacity; i++)
                {
                    Return(reactor, incremental);
                }

                var waiting = new Thread(() => Return(reactor, incremental)) { IsBackground = true, Name = "full-queue-return" };
                waiting.Start();
                Assert.True(!waiting.Join(200), "a return that found the queue full while the reactor runs was dropped instead of waiting for room");

                Volatile.Write(ref PostsClosedOf(reactor), true);
                Assert.True(waiting.Join(3_000), "a return waiting on the full queue still spins after the stop, where nothing will drain it");
            });
        }
    }

    // Every caller is another thread, and the wake finds no eventfd to write.
    private static Reactor NeverRunning(bool incremental)
    {
        var reactor = new Reactor(0, new ServerConfig
        {
            ReactorCount = 1, Tcp = null, Udp = null, Incremental = incremental ? new IncrementalOptions() : null,
        });
        if (incremental)
        {
            InitIncremental(reactor);
        }

        return reactor;
    }

    private static void Return(Reactor reactor, bool incremental)
    {
        if (incremental)
        {
            reactor.EnqueueReturnQIncremental(3, 0, 0);
        }
        else
        {
            reactor.EnqueueReturnQ(0);
        }
    }
}
