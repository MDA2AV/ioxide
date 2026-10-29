using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// RingTimer at its short end: a sub-millisecond wait, and waits of zero and less. TimerTests measures
/// waits of milliseconds from the client, which a lost sub-millisecond part would still pass.
/// </summary>
internal static class RingTimerTests
{
    private const int Waits = 200;
    private const long WaitNs = 200_000;

    public static void Register(Runner runner)
    {
        runner.Test($"timer: a 200 us wait never completes early, over {Waits} waits", () =>
        {
            // On the monotonic clock the kernel's timeout runs on, from before the wait was submitted.
            List<(int Result, long WaitedNs)> waits = OnReactor<List<(int, long)>>(async timer =>
            {
                var seen = new List<(int, long)>(Waits);
                for (int i = 0; i < Waits; i++)
                {
                    long armed = Stopwatch.GetTimestamp();
                    int result = await timer.DelayNanosecondsAsync(WaitNs);
                    seen.Add((result, (Stopwatch.GetTimestamp() - armed) * 1_000_000_000 / Stopwatch.Frequency));
                }
                return seen;
            });

            Assert.Equal(Waits, waits.Count);
            int[] errors = waits.Where(w => w.Result != RingTimer.ETime).Select(w => w.Result).ToArray();
            Assert.True(errors.Length == 0, $"{errors.Length} waits completed with something other than ETIME: {string.Join(", ", errors.Distinct())}");

            long[] early = waits.Where(w => w.WaitedNs < WaitNs).Select(w => w.WaitedNs).ToArray();
            Assert.True(early.Length == 0,
                $"{early.Length} of {Waits} waits of {WaitNs} ns completed early, the shortest after {early.DefaultIfEmpty().Min()} ns");
        });

        runner.Test("timer: zero and negative delays complete, as expiries", () =>
        {
            int[] results = OnReactor<int[]>(async timer =>
            [
                await timer.DelayAsync(0),
                await timer.DelayAsync(0),   // the same timer again, after a zero wait
                await timer.DelayNanosecondsAsync(0),
                await timer.DelayNanosecondsAsync(-1),
                await timer.DelayAsync(-5),
                await timer.DelayAsync(int.MinValue),
                await timer.DelayAsync(TimeSpan.Zero),
                await timer.DelayAsync(TimeSpan.FromMilliseconds(-5)),
            ]);

            Assert.Equal(string.Join(", ", Enumerable.Repeat(RingTimer.ETime, 8)), string.Join(", ", results));
        });
    }

    /// <summary>
    /// Runs <paramref name="waits"/> in a handler, on the reactor thread, once a client has sent a byte,
    /// and returns what it recorded. The client waits for the handler's answer, so a wait that never
    /// completes fails the test on the read's timeout.
    /// </summary>
    private static T OnReactor<T>(Func<RingTimer, Task<T>> waits)
    {
        var recorded = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (reactor, conn) =>
        {
            try
            {
                RecvSnapshot snapshot;
                bool peerSent = false;
                do
                {
                    snapshot = await conn.ReadAsync();
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            peerSent = true;
                            conn.ReturnBuffer(in item);
                        }
                    }
                }
                while (!peerSent && !snapshot.IsClosed);

                if (!peerSent)
                {
                    return;   // the harness's readiness probe
                }

                try
                {
                    recorded.TrySetResult(await waits(new RingTimer(reactor)));
                }
                catch (Exception e)
                {
                    recorded.TrySetException(e);
                }

                conn.Write("done"u8);
                await conn.FlushAsync();
            }
            finally
            {
                conn.DecRef();
            }
        }, new ServerConfig
        {
            RecvBufferSize = 4096, RecvSlots = 64,
            Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
        }).Port;

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 10_000 };
        client.Connect(IPAddress.Loopback, port);
        client.Send([1]);

        byte[] done = new byte[4];
        int got = 0, n;
        while (got < done.Length && (n = client.Receive(done, got, done.Length - got, SocketFlags.None)) > 0)
        {
            got += n;
        }
        Assert.True(got == 4 && "done"u8.SequenceEqual(done), "the waits never finished");

        return recorded.Task.Result;
    }
}
