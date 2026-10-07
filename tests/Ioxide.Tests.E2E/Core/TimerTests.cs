using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// RingTimer: the wait actually waits, it reports expiry rather than an error, a single timer is
/// reusable across requests on its connection, two connections waiting different amounts get
/// their own deadlines rather than each other's, and a wait keeps its deadline when the reactor
/// grows its op table before the wait has reached the kernel.
/// </summary>
internal static class TimerTests
{
    // Read only to tell whether the growth moved the deadline block, without which nothing dangled.
    private static readonly FieldInfo Deadlines =
        typeof(Reactor).GetField("_opTimespecs", BindingFlags.NonPublic | BindingFlags.Instance)
        ?? throw new Exception("could not reflect Reactor._opTimespecs");

    private static unsafe nint DeadlinesAt(Reactor r)
        => Deadlines.GetValue(r) is { } boxed ? (nint)Pointer.Unbox(boxed) : 0;

    private static unsafe nint NativeAlloc(int bytes) => (nint)NativeMemory.Alloc((nuint)bytes);

    private static unsafe void NativeFree(nint block) => NativeMemory.Free((void*)block);

    // A 20ms wait, then the path's count of 1ms waits in one pass, so the 1025th grows the table.
    private static async Task QueueThenGrow(Reactor r, TcpConnection conn)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            if (!int.TryParse(Wire.ReadPath(conn, snapshot).TrimStart('/'), out int others))
            {
                return;   // the harness's readiness probe, which sends no request
            }

            long armed = Stopwatch.GetTimestamp();
            Task<string> first = Timed(new RingTimer(r).DelayAsync(20), armed);
            nint block = DeadlinesAt(r);

            // Right behind the block, so the growth normally cannot extend it and has to move it.
            nint fence = NativeAlloc(16 * 1024);

            var rest = new Task<int>[others];
            for (int i = 0; i < others; i++)
            {
                rest[i] = new RingTimer(r).DelayAsync(1).AsTask();
            }
            bool moved = DeadlinesAt(r) != block;

            // Armed after the growth, so it fires: a wait that never does is reported, not hung.
            Task<int> bound = new RingTimer(r).DelayAsync(5_000).AsTask();
            await Task.WhenAny(Task.WhenAll(rest.Append<Task>(first)), bound);
            NativeFree(fence);

            int expired = rest.Count(t => t.IsCompleted && RingTimer.Expired(t.Result));
            Wire.Write(conn, 200, $"{(first.IsCompleted ? first.Result : "never -1")} {expired} {moved}");
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    // "<result> <whole ms>", stamped inline on the reactor as the wait completes.
    private static async Task<string> Timed(ValueTask<int> wait, long since)
    {
        int result = await wait;
        return $"{result} {(int)Stopwatch.GetElapsedTime(since).TotalMilliseconds}";
    }

    private static (string First, int Ms, int Expired, bool Moved) QueueThenGrowAt(int port, int others)
    {
        (int status, string body) = Client.Get(port, $"/{others}", timeoutMs: 30_000);
        Assert.Equal(200, status);

        string[] fields = body.Split(' ');
        return (fields[0], int.Parse(fields[1]), int.Parse(fields[2]), bool.Parse(fields[3]));
    }

    // Answers after the milliseconds named in the path, holding one timer for the connection and
    // re-arming it per request - the shape a caller is meant to use.
    private static async Task Delay(Reactor r, TcpConnection conn)
    {
        var timer = new RingTimer(r);
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = Wire.ReadPath(conn, snapshot);
                int ms = int.TryParse(path.TrimStart('/'), out int parsed) ? parsed : 0;

                int result = ms > 0 ? await timer.DelayAsync(ms) : RingTimer.ETime;
                Wire.Write(conn, 200, RingTimer.Expired(result) ? ms.ToString() : $"errno {result}");
                await conn.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    public static void Register(Runner runner)
    {
        runner.Test("timer: the wait actually elapses", () =>
        {
            int port = TestServer.Start(Delay);
            var sw = Stopwatch.StartNew();
            (int status, string body) = Client.Get(port, "/50");
            sw.Stop();
            Assert.Equal(200, status);
            Assert.Equal("50", body);
            Assert.True(sw.Elapsed.TotalMilliseconds >= 50,
                $"answered in {sw.Elapsed.TotalMilliseconds:F1}ms, short of the 50ms asked for");
        });

        runner.Test("timer: expiry is reported as expiry, not an error", () =>
        {
            int port = TestServer.Start(Delay);
            (int status, string body) = Client.Get(port, "/5");
            Assert.Equal(200, status);
            // The handler writes "errno N" if the completion was anything but a clean expiry.
            Assert.Equal("5", body);
        });

        runner.Test("timer: one timer serves a connection's whole life", () =>
        {
            int port = TestServer.Start(Delay);
            var sw = Stopwatch.StartNew();
            var replies = Client.GetKeepAlive(port, "/10", 5);
            sw.Stop();
            Assert.Equal(5, replies.Count);
            foreach ((int status, string body) in replies)
            {
                Assert.Equal(200, status);
                Assert.Equal("10", body);
            }
            // Five waits of 10ms on one connection, served one after another.
            Assert.True(sw.Elapsed.TotalMilliseconds >= 50,
                $"five 10ms waits took {sw.Elapsed.TotalMilliseconds:F1}ms, so some did not happen");
        });

        runner.Test("timer: overlapping waits keep their own deadlines", () =>
        {
            int port = TestServer.Start(Delay);
            int[] delays = [80, 10, 40];
            var results = new (int Status, string Body, double Ms)[delays.Length];
            var threads = new Thread[delays.Length];

            for (int i = 0; i < delays.Length; i++)
            {
                int index = i;
                threads[i] = new Thread(() =>
                {
                    var sw = Stopwatch.StartNew();
                    (int status, string body) = Client.Get(port, $"/{delays[index]}");
                    sw.Stop();
                    results[index] = (status, body, sw.Elapsed.TotalMilliseconds);
                });
                threads[i].Start();
            }

            foreach (Thread t in threads)
            {
                t.Join();
            }

            for (int i = 0; i < delays.Length; i++)
            {
                Assert.Equal(200, results[i].Status);
                // Its own value came back, not whichever request finished parsing last.
                Assert.Equal(delays[i].ToString(), results[i].Body);
                Assert.True(results[i].Ms >= delays[i],
                    $"/{delays[i]} answered in {results[i].Ms:F1}ms");
            }
        });

        runner.Test("timer: a wait queued before the op table grows keeps its deadline", () =>
        {
            // Past the first 1024 slots; a block that grew in place anyway left nothing dangling.
            bool moved = false;
            for (int attempt = 0; attempt < 3 && !moved; attempt++)
            {
                int port = TestServer.Start(QueueThenGrow);
                (string first, int ms, int expired, moved) = QueueThenGrowAt(port, 1100);

                Assert.True(first == RingTimer.ETime.ToString(), first == "never"
                    ? "the 20ms wait queued before the growth had still not fired 5s later"
                    : $"the 20ms wait queued before the growth completed with {first} after {ms}ms, not ETIME (-62)");
                Assert.True(ms >= 20, $"the 20ms wait queued before the growth expired after {ms}ms");
                Assert.Equal(1100, expired);
            }

            Assert.True(moved,
                "the deadline block grew in place on all three reactors, so nothing was ever left dangling");
        });

        runner.Test("control: the same burst within the op table's first 1024 slots keeps every deadline", () =>
        {
            // 1 + 1000 + the bound: no growth, so nothing moves the block under the queued SQEs.
            int port = TestServer.Start(QueueThenGrow);
            (string first, int ms, int expired, bool moved) = QueueThenGrowAt(port, 1000);

            Assert.True(!moved, "the deadline block moved although the op table never grew");
            Assert.Equal(RingTimer.ETime.ToString(), first);
            Assert.True(ms >= 20, $"the 20ms wait expired after {ms}ms");
            Assert.Equal(1000, expired);
        });
    }
}
