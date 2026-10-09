using System.Diagnostics;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// RingTimer: the wait actually waits, it reports expiry rather than an error, a single timer is
/// reusable across requests on its connection, and two connections waiting different amounts get
/// their own deadlines rather than each other's. And the reactor's ticker: a long pass does not
/// push its next run a whole interval out.
/// </summary>
internal static class TimerTests
{
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

        runner.Test("ticker: the wait after a pass that ran into the interval asks only for what is left of it", () =>
        {
            // The wait's timeout is the next deadline minus the clock, and the loop reads the clock
            // once per pass, right after the wait. By the next wait that reading is as old as the
            // pass's own work: after a pass that used 150 of the 250 ms, the reactor asked to sleep
            // the whole 250 again, and the tick came 150 ms late.
            //
            // Asserted on the timeout the parked reactor handed the kernel, not on how long it took.
            const int WorkMs = 150;
            int tid = 0;
            int runs = 0;

            TestServer.Start(Handlers.Raw, onStart: r =>
            {
                tid = gettid();
                r.AddTicker(() =>
                {
                    // Every other run stands in for a long completion batch or handler.
                    if (Volatile.Read(ref runs) % 2 == 1)
                    {
                        Thread.Sleep(WorkMs);
                    }
                    Interlocked.Increment(ref runs);
                });
            });

            // A wait sampled while `runs` stays at n is the one after run n, counting from 1, and
            // the even-numbered runs are the long ones.
            var afterLong = new List<long>();
            var afterShort = new List<long>();
            long deadline = Environment.TickCount64 + 20_000;
            while ((afterLong.Count == 0 || afterShort.Count == 0) && Environment.TickCount64 < deadline)
            {
                int n = Volatile.Read(ref runs);
                long? asked = ParkedWaitMs(tid);
                if (asked is long ms && n > 0 && Volatile.Read(ref runs) == n)
                {
                    (n % 2 == 0 ? afterLong : afterShort).Add(ms);
                }
            }

            Assert.True(afterShort.Count > 0 && afterLong.Count > 0,
                $"the reactor was not seen parked after both kinds of run ({afterShort.Count} short, {afterLong.Count} long)");

            // Control: after a short run the next tick is a whole interval away, and the probe sees that.
            Assert.True(afterShort.Min() > Reactor.TickMs / 2,
                $"after a short run the wait asked for {afterShort.Min()} ms, so the probe is not reading it");

            // +1 is the wait's own rounding, and the rest covers the coarse clock's tick.
            Assert.True(afterLong.Max() <= Reactor.TickMs - WorkMs + 10,
                $"after a {WorkMs} ms run the wait asked for {afterLong.Max()} ms with the tick due in "
                + $"{Reactor.TickMs - WorkMs}: it was computed from the clock read before the run");
        }, skip: !File.Exists("/proc/self/syscall"));
    }

    [DllImport("libc")]
    private static extern int gettid();

    // The timeout a thread is parked with in io_uring_enter, from /proc/self/task/<tid>/syscall and
    // the getevents arg it points at on that thread's stack. Null when the thread is not in a timed
    // wait, or left it while being read.
    private static unsafe long? ParkedWaitMs(int tid)
    {
        string path = $"/proc/self/task/{tid}/syscall";
        string first = File.ReadAllText(path);
        string[] f = first.Split(' ');
        if (f[0] != "426" || (Convert.ToUInt64(f[4], 16) & 8) == 0)   // io_uring_enter with EXT_ARG
        {
            return null;
        }

        // io_uring_getevents_arg { u64 sigmask; u32 sigmask_sz; u32 min_wait_usec; u64 ts }, and the
        // timespec is a local next to it: anything further away is a frame that has moved on.
        ulong arg = Convert.ToUInt64(f[5], 16);
        ulong ts = *(ulong*)(arg + 16);
        if (ts - arg + 4096 > 8192)
        {
            return null;
        }
        long ms = (*(long*)ts * 1000) + (*((long*)ts + 1) / 1_000_000);
        return File.ReadAllText(path) == first ? ms : null;
    }
}
