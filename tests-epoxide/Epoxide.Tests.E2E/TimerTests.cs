using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// ReactorTimer: the wait actually waits, it reports expiry rather than an error, a single timer is
/// reusable across requests on its connection, two connections waiting different amounts get their
/// own deadlines rather than each other's, and a burst of waits - armed on the reactor, or posted to
/// it from other threads - keeps every deadline. And the reactor's ticker: a long pass does not push
/// its next run a whole interval out.
/// </summary>
/// <remarks>
/// ioxide's two op-table growth tests protect a wait whose deadline lives in storage that moves
/// while the wait is queued. epoxide keeps deadlines in a priority queue on the reactor, and an
/// arm from another thread is posted with the deadline already computed - so its equivalents are a
/// wait queued ahead of a burst large enough to grow that queue many times over, and waits armed
/// from other threads, whose deadlines must not slip by the post.
/// </remarks>
internal static class TimerTests
{
    // "<result> <whole ms>", stamped inline on the reactor as the wait completes.
    private static async Task<string> Timed(ValueTask<int> wait, long since)
    {
        int result = await wait;
        return $"{result} {(int)Stopwatch.GetElapsedTime(since).TotalMilliseconds}";
    }

    // A 20 ms wait, then the path's count of 1 ms waits in one pass, behind it in the reactor's queue.
    private static async Task QueueThenBurst(Reactor r, TcpConnection conn)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            if (!int.TryParse(Wire.ReadPath(conn, snapshot).TrimStart('/'), out int others))
            {
                return;   // the harness's readiness probe, which sends no request
            }

            long armed = Stopwatch.GetTimestamp();
            Task<string> first = Timed(new ReactorTimer(r).DelayAsync(20), armed);

            var rest = new Task<int>[others];
            for (int i = 0; i < others; i++)
            {
                rest[i] = new ReactorTimer(r).DelayAsync(1).AsTask();
            }

            // Armed after the burst, so it fires: a wait that never does is reported, not hung.
            Task<int> bound = new ReactorTimer(r).DelayAsync(5_000).AsTask();

            // On the reactor, so nothing has expired yet: every wait is in the queue at once.
            int queued = Internals.PendingTimers(r);

            await Task.WhenAny(Task.WhenAll(rest.Append<Task>(first)), bound);

            int expired = rest.Count(t => t.IsCompleted && ReactorTimer.Expired(t.Result));
            Wire.Write(conn, 200, $"{(first.IsCompleted ? first.Result : "never -1")} {expired} {queued}");
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static (string First, int Ms, int Expired, int Queued) QueueThenBurstAt(int port, int others)
    {
        (int status, string body) = Client.Get(port, $"/{others}", timeoutMs: 30_000);
        Assert.Equal(200, status);

        string[] fields = body.Split(' ');
        return (fields[0], int.Parse(fields[1]), int.Parse(fields[2]), int.Parse(fields[3]));
    }

    // Answers after the milliseconds named in the path, holding one timer for the connection and
    // re-arming it per request - the shape a caller is meant to use.
    private static async Task Delay(Reactor r, TcpConnection conn)
    {
        var timer = new ReactorTimer(r);
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = Wire.ReadPath(conn, snapshot);
                int ms = int.TryParse(path.TrimStart('/'), out int parsed) ? parsed : 0;

                int result = ms > 0 ? await timer.DelayAsync(ms) : ReactorTimer.ETime;
                Wire.Write(conn, 200, ReactorTimer.Expired(result) ? ms.ToString() : $"errno {result}");
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

    // Twenty 5 ms waits in a row on one timer, answered with the median of how far past its deadline
    // each one ended, in microseconds.
    private static async Task Lateness(Reactor r, TcpConnection conn)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            Wire.ReadPath(conn, snapshot);
            if (snapshot.IsClosed)
            {
                return;   // the harness's readiness probe, which sends no request
            }

            var timer = new ReactorTimer(r);
            var late = new double[20];
            for (int i = 0; i < late.Length; i++)
            {
                long armed = Stopwatch.GetTimestamp();
                await timer.DelayAsync(5);
                late[i] = Stopwatch.GetElapsedTime(armed).TotalMicroseconds - 5_000;
            }

            Array.Sort(late);
            Wire.Write(conn, 200, ((int)late[late.Length / 2]).ToString());
            await conn.FlushAsync();
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

        runner.Test("timer: a wait queued before a burst of 1100 others keeps its deadline", () =>
        {
            // The queue starts empty and grows as it fills, so 1102 waits at once move its storage
            // many times while the first one is queued.
            int port = TestServer.StartConfigured(QueueThenBurst, Config()).Port;
            (string first, int ms, int expired, int queued) = QueueThenBurstAt(port, 1100);

            Assert.True(queued >= 1102, $"only {queued} waits were queued at once, so the burst never stood behind the first");
            Assert.True(first == "0", first == "never"
                ? "the 20ms wait queued before the burst had still not fired 5s later"
                : $"the 20ms wait queued before the burst completed with {first} after {ms}ms, not as an expiry (0)");
            Assert.True(ms >= 20, $"the 20ms wait queued before the burst expired after {ms}ms");
            Assert.Equal(1100, expired);
        });

        runner.Test("timer: waits armed from other threads and from the reactor at once keep their deadlines", () =>
        {
            // An arm off the reactor is posted, with its deadline computed before the post: a deadline
            // computed when the reactor got round to it would be late by however busy the reactor was,
            // and one compared on the wrong clock could fire early. Eight threads and the reactor arm
            // 200 waits between them, all pending together, and each must expire no earlier than asked.
            (Reactor reactor, _) = TestServer.StartClientOnly();

            const int Threads = 8, PerThread = 20, OnReactor = 40;
            var outcomes = new ConcurrentBag<string>();
            var completions = new ConcurrentBag<Task>();

            void Arm(int index)
            {
                int ms = 100 + index % 37 * 3;   // 100-208 ms: all still pending when they are counted
                long armedAt = Stopwatch.GetTimestamp();
                Task<int> wait = new ReactorTimer(reactor).DelayAsync(ms).AsTask();
                completions.Add(wait.ContinueWith(t =>
                {
                    double after = Stopwatch.GetElapsedTime(armedAt).TotalMilliseconds;
                    if (!t.IsCompletedSuccessfully || !ReactorTimer.Expired(t.Result))
                    {
                        outcomes.Add($"wait {index} ({ms} ms) ended {t.Status} with {(t.IsCompletedSuccessfully ? t.Result : -1)}");
                    }
                    else if (after < ms)
                    {
                        outcomes.Add($"wait {index} ({ms} ms) expired after {after:F1} ms");
                    }
                }, TaskContinuationOptions.ExecuteSynchronously));
            }

            using var armed = new CountdownEvent(Threads + 1);
            var arming = new Thread[Threads];
            for (int t = 0; t < Threads; t++)
            {
                int first = t * PerThread;
                arming[t] = new Thread(() =>
                {
                    for (int i = 0; i < PerThread; i++)
                    {
                        Arm(first + i);
                    }
                    armed.Signal();
                });
                arming[t].Start();
            }
            reactor.ScheduleOnReactor(_ =>
            {
                for (int i = 0; i < OnReactor; i++)
                {
                    Arm(Threads * PerThread + i);
                }
                armed.Signal();
            }, null);

            Assert.True(armed.Wait(10_000), "the waits were never all armed");

            // Posted after every arm the threads posted, so they have all landed when this runs.
            int queued = Internals.PendingTimers(reactor);
            Assert.True(queued == Threads * PerThread + OnReactor,
                $"{queued} of {Threads * PerThread + OnReactor} waits were pending together, so they did not overlap");

            Assert.True(Task.WaitAll([.. completions], 10_000), "some waits never completed");
            Assert.True(outcomes.IsEmpty, $"{outcomes.Count} waits broke their deadline: {string.Join("; ", outcomes.Take(3))}");
        });

        runner.Test("timer: a wait ends at its deadline, not at the millisecond after it", () =>
        {
            // A wait that rounds a deadline up to whole milliseconds ends every timer up to one late,
            // and every timer that came due in one sleep together - the async profile's whole gap.
            int port = TestServer.Start(Lateness);
            (int status, string body) = Client.Get(port, "/", timeoutMs: 10_000);
            Assert.Equal(200, status);
            Assert.True(int.Parse(body) < 500, $"the median 5 ms wait ended {body} us past its deadline");
        }, skip: !PreciseWaitAvailable());

        runner.Test("ticker: the wait after a pass that ran into the interval asks only for what is left of it", () =>
        {
            // The wait's timeout is the next deadline minus the clock. Read once per pass, right after
            // the wait, that reading is as old as the pass's own work by the next wait: after a pass
            // that used 150 of the 250 ms, the reactor would ask to sleep the whole 250 again, and the
            // tick would come 150 ms late.
            //
            // Asserted on the timeout the parked reactor handed epoll_wait, not on how long it took.
            const int WorkMs = 150;
            int tid = 0;
            int runs = 0;

            TestServer.Start(Handlers.Raw, onStart: r =>
            {
                tid = gettid();
                r.AddTicker(() =>
                {
                    // Every other run stands in for a long event batch or handler.
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
        }, skip: !File.Exists("/proc/self/syscall") || EpollWaitSyscalls().Length == 0);
    }

    private static ServerConfig Config() => new()
    {
        RecvBufferSize = 4096,
        Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
    };

    [DllImport("libc")]
    private static extern int gettid();

    // The syscalls a parked epoll reactor can be in, by number: epoll_pwait2 (441 on both), whose fourth
    // argument points at the timeout, and the fallback's epoll_wait and epoll_pwait on x86-64 and
    // epoll_pwait on arm64 (which has no epoll_wait), whose fourth argument is the timeout in ms.
    private const string EpollPwait2 = "441";

    private static string[] EpollWaitSyscalls() => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => [EpollPwait2, "232", "281"],
        Architecture.Arm64 => [EpollPwait2, "22"],
        _ => [],
    };

    // The reactor waits in nanoseconds where the kernel (5.11) and libc (2.35) both have epoll_pwait2.
    private static bool PreciseWaitAvailable()
        => Environment.OSVersion.Version >= new Version(5, 11)
        && NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "epoll_pwait2", out _);

    // The timeout a thread is parked with in epoll_wait, from /proc/self/task/<tid>/syscall
    // ("nr arg1 arg2 arg3 arg4 ..."). Null when the thread is not in that wait, or left it while
    // being read.
    private static unsafe long? ParkedWaitMs(int tid)
    {
        string path = $"/proc/self/task/{tid}/syscall";
        string first = File.ReadAllText(path);
        string[] f = first.Split(' ');
        if (f.Length < 5 || !EpollWaitSyscalls().Contains(f[0]))
        {
            return null;
        }

        ulong arg = Convert.ToUInt64(f[4], 16);
        if (f[0] == EpollPwait2 && arg == 0)
        {
            return null;
        }

        // epoll_pwait2's timespec is in this process, on the reactor's stack while it is parked.
        long ms = f[0] == EpollPwait2
            ? ((Native.timespec*)arg)->tv_sec * 1000 + ((Native.timespec*)arg)->tv_nsec / 1_000_000
            : (int)arg;
        return File.ReadAllText(path) == first ? ms : null;
    }
}
