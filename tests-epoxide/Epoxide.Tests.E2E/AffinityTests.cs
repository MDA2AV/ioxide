using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Where a handler runs after it awaits. A reactor thread has no SynchronizationContext, so an await
/// that is not one of epoxide's own - Task.Delay, Task.Run, a BCL HttpClient call - continues on the
/// thread pool, and the handler serves its connection from there until a read or flush of its has to
/// wait: the reactor resumes that inline, so the handler is back on it. ThreadPoolTests has the rest.
/// </summary>
internal static class AffinityTests
{
    public static void Register(Runner runner)
    {
        runner.Test("affinity: a reactor thread carries no SynchronizationContext, not even one its thread started with", () =>
        {
            // A handler's await would capture it, and a context tied to the reactor's thread could
            // never run what is posted to it while the loop holds that thread.
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null });
            string seen = "OnStart never ran";
            reactor.OnStart = r =>
            {
                seen = SynchronizationContext.Current?.GetType().Name ?? "none";
                r.Stop();
            };

            var thread = new Thread(() =>
            {
                SynchronizationContext.SetSynchronizationContext(new SynchronizationContext());
                reactor.Run();
            }) { IsBackground = true };
            thread.Start();

            Assert.True(thread.Join(10_000), "the reactor never stopped");
            Assert.Equal("none", seen);
        });

        runner.Test("affinity: Task.Delay continues on the thread pool, and a read that waits brings the handler back to the reactor", () =>
        {
            AssertServesFromPoolAfter(static async () => await Task.Delay(1));
        });

        runner.Test("affinity: Task.Run continues on the thread pool, and a read that waits brings the handler back to the reactor", () =>
        {
            AssertServesFromPoolAfter(static async () => await Task.Run(static () => Thread.Sleep(1)));
        });

        runner.Test("affinity: a BCL HttpClient call continues on the thread pool, and a read that waits brings the handler back to the reactor", () =>
        {
            int origin = TestServer.Start(Handlers.Raw);

            AssertServesFromPoolAfter(async () =>
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                await http.GetStringAsync($"http://127.0.0.1:{origin}/");
            });
        });

        runner.Test("affinity: a callback scheduled on the reactor that throws does not kill it", () =>
        {
            // An unguarded throw would unwind Run() and take the whole reactor with it - ioxide's #92
            // failure class. DrainPostQ wraps each callback for exactly this.
            int port = TestServer.Start(async (r, conn) =>
            {
                try
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    string path = Wire.ReadPath(conn, snapshot);

                    if (path == "/boom")
                    {
                        r.ScheduleOnReactor(static _ =>
                        {
                            Volatile.Write(ref _explodeReached, 1);
                            throw new InvalidOperationException("scheduled callback blew up on the reactor thread");
                        }, null);
                        Wire.Write(conn, 200, "queued");
                    }
                    else
                    {
                        Wire.Write(conn, 200, "alive");
                    }

                    await conn.FlushAsync();
                }
                finally
                {
                    conn.DecRef();
                }
            });

            (_, string queued) = Client.Get(port, "/boom");
            Assert.Equal("queued", queued);

            // Wait for proof the callback actually RAN. Without this the test asserts only that the
            // reactor is alive, which it would also be if the callback had been silently dropped -
            // passing for the opposite of the reason intended.
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref _explodeReached) == 1, 5_000),
                "the scheduled callback never reached its throw");

            // The reactor is still serving, which is the whole assertion.
            for (int i = 0; i < 3; i++)
            {
                (int status, string body) = Client.Get(port, "/ping");
                Assert.Equal(200, status);
                Assert.Equal("alive", body);
            }
        });

        runner.Test("affinity: a post that races the drain is either run by it or keeps its wake", () =>
        {
            // ScheduleOnReactor enqueues, then wakes the loop only if the pending flag was clear;
            // DrainPostQ clears the flag, then drains. Each side is a store then a load, so each needs
            // a full fence: after a plain store the drain can read the queue empty before its clear
            // lands, the poster still reads the flag set and skips its wake, and the post waits for
            // some unrelated wake - up to a tick. Too narrow to hit through a running loop, so the two
            // halves race directly here, on a reactor that never runs, from the state a post landing
            // mid-drain leaves behind: flag set, queue empty.
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null });
            var race = new PostRace();
            Action<object?> post = _ => Volatile.Write(ref race.Ran, 1);

            var poster = new Thread(() =>
            {
                for (long t = 1; ; t++)
                {
                    long go;
                    while ((go = Volatile.Read(ref race.Go)) < t) { }
                    if (go == long.MaxValue)
                    {
                        return;
                    }
                    reactor.ScheduleOnReactor(post, null);
                    Volatile.Write(ref race.Posted, t);
                    while (Volatile.Read(ref race.Checked) < t) { }
                }
            }) { IsBackground = true };
            poster.Start();

            long races = 0, missed = 0, stranded = 0;
            var headStart = new Random(1);
            var budget = Stopwatch.StartNew();
            try
            {
                while (races < 20_000_000 && budget.ElapsedMilliseconds < 30_000)
                {
                    long t = ++races;
                    Internals.PostSignalPending(reactor) = 1;
                    Volatile.Write(ref race.Ran, 0);
                    Interlocked.Exchange(ref race.Go, t);

                    // A random head start for the poster, so its post lands on every part of the drain.
                    int spin = 0;
                    for (int i = headStart.Next(0, 250); i > 0; i--)
                    {
                        spin += i;
                    }

                    Internals.DrainPostQ(reactor);
                    while (Volatile.Read(ref race.Posted) < t) { }
                    if (Volatile.Read(ref race.Ran) == 0)
                    {
                        missed++;
                        stranded += Volatile.Read(ref Internals.PostSignalPending(reactor)) == 0 ? 1 : 0;
                    }

                    Internals.DrainPostQ(reactor);   // takes the post if the racing drain left it
                    race.Sink = spin;
                    Volatile.Write(ref race.Checked, t);
                }
            }
            finally
            {
                Volatile.Write(ref race.Go, long.MaxValue);
                poster.Join();
            }

            // Vacuity guard: the post has to have landed both before and after the drain looked.
            Assert.True(missed > 0 && missed < races, $"the drain missed {missed} of {races} posts, so they never raced");
            Assert.True(stranded == 0,
                $"{stranded} of the {missed} posts the drain missed were left with the flag clear: queued, with no wake coming");
        }, skip: Environment.ProcessorCount < 2);
    }

    // Each counter on its own line, so the race's own bookkeeping does not share one with the flag.
    [StructLayout(LayoutKind.Explicit, Size = 320)]
    private sealed class PostRace
    {
        [FieldOffset(64)] public long Go;
        [FieldOffset(128)] public long Posted;
        [FieldOffset(192)] public long Checked;
        [FieldOffset(256)] public int Ran;
        [FieldOffset(260)] public int Sink;
    }

    // Runs `work` inside a handler between two requests on one connection, and reports where the
    // handler answers each: on the pool after the work, and on the reactor after a read that waited -
    // the client sends the second request only once that read has parked.
    private static void AssertServesFromPoolAfter(Func<Task> work)
    {
        int port = TestServer.Start(async (r, conn) =>
        {
            try
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                Wire.ReadPath(conn, snapshot);
                if (snapshot.IsClosed)
                {
                    return;   // the harness's probe
                }

                string verdict;
                try
                {
                    await work();
                    verdict = Where(r);
                }
                catch (Exception e)
                {
                    verdict = $"work failed: {e.Message}";
                }

                Wire.Write(conn, 200, verdict);
                await conn.FlushAsync();

                ValueTask<RecvSnapshot> next = conn.ReadAsync();
                bool waited = !next.IsCompleted;
                snapshot = await next;
                Wire.ReadPath(conn, snapshot);
                Wire.Write(conn, 200, waited ? Where(r) : "the read did not wait, so nothing was tested");
                await conn.FlushAsync();
            }
            finally
            {
                conn.DecRef();
            }
        });

        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 20_000;
        NetworkStream stream = client.GetStream();
        Client.Send(stream, "/");
        Assert.Equal("pool", Client.ReadResponse(stream).Body);
        Thread.Sleep(200);   // the handler's next read has parked by now
        Client.Send(stream, "/");
        Assert.Equal("reactor", Client.ReadResponse(stream).Body);
    }

    private static string Where(Reactor r)
        => r.OnReactorThread ? "reactor"
         : Thread.CurrentThread.IsThreadPoolThread ? "pool"
         : $"thread {Environment.CurrentManagedThreadId}";

    // Set immediately before the throw, so the test can tell "the guard handled it" from "the
    // callback never ran at all" - which look identical from the outside.
    private static int _explodeReached;
}
