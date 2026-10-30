using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Continuation affinity: ioxide's own completions resume a handler on its reactor, an await on
/// anything else resumes where that thing completed, and <see cref="ReactorSwitch"/> comes back.
///
/// The reactor installs no SynchronizationContext. One would send every ConfigureAwait(false)
/// continuation the reactor completes to the thread pool - .NET never runs such a continuation
/// inline on a thread that has a context - which is how library code ended up leaving it.
/// </summary>
internal static class AffinityTests
{
    public static void Register(Runner runner)
    {
        runner.Test("affinity: a reactor thread knows its reactor and carries no SynchronizationContext", () =>
        {
            int port = TestServer.Start(async (r, conn) =>
            {
                try
                {
                    await conn.ReadAsync();

                    SynchronizationContext? context = SynchronizationContext.Current;
                    string verdict = !ReferenceEquals(Reactor.Current, r) ? "Reactor.Current is not this reactor"
                        : context is not null ? $"context installed: {context.GetType().Name}"
                        : "bound";

                    Wire.Write(conn, 200, verdict);
                    await conn.FlushAsync();
                }
                finally
                {
                    conn.DecRef();
                }
            });

            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("bound", body);
        });

        runner.Test("affinity: a ConfigureAwait(false) continuation the reactor completes stays on it", () =>
        {
            // The shape of library code: a task completed from the reactor, awaited with
            // ConfigureAwait(false). Under a reactor context this continuation went to the pool.
            AssertOnReactorAfter(static async r =>
            {
                var done = new TaskCompletionSource();
                r.ScheduleOnReactor(static s => ((TaskCompletionSource)s!).SetResult(), done);
                await done.Task.ConfigureAwait(false);
            });
        });

        runner.Test("affinity: ReactorSwitch comes back after Task.Delay", () =>
        {
            AssertOnReactorAfter(static async r =>
            {
                await Task.Delay(1);
                await new ReactorSwitch(r);
            });
        });

        runner.Test("affinity: ReactorSwitch comes back after Task.Run", () =>
        {
            AssertOnReactorAfter(static async r =>
            {
                await Task.Run(static () => Thread.Sleep(1));
                await new ReactorSwitch(r);
            });
        });

        runner.Test("affinity: ReactorSwitch comes back after a BCL HttpClient call", () =>
        {
            int origin = TestServer.Start(Handlers.Raw);

            AssertOnReactorAfter(async r =>
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                await http.GetStringAsync($"http://127.0.0.1:{origin}/");
                await new ReactorSwitch(r);
            });
        });

        runner.Test("affinity: ReactorSwitch on the reactor continues at once", () =>
        {
            // Completed when already there, so a call site needs no check of its own.
            int port = TestServer.Start(async (r, conn) =>
            {
                try
                {
                    await conn.ReadAsync();
                    ReactorSwitch hop = new ReactorSwitch(r).GetAwaiter();
                    Wire.Write(conn, 200, hop.IsCompleted && new ReactorSwitch(null).IsCompleted ? "inline" : "posted");
                    await conn.FlushAsync();
                }
                finally
                {
                    conn.DecRef();
                }
            });

            (_, string body) = Client.Get(port, "/");
            Assert.Equal("inline", body);
        });

        runner.Test("affinity: a posted callback that throws does not kill the reactor", () =>
        {
            // DrainPostQ wraps each callback: an unguarded throw would unwind Run() and take the
            // whole reactor with it - the #92 failure class.
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
                            throw new InvalidOperationException("posted callback blew up on the reactor thread");
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

            // Proof the callback actually RAN: otherwise this passes when it was silently dropped.
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref _explodeReached) == 1, 5_000),
                "the posted callback never reached its throw");

            for (int i = 0; i < 3; i++)
            {
                (int status, string body) = Client.Get(port, "/ping");
                Assert.Equal(200, status);
                Assert.Equal("alive", body);
            }
        });

        runner.Test("affinity: a post that races the drain is either run by it or keeps its wake", () =>
        {
            // ScheduleOnReactor enqueues, then wakes the loop only if the pending flag was clear; a
            // loop pass clears the flag, then drains. Each side is a store then a load, so each needs
            // a full fence: after a plain store the drain can read the queue empty before its clear
            // lands, the poster still reads the flag set and skips its wake, and the post waits for
            // some unrelated wake - up to a tick. Too narrow to hit through a running loop, so the two
            // halves race directly here, on a reactor that never runs, from the state a post landing
            // mid-drain leaves behind: flag set, queue empty.
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });
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
                    PendingFlag(reactor) = 1;
                    Volatile.Write(ref race.Ran, 0);
                    Interlocked.Exchange(ref race.Go, t);

                    // A random head start for the poster, so its post lands on every part of the drain.
                    int spin = 0;
                    for (int i = headStart.Next(0, 250); i > 0; i--)
                    {
                        spin += i;
                    }

                    ClearWakePending(reactor);
                    DrainPostQ(reactor);
                    while (Volatile.Read(ref race.Posted) < t) { }
                    if (Volatile.Read(ref race.Ran) == 0)
                    {
                        missed++;
                        stranded += Volatile.Read(ref PendingFlag(reactor)) == 0 ? 1 : 0;
                    }

                    DrainPostQ(reactor);   // takes the post if the racing drain left it
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

        runner.Test("affinity: handoffs from another thread share one eventfd write until the loop's next pass", () =>
        {
            // Only posts shared a wake: a buffer return, a flush, a recycle or a client op handed over
            // from another thread wrote the eventfd each, a syscall apiece for a handler that hops
            // threads. On a reactor that never runs, whose wake is an eventfd of the test's own, so the
            // counter it reads back is the number of writes.
            var reactor = new Reactor(0, new ServerConfig
            {
                ReactorCount = 1, Tcp = null, Udp = null, Incremental = new IncrementalOptions(),
            });
            InitIncremental(reactor);
            ReactorThreadId(reactor) = -1;   // every caller is another thread

            int wake = eventfd(0, 0x800);   // EFD_NONBLOCK
            Assert.True(wake > 0, "eventfd failed");
            WakeFd(reactor) = wake;
            try
            {
                var conn = (TcpConnection)RuntimeHelpers.GetUninitializedObject(typeof(TcpConnection));
                var completion = new NoCompletion();
                for (int i = 0; i < 100; i++)
                {
                    reactor.EnqueueReturnQ(0);
                    reactor.EnqueueReturnQIncremental(3, 0, 0);
                    EnqueueFlush(reactor, 3, 0);
                    EnqueueRecycle(reactor, conn);
                    reactor.SubmitRecv(3, 0, 0, completion);
                    reactor.ScheduleOnReactor(static _ => { }, null);
                }
                ulong burst = Writes(wake);

                ClearWakePending(reactor);   // what the loop's next pass does first
                reactor.EnqueueReturnQ(0);
                reactor.EnqueueReturnQ(0);
                ulong nextPass = Writes(wake);

                Assert.Equal(1UL, burst);
                Assert.Equal(1UL, nextPass);
            }
            finally
            {
                WakeFd(reactor) = 0;
                close(wake);
            }
        });
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_wakePending")]
    private static extern ref int PendingFlag(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "ClearWakePending")]
    private static extern void ClearWakePending(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "DrainPostQ")]
    private static extern void DrainPostQ(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_wakeFd")]
    private static extern ref int WakeFd(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_reactorThreadId")]
    private static extern ref int ReactorThreadId(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "InitIncremental")]
    private static extern void InitIncremental(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "EnqueueFlush")]
    private static extern void EnqueueFlush(Reactor reactor, int fd, int gen);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "EnqueueRecycle")]
    private static extern void EnqueueRecycle(Reactor reactor, TcpConnection conn);

    [DllImport("libc")] private static extern int eventfd(uint initval, int flags);
    [DllImport("libc")] private static extern unsafe long read(int fd, ulong* buf, nuint count);
    [DllImport("libc")] private static extern int close(int fd);

    // What the eventfd counted since it was last read: one per write.
    private static unsafe ulong Writes(int fd)
    {
        ulong count = 0;
        return read(fd, &count, 8) == 8 ? count : 0;
    }

    private sealed class NoCompletion : IRingCompletion
    {
        public void Complete(int result) { }
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

    // Runs `work` inside a handler and reports whether execution is on the reactor thread afterwards.
    // The comparison is against the reactor's own view (OnReactorThread), not a thread id the test
    // captured, so it stays true regardless of how the harness starts reactors.
    private static void AssertOnReactorAfter(Func<Reactor, Task> work)
    {
        int port = TestServer.Start(async (r, conn) =>
        {
            try
            {
                await conn.ReadAsync();

                string verdict;
                try
                {
                    await work(r);
                    verdict = r.OnReactorThread
                        ? "on-reactor"
                        : $"MIGRATED to thread {Environment.CurrentManagedThreadId}";
                }
                catch (Exception e)
                {
                    verdict = $"work failed: {e.Message}";
                }

                await new ReactorSwitch(r);   // the response goes out from the reactor either way
                Wire.Write(conn, 200, verdict);
                await conn.FlushAsync();
            }
            finally
            {
                conn.DecRef();
            }
        });

        (int status, string body) = Client.Get(port, "/", timeoutMs: 20_000);
        Assert.Equal(200, status);
        Assert.Equal("on-reactor", body);
    }

    // Set immediately before the throw, so the test can tell "the guard handled it" from "the
    // callback never ran at all" - which look identical from the outside.
    private static int _explodeReached;
}
