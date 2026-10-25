using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The connection's one waiter slot: every read that waits - <see cref="TcpConnection.ReadAsync"/>'s
/// own included - parks with one CompareExchange and is taken back with one Exchange, and every flush
/// signals the listener it was armed for, taken before the in-progress guard is let go.
/// </summary>
/// <remarks>
/// The races run on a reactor that never runs, with a thread of the test's own playing the reactor's
/// part, and each one asserts that the two sides actually overlapped before it trusts a clean count.
/// </remarks>
internal static unsafe class WaiterSlotTests
{
    private const int Rounds = 200_000;
    private const int MinOverlapped = 1_000;
    private static readonly byte[] One = [1];

    public static void Register(Runner runner)
    {
        runner.Test("conn: a raw read racing its recv completions leaves the reads after it working", () =>
        {
            // ReadAsync used to take its arm back without looking at the exchange's result, so a recv
            // that had already taken it delivered too - into the read's value task, after the caller had
            // been served at once and moved on. That completion raced the caller's ResetRead and next
            // read: the value task came out torn ("Operation is not valid due to the current state of
            // the object"), or the next read, parked for real, looked complete, and the one after it
            // found the arm still taken and was refused as already armed.
            Reactor reactor = NeverRunning();
            TcpConnection conn = null!;
            int broken = 0, overlapped = 0;
            Race(
                setup: _ => conn = Connection(reactor),
                here: _ =>
                {
                    int before = Volatile.Read(ref Stage);
                    try
                    {
                        ValueTask<RecvSnapshot> read = conn.ReadAsync();
                        if (Volatile.Read(ref Stage) != before)
                        {
                            overlapped++;   // a completion landed while the read was parking
                        }

                        // The caller's loop: take what each read brings, then read again.
                        for (int reads = 0; reads < 4 && read.IsCompleted; reads++)
                        {
                            RecvSnapshot snapshot = read.Result;
                            while (conn.TryGetItem(snapshot, out var item))
                            {
                            }
                            conn.ResetRead();
                            read = conn.ReadAsync();
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        broken++;
                    }
                },
                there: _ =>
                {
                    conn.Complete(1, 0, hasBuffer: false, ptr: null);
                    Interlocked.Increment(ref Stage);
                    conn.Complete(1, 0, hasBuffer: false, ptr: null);
                    Interlocked.Increment(ref Stage);
                },
                check: _ =>
                {
                    conn.MarkClosed();
                    conn.Dispose();
                });

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} recv completions landed while a read was parking: the race never ran");
            Assert.True(broken == 0, $"{broken} of {Rounds} rounds broke a read after the first: refused as already armed, or its value task torn");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("conn: ResetRead while a raw read is parked leaves the read to complete", () =>
        {
            // ReadAsync readies its value task itself now, so ResetRead has nothing left to do. It used
            // to reset that value task even with a read parked on it, throwing the read's continuation
            // away.
            TcpConnection conn = Connection(NeverRunning());
            ValueTask<RecvSnapshot> read = conn.ReadAsync();
            bool resumed = false;
            read.GetAwaiter().UnsafeOnCompleted(() => resumed = true);

            conn.ResetRead();
            conn.MarkClosed();

            Assert.True(resumed, "the parked read was never resumed after ResetRead");
            Assert.True(read.Result.IsClosed, "the parked read resumed without the close");
            conn.Dispose();
        });

        runner.Test("conn: a completion that lands while a read readies its listener is served by that read, which then lets go of the slot", () =>
        {
            // Between the claim and the park the listener readies its value task, and a completion can
            // land there - here, deterministically, a wake from inside OnParking. Nothing is parked to
            // deliver to, so it marks the claim, and the read returns at once instead of parking. Then
            // the slot is free again: the next read parks, rather than being refused as already armed,
            // and the close reaches it.
            TcpConnection conn = Connection(NeverRunning());
            var wakesWhileReadying = new WakingRecvListener(conn);

            bool served = conn.TryReadOrPark(wakesWhileReadying, out RecvSnapshot snapshot);

            Assert.True(wakesWhileReadying.Parkings == 1, $"the listener was readied {wakesWhileReadying.Parkings} times, not once");
            Assert.True(served, "the read parked with the wake that landed while it readied already spent: nothing would wake it");
            Assert.True(wakesWhileReadying.Calls == 0, $"the listener was delivered to as well, {wakesWhileReadying.Calls} times");

            var next = new CountingRecvListener();
            Assert.True(!conn.TryReadOrPark(next, out _), "the next read did not park, with nothing queued");
            conn.MarkClosed();
            Assert.True(next.Calls == 1, $"the next read was delivered to {next.Calls} times by the close, not once");
            conn.Dispose();
        });

        runner.Test("conn: two reads parking at once cannot take each other's place", () =>
        {
            // One parks and the other is refused. The one refused must not have replaced the parked
            // one's listener on its way to the refusal, or the parked one is never called.
            Reactor reactor = NeverRunning();
            TcpConnection conn = null!;
            var first = new CountingRecvListener();
            var second = new CountingRecvListener();
            Park firstPark = default, secondPark = default;
            int wrong = 0, overlapped = 0;
            Race(
                setup: _ =>
                {
                    conn = Connection(reactor);
                    first.Calls = 0;
                    second.Calls = 0;
                },
                here: _ =>
                {
                    int before = Volatile.Read(ref Stage);
                    firstPark = TryPark(conn, first);
                    if (Volatile.Read(ref Stage) != before)
                    {
                        overlapped++;   // the other park ran while this one did
                    }
                },
                there: _ =>
                {
                    secondPark = TryPark(conn, second);
                    Interlocked.Increment(ref Stage);
                },
                check: _ =>
                {
                    conn.MarkClosed();
                    bool oneParked = (firstPark == Park.Parked) != (secondPark == Park.Parked);
                    if (!oneParked
                        || first.Calls != (firstPark == Park.Parked ? 1 : 0)
                        || second.Calls != (secondPark == Park.Parked ? 1 : 0))
                    {
                        wrong++;
                    }
                    conn.Dispose();
                });

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} parks overlapped another: the race never ran");
            Assert.True(wrong == 0, $"{wrong} of {Rounds} rounds did not end with exactly the parked read called, once");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("conn: a read refused for racing a park of the same listener never readies that listener", () =>
        {
            // Two reads through one adapter - or two of ReadAsync's, whose listener is the connection -
            // share the value task the parked one's caller waits on. The one refused must not have
            // readied it on its way to the refusal: that reset throws the parked one's continuation away.
            Reactor reactor = NeverRunning();
            TcpConnection conn = null!;
            var shared = new CountingRecvListener();
            Park herePark = default, therePark = default;
            int wrong = 0, overlapped = 0;
            Race(
                setup: _ =>
                {
                    conn = Connection(reactor);
                    shared.Calls = 0;
                    shared.Parkings = 0;
                },
                here: _ =>
                {
                    int before = Volatile.Read(ref Stage);
                    herePark = TryPark(conn, shared);
                    if (Volatile.Read(ref Stage) != before)
                    {
                        overlapped++;   // the other read ran while this one did
                    }
                },
                there: _ =>
                {
                    therePark = TryPark(conn, shared);
                    Interlocked.Increment(ref Stage);
                },
                check: _ =>
                {
                    conn.MarkClosed();
                    int parked = (herePark == Park.Parked ? 1 : 0) + (therePark == Park.Parked ? 1 : 0);
                    if (parked != 1 || shared.Parkings != 1 || shared.Calls != 1)
                    {
                        wrong++;
                    }
                    conn.Dispose();
                });

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} reads overlapped another: the race never ran");
            Assert.True(wrong == 0, $"{wrong} of {Rounds} rounds did not end with one read parked, its listener readied once and called once");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("conn: two raw reads at once: the one refused leaves the parked one's value task to complete", () =>
        {
            // The same through ReadAsync itself, whose value task is the connection's own: readied once
            // per round, by the read that parked, which the close then completes.
            Reactor reactor = NeverRunning();
            TcpConnection conn = null!;
            ValueTask<RecvSnapshot> hereRead = default, thereRead = default;
            bool hereRefused = false, thereRefused = false;
            short versionBefore = 0;
            int wrong = 0, overlapped = 0;
            Race(
                setup: _ =>
                {
                    conn = Connection(reactor);
                    hereRefused = thereRefused = false;
                    versionBefore = ReadSignal(conn).Version;
                },
                here: _ =>
                {
                    int before = Volatile.Read(ref Stage);
                    try
                    {
                        hereRead = conn.ReadAsync();
                    }
                    catch (InvalidOperationException)
                    {
                        hereRefused = true;
                    }
                    if (Volatile.Read(ref Stage) != before)
                    {
                        overlapped++;
                    }
                },
                there: _ =>
                {
                    try
                    {
                        thereRead = conn.ReadAsync();
                    }
                    catch (InvalidOperationException)
                    {
                        thereRefused = true;
                    }
                    Interlocked.Increment(ref Stage);
                },
                check: _ =>
                {
                    int readied = (short)(ReadSignal(conn).Version - versionBefore);
                    ValueTask<RecvSnapshot> parked = hereRefused ? thereRead : hereRead;
                    conn.MarkClosed();
                    if (hereRefused == thereRefused || readied != 1 || !parked.IsCompleted || !parked.Result.IsClosed)
                    {
                        wrong++;
                    }
                    conn.Dispose();
                });

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} reads overlapped another: the race never ran");
            Assert.True(wrong == 0, $"{wrong} of {Rounds} rounds did not end with one read refused and the parked one, readied once, completing");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("conn: a flush that starts while the last one's completion is delivering is neither refused as armed nor signalled in its place", () =>
        {
            // CompleteFlush let go of the in-progress guard before it disarmed the flush, so a flush that
            // took the guard in between found it still armed and was refused - and had stored its own
            // listener, which the completion then signalled in place of the one it was completing.
            Reactor reactor = NeverRunning();
            TcpConnection conn = null!;
            var completing = new CountingFlushListener();
            var next = new CountingFlushListener();
            bool nextParked = false;
            int armedRefusals = 0, wrong = 0, overlapped = 0;
            Race(
                setup: _ =>
                {
                    conn = Connection(reactor);
                    completing.Calls = 0;
                    next.Calls = 0;
                    nextParked = false;
                    conn.Write(One);
                    Assert.True(!conn.TryFlushOrPark(completing), "the flush did not park");
                    Assert.True(conn.TryClaimFlush(), "the flush was not armed for the reactor to claim");
                },
                here: _ =>
                {
                    // Another writer, staging as soon as the last flush lets go.
                    int spins = 0;
                    while (true)
                    {
                        try
                        {
                            conn.Write(One);
                            break;
                        }
                        catch (InvalidOperationException) when (++spins < 10_000_000)
                        {
                            Thread.SpinWait(1);
                        }
                    }
                    if (spins > 0)
                    {
                        overlapped++;   // it waited on the release, so it met the completion
                    }

                    try
                    {
                        nextParked = !conn.TryFlushOrPark(next);
                    }
                    catch (InvalidOperationException e) when (e.Message.Contains("already armed"))
                    {
                        armedRefusals++;
                    }
                },
                there: _ => conn.CompleteFlush(),
                check: _ =>
                {
                    conn.MarkClosed();   // releases the next flush, which the kernel never had
                    DrainFlushQ(reactor);
                    if (completing.Calls != 1 || next.Calls != (nextParked ? 1 : 0))
                    {
                        wrong++;
                    }
                    conn.Dispose();
                });

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} flushes waited on the completion: the race never ran");
            Assert.True(armedRefusals == 0, $"{armedRefusals} of {Rounds} flushes were refused as already armed");
            Assert.True(wrong == 0, $"{wrong} of {Rounds} rounds signalled a flush other than the one completing, or none");
        }, skip: Environment.ProcessorCount < 2);
    }

    private enum Park { Parked, Served, Refused }

    private static Park TryPark(TcpConnection conn, CountingRecvListener listener)
    {
        try
        {
            return conn.TryReadOrPark(listener, out _) ? Park.Served : Park.Parked;
        }
        catch (InvalidOperationException)
        {
            return Park.Refused;
        }
    }

    // Bumped by whichever side runs on the other thread, so the test thread can tell it ran meanwhile.
    private static int Stage;

    /// <summary>
    /// <paramref name="here"/> on this thread against <paramref name="there"/> on a thread of the
    /// test's own, once per round, the two sides skewed differently each time; <paramref name="setup"/>
    /// before and <paramref name="check"/> after, both here, with the other side done.
    /// </summary>
    private static void Race(Action<int> setup, Action<int> here, Action<int> there, Action<int> check)
    {
        int go = 0, done = 0, skew = 0;
        Exception? fault = null;   // the other side's, which would otherwise end the process
        var other = new Thread(() =>
        {
            for (int i = 1; ; i++)
            {
                if (!WaitFor(ref go, i))
                {
                    return;
                }
                for (int s = Volatile.Read(ref skew); s > 0; s--)
                {
                    Thread.SpinWait(1);
                }
                try
                {
                    there(i);
                }
                catch (Exception e)
                {
                    fault ??= e;
                }
                Volatile.Write(ref done, i);
            }
        }) { IsBackground = true, Name = "waiter-slot-race" };
        other.Start();

        try
        {
            for (int i = 1; i <= Rounds; i++)
            {
                setup(i);
                Volatile.Write(ref skew, i / 8 * 3 % 8);
                Volatile.Write(ref go, i);
                for (int s = i * 7 % 8; s > 0; s--)
                {
                    Thread.SpinWait(1);
                }
                here(i);
                WaitFor(ref done, i);
                check(i);
            }
        }
        finally
        {
            Volatile.Write(ref go, -1);
            other.Join();
        }

        if (fault != null)
        {
            throw new Exception($"the side playing the reactor threw: {fault.GetType().Name}: {fault.Message}", fault);
        }
    }

    // Spins, so the two sides meet within nanoseconds; yields past that. False once the race is over.
    private static bool WaitFor(ref int field, int value)
    {
        for (int spins = 0; ; spins++)
        {
            int seen = Volatile.Read(ref field);
            if (seen == value)
            {
                return true;
            }
            if (seen == -1)
            {
                return false;
            }
            if (spins < 1_000)
            {
                Thread.SpinWait(1);
            }
            else
            {
                Thread.Yield();
            }
        }
    }

    private static Reactor NeverRunning() => new(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });

    // fd -1, so a flush queued to the reactor finds no table entry when it is drained.
    private static TcpConnection Connection(Reactor reactor) => new(reactor, -1, 64, 8);

    private sealed class CountingRecvListener : IRecvListener
    {
        public int Calls;
        public int Parkings;

        public void OnParking() => Interlocked.Increment(ref Parkings);

        public void OnRecvReady(RecvSnapshot snapshot) => Interlocked.Increment(ref Calls);
    }

    // Wakes the connection's read from inside OnParking: a completion landing between the claim and the park.
    private sealed class WakingRecvListener(TcpConnection conn) : IRecvListener
    {
        public int Calls;
        public int Parkings;

        public void OnParking()
        {
            Parkings++;
            conn.WakeRead();
        }

        public void OnRecvReady(RecvSnapshot snapshot) => Calls++;
    }

    private sealed class CountingFlushListener : IFlushListener
    {
        public int Calls;

        public void OnParking() { }

        public void OnFlushDone() => Interlocked.Increment(ref Calls);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "DrainFlushQ")]
    private static extern void DrainFlushQ(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_readSignal")]
    private static extern ref ManualResetValueTaskSourceCore<RecvSnapshot> ReadSignal(TcpConnection conn);
}
