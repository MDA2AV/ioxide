using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The pipe adapters park on the connection itself - <see cref="IRecvListener"/> and
/// <see cref="IFlushListener"/> - instead of on its value tasks, so the connection's arm protocol now
/// has to deliver exactly once on its own. Before, a delivery that raced the arm landed in a
/// value-task source nobody had registered on and went nowhere; with the adapter called directly,
/// that same delivery runs it a second time.
/// </summary>
/// <remarks>
/// Each test races an arm made off the reactor against a close made on it, the shape a handler that
/// hops threads produces. The "reactor" is a thread of the test's own on a reactor that never runs,
/// which plays its part: it closes, and drains the queued flushes, whose fd -1 finds no table entry,
/// as a closed connection's does. The window is a few instructions wide, so every test also asserts
/// that closes landed inside it before trusting a clean count.
/// </remarks>
internal static class AdapterParkTests
{
    private const int Rounds = 200_000;

    // Of the rounds, how many must have had the close complete while the arm was still running.
    private const int MinOverlapped = 1_000;

    public static void Register(Runner runner)
    {
        runner.Test("park: a read an adapter parks is delivered exactly once when a close races its arming", () =>
        {
            var listener = new CountingRecvListener();
            (int lost, int twice, int overlapped) = Race(
                static (conn, state) =>
                {
                    var l = (CountingRecvListener)state!;
                    Volatile.Write(ref l.Calls, 0);
                    return conn.TryReadOrPark(l, out _) ? 1 : 0;
                },
                static state => Volatile.Read(ref ((CountingRecvListener)state!).Calls),
                listener);

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} closes landed while a read was arming: the race never ran");
            Assert.True(lost == 0, $"{lost} of {Rounds} parked reads were never delivered");
            Assert.True(twice == 0, $"{twice} of {Rounds} parked reads were delivered twice");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("park: a flush an adapter parks is delivered exactly once when a close races its arming", () =>
        {
            var listener = new CountingFlushListener();
            (int lost, int twice, int overlapped) = Race(
                static (conn, state) =>
                {
                    var l = (CountingFlushListener)state!;
                    Volatile.Write(ref l.Calls, 0);
                    conn.Write(One);
                    return conn.TryFlushOrPark(l) ? 1 : 0;
                },
                static state => Volatile.Read(ref ((CountingFlushListener)state!).Calls),
                listener);

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} closes landed while a flush was arming: the race never ran");
            Assert.True(lost == 0, $"{lost} of {Rounds} parked flushes were never delivered");
            Assert.True(twice == 0, $"{twice} of {Rounds} parked flushes were delivered twice");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("pipereader: a read from off the reactor that races the connection's close completes", () =>
        {
            // The reader has to have its own value task ready before it parks: off the reactor, the
            // close can complete the park before ReadAsync has returned.
            var reads = new ValueTask<ReadResult>[1];
            (int lost, _, int overlapped) = Race(
                static (conn, state) =>
                {
                    ((ValueTask<ReadResult>[])state!)[0] = new TcpConnectionPipeReader(conn).ReadAsync();
                    return 0;
                },
                static state =>
                {
                    ValueTask<ReadResult> read = ((ValueTask<ReadResult>[])state!)[0];
                    return read.IsCompleted && read.Result.IsCompleted ? 1 : 0;
                },
                reads);

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} closes landed while a read was arming: the race never ran");
            Assert.True(lost == 0, $"{lost} of {Rounds} reads never completed, or completed without the close, after it raced their arming");
        }, skip: Environment.ProcessorCount < 2);

        runner.Test("pipewriter: a flush from off the reactor that races the connection's close completes", () =>
        {
            var flushes = new ValueTask<FlushResult>[1];
            (int lost, _, int overlapped) = Race(
                static (conn, state) =>
                {
                    conn.Write(One);
                    ((ValueTask<FlushResult>[])state!)[0] = new TcpConnectionPipeWriter(conn).FlushAsync();
                    return 0;
                },
                static state =>
                {
                    ValueTask<FlushResult> flush = ((ValueTask<FlushResult>[])state!)[0];
                    return flush.IsCompleted && flush.Result.IsCompleted ? 1 : 0;
                },
                flushes);

            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} closes landed while a flush was arming: the race never ran");
            Assert.True(lost == 0, $"{lost} of {Rounds} flushes never completed, or completed without the close, after it raced their arming");
        }, skip: Environment.ProcessorCount < 2);
    }

    private static readonly byte[] One = [1];

    /// <summary>
    /// <paramref name="arm"/> on this thread against a close on the "reactor" thread, once per round,
    /// with the two sides skewed differently each time. <paramref name="arm"/> returns the deliveries
    /// it made itself and <paramref name="delivered"/> the ones the close made, read once both sides
    /// are done: a round that adds up to 0 is lost, one past 1 is twice.
    /// </summary>
    private static (int Lost, int Twice, int Overlapped) Race(
        Func<TcpConnection, object?, int> arm, Func<object?, int> delivered, object? state)
    {
        var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });
        var side = new CloseSide(reactor);
        var thread = new Thread(side.Run) { IsBackground = true, Name = "park-race-reactor" };
        thread.Start();
        side.WaitStarted();

        int lost = 0, twice = 0, overlapped = 0;
        try
        {
            for (int i = 1; i <= Rounds; i++)
            {
                var conn = new TcpConnection(reactor, -1, 64, 8);
                side.Conn = conn;
                side.Skew = i / 8 * 3 % 8;
                Volatile.Write(ref side.Go, i);
                for (int s = i * 7 % 8; s > 0; s--)
                {
                    Thread.SpinWait(1);
                }

                bool closedBefore = Volatile.Read(ref side.Closed) == i;
                int deliveries = arm(conn, state);
                if (!closedBefore && Volatile.Read(ref side.Closed) == i)
                {
                    overlapped++;   // the close completed while the arm was running
                }
                CloseSide.WaitFor(ref side.Closed, i);

                deliveries += delivered(state);
                if (deliveries == 0)
                {
                    lost++;
                }
                else if (deliveries > 1)
                {
                    twice++;
                }
                conn.Dispose();
            }
        }
        finally
        {
            Volatile.Write(ref side.Go, -1);
            thread.Join();
        }

        return (lost, twice, overlapped);
    }

    // The reactor's part: a close per round, and the drain of the flushes queued to it meanwhile.
    private sealed class CloseSide(Reactor reactor)
    {
        public TcpConnection? Conn;
        public int Go, Closed, Skew;
        private int _started;

        public void Run()
        {
            ReactorThreadId(reactor) = Environment.CurrentManagedThreadId;   // the arms are off it
            Volatile.Write(ref _started, 1);

            for (int i = 1; ; i++)
            {
                if (!WaitFor(ref Go, i))
                {
                    return;
                }
                for (int s = Skew; s > 0; s--)
                {
                    Thread.SpinWait(1);
                }

                Conn!.MarkClosed();
                DrainFlushQ(reactor);
                Volatile.Write(ref Closed, i);
            }
        }

        public void WaitStarted() => WaitFor(ref _started, 1);

        // Spins, so the two sides meet within nanoseconds; yields past that, so a busy machine still
        // gets through. False when the round counter is -1: the race is over.
        public static bool WaitFor(ref int field, int value)
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
    }

    private sealed class CountingRecvListener : IRecvListener
    {
        public int Calls;

        public void OnRecvReady(RecvSnapshot snapshot) => Interlocked.Increment(ref Calls);
    }

    private sealed class CountingFlushListener : IFlushListener
    {
        public int Calls;

        public void OnFlushDone() => Interlocked.Increment(ref Calls);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_reactorThreadId")]
    private static extern ref int ReactorThreadId(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "DrainFlushQ")]
    private static extern void DrainFlushQ(Reactor reactor);
}
