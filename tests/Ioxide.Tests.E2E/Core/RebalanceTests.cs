using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TcpOptions.Rebalance"/> under load of its own making: every client's connection on one reactor, whose handler
/// keeps it busy, next to one with nothing to do.
/// </summary>
internal static class RebalanceTests
{
    // Of a reactor's time per message: some clients at once keep it busy all the time.
    private const int WorkUs = 400;

    // Long after it would have happened: two or three ticks of 250 ms.
    private const int LongEnoughMs = 2_500;

    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            runner.Test($"rebalance: a busy reactor gives connections to an idle one, and all are served right throughout ({mode})", () =>
            {
                using var fleet = new MoveFleet(2, Work, On(config()));
                (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
                using var load = new Load(all.Select(pair => pair.Client));

                AwaitGiven(fleet.A, () => Moves.LiveOn(fleet.B) >= 2,
                    () => $"reactor A has {Moves.LiveOn(fleet.A)} of 8 connections and B {Moves.LiveOn(fleet.B)} after 20 s");
                load.AssertRuns();
                Assert.True(SpinWait.SpinUntil(() => load.ServedBy(1) > 100 && load.ServedBy(0) > 100, 20_000),
                    $"{load.ServedBy(0)} messages were answered by A and {load.ServedBy(1)} by B");
                Assert.True(Moves.LiveOn(fleet.A) >= 2, "A gave nearly all it had");
            }, skip);
        }

        runner.Test("rebalance: without the option nothing moves", () =>
        {
            using var fleet = new MoveFleet(2, Work);
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
            using var load = new Load(all.Select(pair => pair.Client));
            Thread.Sleep(LongEnoughMs);
            load.AssertRuns();
            Assert.Equal(0L, fleet.B.ConnectionsTaken);
            Assert.Equal(0L, load.ServedBy(1));
        });

        runner.Test("rebalance: a connection that alone keeps its reactor busy stays", () =>
        {
            using var fleet = new MoveFleet(2, conn => Work(conn, 5 * WorkUs), On());
            (Socket client, TcpConnection _) = fleet.Connect();
            using var load = new Load([client]);
            Thread.Sleep(LongEnoughMs);
            load.AssertRuns();
            Assert.Equal(0L, fleet.A.ConnectionsGiven);
        });

        runner.Test("rebalance: connections that are silent stay where they are", () =>
        {
            using var fleet = new MoveFleet(2, Work, On());
            (Socket Client, TcpConnection Conn)[] silent = Enumerable.Range(0, 30).Select(_ => fleet.Connect()).ToArray();
            (Socket Client, TcpConnection Conn)[] busy = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
            using var load = new Load(busy.Select(pair => pair.Client));
            AwaitGiven(fleet.A, () => fleet.B.ConnectionsTaken >= 2, () => "nothing was given");
            Thread.Sleep(LongEnoughMs);
            load.AssertRuns();
            Assert.True(silent.All(pair => ReferenceEquals(pair.Conn.Reactor, fleet.A)), "a connection that never said anything was given away");
        });

        runner.Test("rebalance: pinned connections stay, and the others go", () =>
        {
            using var fleet = new MoveFleet(2, Work, On());
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
            foreach ((Socket _, TcpConnection conn) in all.Take(4))
            {
                conn.Pinned = true;
            }
            using var load = new Load(all.Select(pair => pair.Client));
            AwaitGiven(fleet.A, () => fleet.B.ConnectionsTaken >= 2, () => "nothing was given");
            Thread.Sleep(LongEnoughMs);
            load.AssertRuns();
            Assert.True(all.Take(4).All(pair => ReferenceEquals(pair.Conn.Reactor, fleet.A)), "a pinned connection was given away");
        });

        runner.Test("rebalance: a reactor stuck in a handler is given nothing, however little it was doing before", () =>
        {
            using var fleet = new MoveFleet(3, Work, On());
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
            using Moves.Held stuck = Moves.Hold(fleet.B);
            Thread.Sleep(1_000);   // long enough for its last reading to be an old one
            using var load = new Load(all.Select(pair => pair.Client));
            AwaitGiven(fleet.A, () => fleet.Reactors[2].ConnectionsTaken >= 2, () => "nothing was given to the idle one");
            Thread.Sleep(LongEnoughMs);
            Assert.True(all.All(pair => !ReferenceEquals(pair.Conn.Reactor, fleet.B) && Moves.StateOf(pair.Conn) != Moves.Given), "the stuck one was given a connection");
            load.AssertRuns();
        });

        runner.Test("rebalance: a reactor kept from its completions by a handler that blocks is given nothing, though its thread is off a CPU", () =>
        {
            using var fleet = new MoveFleet(2, conn => conn.Reactor.ShardIndex == 1 ? Block(conn) : Work(conn), On());
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
            (Socket blocked, TcpConnection _) = fleet.Connect(fleet.B);
            using var load = new Load(all.Select(pair => pair.Client).Append(blocked));
            Thread.Sleep(2 * LongEnoughMs);
            load.AssertRuns();
            Assert.Equal(0L, fleet.B.ConnectionsTaken);
        });

        runner.Test("rebalance: once the load is even nothing moves any more", () =>
        {
            using var fleet = new MoveFleet(2, Work, On());
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(i => fleet.Connect(fleet.Reactors[i % 2])).ToArray();
            using var load = new Load(all.Select(pair => pair.Client));
            Thread.Sleep(2 * LongEnoughMs);
            load.AssertRuns();
            long moved = fleet.A.ConnectionsGiven + fleet.B.ConnectionsGiven;
            Assert.True(moved <= 4, $"{moved} connections moved between reactors equally busy");
        });

        runner.Test("rebalance: reactors that stop while one gives to the other all end", () =>
        {
            using var fleet = new MoveFleet(2, Work, On());
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 8).Select(_ => fleet.Connect()).ToArray();
            using (var load = new Load(all.Select(pair => pair.Client)))
            {
                AwaitGiven(fleet.A, () => fleet.B.ConnectionsTaken >= 1, () => "nothing was given");
                foreach (Reactor reactor in fleet.Reactors)
                {
                    reactor.Stop();
                }
                foreach (Thread thread in fleet.Threads)
                {
                    Assert.True(thread.Join(5_000), "a stop never ended");
                }
                load.Ended();
            }
            Assert.Equal(0, Moves.LiveOn(fleet.A));
            Assert.Equal(0, Moves.LiveOn(fleet.B));
        });
    }

    // Waits for what the balance is to bring about. A reactor that never reads 75% of a CPU, its share on a machine busy with
    // other things, has nothing to balance by: the test is skipped rather than failed.
    private static void AwaitGiven(Reactor giver, Func<bool> done, Func<string> what)
    {
        int busiest = 0;
        if (SpinWait.SpinUntil(() =>
        {
            busiest = Math.Max(busiest, Volatile.Read(ref LoadOf(giver)));
            return done();
        }, 20_000))
        {
            return;
        }
        if (busiest < 75)
        {
            throw new SkipException($"reactor {giver.ShardIndex} read {busiest}% of a CPU at most, short of the 75% from which it gives");
        }
        Assert.True(false, what());
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_loadPercent")]
    private static extern ref int LoadOf(Reactor reactor);

    private static ServerConfig On(ServerConfig? config = null)
    {
        config ??= MoveFleet.Shared();
        return config with { Tcp = config.Tcp! with { Rebalance = true, RebalanceIntervalMs = 750 } };   // a look every three ticks
    }

    private static Task Work(TcpConnection conn) => Work(conn, WorkUs);

    // Answers each line as Work does, after keeping its reactor's thread asleep for 100 ms.
    private static async Task Block(TcpConnection conn)
    {
        string pending = "";
        try
        {
            for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
            {
                pending += got;
                for (int end; (end = pending.IndexOf('\n') + 1) > 0; pending = pending[end..])
                {
                    Thread.Sleep(100);
                    conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{pending[..end]}"));
                }
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Answers each line with the digit of the reactor it runs on and the line itself, after keeping that reactor busy for a while.
    private static async Task Work(TcpConnection conn, int forUs)
    {
        string pending = "";
        try
        {
            for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
            {
                pending += got;
                for (int end; (end = pending.IndexOf('\n') + 1) > 0; pending = pending[end..])
                {
                    long until = Stopwatch.GetTimestamp() + (Stopwatch.Frequency * forUs / 1_000_000);
                    while (Stopwatch.GetTimestamp() < until)
                    {
                        Thread.SpinWait(20);
                    }
                    conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{pending[..end]}"));
                }
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    /// <summary>Clients that each send a message, wait for the answer and check it, over and over until disposed.</summary>
    private sealed class Load : IDisposable
    {
        private readonly Thread[] _threads;
        private readonly long[] _servedBy = new long[10];
        private volatile bool _over;
        private volatile Exception? _failure;

        public Load(IEnumerable<Socket> clients)
        {
            _threads = clients.Select((client, i) => new Thread(() =>
            {
                try
                {
                    for (int n = 0; !_over; n++)
                    {
                        string message = $"client {i} message {n}\n";
                        string answer = MoveFleet.Exchange(client, message);
                        Assert.Equal(message, answer[1..]);
                        Interlocked.Increment(ref _servedBy[answer[0] - '0']);
                    }
                }
                catch (Exception e)
                {
                    _failure ??= e;
                }
            }) { IsBackground = true, Name = $"test-load-{i}" }).ToArray();
            foreach (Thread thread in _threads)
            {
                thread.Start();
            }
        }

        public long ServedBy(int reactor) => Interlocked.Read(ref _servedBy[reactor]);

        public void AssertRuns() => Assert.True(_failure is null, $"a client failed: {_failure?.Message}");

        /// <summary>Waits for every client to have hit the end of its connection.</summary>
        public void Ended()
        {
            foreach (Thread thread in _threads)
            {
                Assert.True(thread.Join(15_000), "a client was left without an answer or an end");
            }
        }

        public void Dispose()
        {
            _over = true;
            foreach (Thread thread in _threads)
            {
                thread.Join(15_000);
            }
        }
    }
}
