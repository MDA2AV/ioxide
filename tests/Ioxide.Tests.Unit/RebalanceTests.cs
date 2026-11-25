using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Who gives connections to whom and which ones (<see cref="TcpOptions.Rebalance"/>), decided on loads and weights put there
/// by hand: the reactors never run.
/// </summary>
internal static class RebalanceTests
{
    private const int Off = 0, Weighing = 1, Giving = 2, Settling = 3;

    public static void Register(Runner runner)
    {
        runner.Test("rebalance: a busy reactor next to an idle one weighs its connections for a tick, gives for one, and settles for one", () =>
        {
            Reactor[] fleet = Fleet(100, 0);
            foreach (int expected in new[] { Weighing, Giving, Settling, Giving, Settling, Giving })
            {
                Tick(fleet[0], weight: 1_000);
                Assert.Equal(expected, BalanceOf(fleet[0]));
                Assert.True(ReferenceEquals(GiverOf(fleet[1]), expected is Giving or Settling ? fleet[0] : null),
                    $"the taker is taken from by {GiverOf(fleet[1])?.ShardIndex.ToString() ?? "nobody"} while {expected}");
            }
        });

        runner.Test("rebalance: it stops once it is busy no more, or the others are nearly as busy, and the taker is free again", () =>
        {
            foreach ((int own, int other) in new[] { (74, 0), (100, 71), (80, 80), (0, 0) })
            {
                Reactor[] fleet = Fleet(100, 0);
                Tick(fleet[0], 1_000);
                Tick(fleet[0], 1_000);
                Assert.Equal(Giving, BalanceOf(fleet[0]));
                Load(fleet[0], own);
                Load(fleet[1], other);
                Tick(fleet[0], 1_000);
                Assert.Equal(Settling, BalanceOf(fleet[0]));   // by loads read again, whatever they were a moment ago
                Tick(fleet[0], 1_000);
                Assert.Equal(Off, BalanceOf(fleet[0]));
                Assert.True(GiverOf(fleet[1]) is null && TakerOf(fleet[0]) is null, "the taker was never let go of");
            }
        });

        runner.Test("rebalance: from 75 percent on, to one 30 points below, and to nobody else", () =>
        {
            foreach ((int own, int other, bool gives) in new[]
            {
                (75, 45, true), (75, 46, false), (74, 0, false), (100, 70, true), (100, 71, false), (90, 0, true), (30, 0, false),
            })
            {
                Reactor[] fleet = Fleet(own, other);
                Tick(fleet[0], 1_000);
                Assert.True(BalanceOf(fleet[0]) == (gives ? Weighing : Off), $"at {own} next to {other}: {BalanceOf(fleet[0])}");
            }
        });

        runner.Test("rebalance: the least busy is given to, and not one that stops, is given to already, is stuck, or isn't there", () =>
        {
            Reactor[] fleet = Fleet(100, 40, 20, 30, 80);
            Assert.True(ReferenceEquals(Chosen(fleet[0]), fleet[2]), "not the least busy");

            GiverOf(fleet[2]) = fleet[4];
            Assert.True(ReferenceEquals(Chosen(fleet[0]), fleet[3]), "one that another reactor gives to");

            LoadAtOf(fleet[3]) -= 751;   // three ticks
            Assert.True(ReferenceEquals(Chosen(fleet[0]), fleet[1]), "one that hasn't said how busy it is for long");
            LoadAtOf(fleet[3]) += 751;

            fleet[3].Stop();
            Assert.True(ReferenceEquals(Chosen(fleet[0]), fleet[1]), "one that stops");

            FleetOf(fleet[0])[1] = null;
            Assert.True(Chosen(fleet[0]) is null, "one that was never there, or itself");
        });

        runner.Test("rebalance: two busy reactors give to two idle ones, and a third to nobody until one is done with", () =>
        {
            Reactor[] fleet = Fleet(100, 100, 100, 0, 10);
            for (int i = 0; i < 3; i++)
            {
                Tick(fleet[i], 1_000);
            }
            for (int i = 0; i < 3; i++)
            {
                Tick(fleet[i], 1_000);
            }
            Assert.True(ReferenceEquals(TakerOf(fleet[0]), fleet[3]) && ReferenceEquals(TakerOf(fleet[1]), fleet[4]) && TakerOf(fleet[2]) is null,
                "they give to the same one, or not to the least busy");
            Assert.Equal(Off, BalanceOf(fleet[2]));

            Tick(fleet[0], 1_000);
            Load(fleet[0], 60);
            Load(fleet[3], 50);
            Tick(fleet[0], 1_000);
            Assert.Equal(Off, BalanceOf(fleet[0]));
            Tick(fleet[2], 1_000);
            Tick(fleet[2], 1_000);
            Assert.True(ReferenceEquals(TakerOf(fleet[2]), fleet[3]), "the one done with is given to by nobody");
        });

        runner.Test("rebalance: of busy reactors that decide at the same moment, one gives to the only idle one", () =>
        {
            const int Busy = 6;
            for (int round = 0; round < 200; round++)
            {
                Reactor[] fleet = Fleet([.. Enumerable.Repeat(100, Busy), 0]);
                for (int i = 0; i < Busy; i++)
                {
                    Tick(fleet[i], 1_000);
                }
                using var together = new Barrier(Busy);
                Thread[] deciding = fleet.Take(Busy).Select(reactor => new Thread(() =>
                {
                    together.SignalAndWait();
                    Tick(reactor, 1_000);
                })).ToArray();
                foreach (Thread thread in deciding)
                {
                    thread.Start();
                }
                foreach (Thread thread in deciding)
                {
                    thread.Join();
                }
                Reactor[] givers = fleet.Take(Busy).Where(reactor => BalanceOf(reactor) == Giving).ToArray();
                Assert.True(givers.Length == 1 && ReferenceEquals(GiverOf(fleet[Busy]), givers[0]), $"{givers.Length} reactors give to it");
            }
        });

        runner.Test("rebalance: what is given is worth half the difference", () =>
        {
            foreach ((int own, int other, long weight, long budget) in new[]
            {
                (100, 0, 1_000L, 500L), (100, 50, 1_000L, 250L), (80, 40, 1_000L, 250L), (100, 70, 1_000L, 150L), (100, 0, 0L, 0L),
            })
            {
                Reactor[] fleet = Fleet(own, other);
                Tick(fleet[0], weight);
                Tick(fleet[0], weight);
                Assert.Equal(Giving, BalanceOf(fleet[0]));
                Assert.True(BudgetOf(fleet[0]) == budget, $"{BudgetOf(fleet[0])} of {weight}, at {own} next to {other}");
            }
        });

        runner.Test("rebalance: each connection is judged by what it weighed over the last whole tick, as it comes by", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(8);
            rig.Tick();
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 100);
                rig.Weigh(conn, 25);
            }
            Assert.True(conns.All(conn => conn.MoveState == TcpConnection.MoveNone), "one went while they were only weighed");
            rig.Tick();
            Assert.Equal(500L, BudgetOf(rig.Reactor));   // half of 1,000

            // A first completion that takes next to nothing says nothing of what its connection weighs.
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 1);
            }
            Assert.Equal(4, conns.Count(conn => conn.MoveState == TcpConnection.MoveCancelling));
            Assert.True(conns.Take(4).All(conn => ReferenceEquals(conn.MoveTo, rig.Other)), "not the first that came by, or not to the taker");
            Assert.Equal(0L, BudgetOf(rig.Reactor));

            // The rest stay, however often they come by.
            for (int i = 0; i < 20; i++)
            {
                rig.Weigh(conns[7], 100);
            }
            Assert.Equal(TcpConnection.MoveNone, conns[7].MoveState);
        });

        runner.Test("rebalance: of two that weigh the same one goes, and of one that has it all none", () =>
        {
            foreach ((int other, int weighs, int goes) in new[] { (0, 500, 1), (4, 500, 1), (20, 500, 0) })   // an idle one reads a little over 0
            {
                using Rig rig = new(100, other);
                TcpConnection[] two = rig.Connections(2);
                rig.Tick();
                rig.Weigh(two[0], weighs);
                rig.Weigh(two[1], weighs);
                rig.Tick();
                rig.Weigh(two[0], 1);
                rig.Weigh(two[1], 1);
                Assert.True(two.Count(conn => conn.MoveState != TcpConnection.MoveNone) == goes, $"next to one at {other}, {two.Count(conn => conn.MoveState != TcpConnection.MoveNone)} of two went");
            }

            using (Rig rig = new(100, 0))
            {
                TcpConnection[] conns = rig.Connections(3);
                rig.Tick();
                rig.Weigh(conns[0], 900);
                rig.Weigh(conns[1], 60);
                rig.Weigh(conns[2], 40);
                rig.Tick();
                foreach (TcpConnection conn in conns)
                {
                    rig.Weigh(conn, 1);
                }
                Assert.True(conns[0].MoveState == TcpConnection.MoveNone && conns[1].MoveState != TcpConnection.MoveNone && conns[2].MoveState != TcpConnection.MoveNone,
                    "the one that is the load went, or the others didn't");
            }
        });

        runner.Test("rebalance: a connection nobody has weighed stays, and so does one last weighed long ago", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(3);
            rig.Tick();
            rig.Weigh(conns[0], 100);
            rig.Weigh(conns[1], 100);
            rig.Tick();   // gives
            rig.Weigh(conns[2], 10);
            Assert.Equal(TcpConnection.MoveNone, conns[2].MoveState);
            rig.Weigh(conns[0], 10);
            Assert.Equal(TcpConnection.MoveCancelling, conns[0].MoveState);

            for (int i = 0; i < 8; i++)
            {
                rig.Tick();
                rig.Weigh(conns[2], 1_000);   // keeps it going
            }
            while (BalanceOf(rig.Reactor) != Giving)
            {
                rig.Tick();
                rig.Weigh(conns[2], 1_000);
            }
            Assert.True(BudgetOf(rig.Reactor) > 200, "there was no room for it anyway");
            rig.Weigh(conns[1], 10);   // once, a dozen ticks ago
            Assert.Equal(TcpConnection.MoveNone, conns[1].MoveState);
        });

        runner.Test("rebalance: a connection is weighed afresh on the reactor it came to", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection conn = rig.Connections(1)[0];
            rig.Tick();
            rig.Weigh(conn, 100);
            conn.LeaveFor(rig.Other);
            conn.ArriveOn(rig.Other);
            Assert.True(conn.LastWeight == 0 && conn.WeighedTick == long.MinValue, "what it weighed elsewhere came along");
        });

        runner.Test("rebalance: pinned connections, and ones that are over, stay, and the rest go for them", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(4);
            rig.Tick();
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 100);
            }
            rig.Tick();
            conns[0].Pinned = true;
            conns[1].MarkClosed();
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 1);
            }
            Assert.True(conns[0].MoveState == TcpConnection.MoveNone && conns[1].MoveState == TcpConnection.MoveNone, "a pinned one went, or one that is over");
            Assert.True(conns[2].MoveState != TcpConnection.MoveNone && conns[3].MoveState != TcpConnection.MoveNone, "the others paid for them");
        });

        runner.Test("rebalance: off by default, and for a reactor alone, or numbered out of its fleet", () =>
        {
            Assert.True(!new TcpOptions().Rebalance, "it is on by default");
            foreach ((int id, int count, bool on, bool joins) in new[] { (0, 2, true, true), (1, 2, true, true), (0, 2, false, false), (0, 1, true, false), (2, 2, true, false) })
            {
                var reactor = new Reactor(id, new ServerConfig { ReactorCount = count, Udp = null, Tcp = new TcpOptions { Rebalance = on } });
                JoinFleet(reactor);
                Assert.True(FleetOf(reactor).Contains(reactor) == joins, $"reactor {id} of {count}, Rebalance {on}");
            }
        });

        runner.Test("rebalance: a fleet is the reactors of one config, not of an equal one", () =>
        {
            ServerConfig config = new() { ReactorCount = 2, Udp = null, Tcp = new TcpOptions { Rebalance = true } };
            var a = new Reactor(0, config);
            var b = new Reactor(1, config);
            var stranger = new Reactor(1, config with { });
            foreach (Reactor reactor in new[] { a, b, stranger })
            {
                JoinFleet(reactor);
            }
            Assert.True(ReferenceEquals(FleetOf(a), FleetOf(b)) && FleetOf(a).Contains(b), "reactors of one config are strangers");
            Assert.True(!FleetOf(a).Contains(stranger), "a reactor of another config is in the fleet");
        });

        runner.Test("rebalance: a reactor that has stopped leaves its fleet, and not the one that came in its place", () =>
        {
            Reactor[] fleet = Fleet(100, 0);
            Tick(fleet[0], 1_000);
            Tick(fleet[0], 1_000);
            Assert.True(ReferenceEquals(GiverOf(fleet[1]), fleet[0]), "nothing was given, so there is nothing to let go of");
            LeaveFleet(fleet[0]);
            Assert.True(!FleetOf(fleet[1]).Contains(fleet[0]) && GiverOf(fleet[1]) is null, "it is still there, or the other is still its taker");

            var next = new Reactor(1, ConfigOf(fleet[1]));
            JoinFleet(next);
            LeaveFleet(fleet[1]);
            Assert.True(FleetOf(next).Contains(next), "the reactor that came in its place left with it");
        });
    }

    // Reactors as busy as that, in one fleet, the first of them to decide.
    private static Reactor[] Fleet(params int[] loads)
    {
        var config = new ServerConfig { ReactorCount = loads.Length, Udp = null, Tcp = new TcpOptions { Rebalance = true } };
        Reactor[] fleet = loads.Select((_, i) => new Reactor(i, config)).ToArray();
        for (int i = 0; i < loads.Length; i++)
        {
            JoinFleet(fleet[i]);
            Load(fleet[i], loads[i]);
        }
        return fleet;
    }

    private static void Load(Reactor reactor, int percent) => LoadOf(reactor) = percent;

    private static void Tick(Reactor reactor, long weight)
    {
        WeightOf(reactor) = weight;
        reactor.NowMs = Native.MonotonicMs;
        DecideBalance(reactor);
    }

    private static Reactor? Chosen(Reactor reactor)
    {
        reactor.NowMs = Native.MonotonicMs;
        return LeastLoaded(reactor);
    }

    /// <summary>A busy reactor with a ring, so its moves can begin, next to another.</summary>
    private sealed class Rig : IDisposable
    {
        private readonly Ring _ring = Ring.Create(64);
        public readonly Reactor Reactor;
        public readonly Reactor Other;

        public Rig(int own, int other)
        {
            Reactor[] fleet = Fleet(own, other);
            (Reactor, Other) = (fleet[0], fleet[1]);
            RingOf(Reactor) = _ring;
        }

        public TcpConnection[] Connections(int count) => Enumerable.Range(0, count).Select(_ =>
        {
            var conn = new TcpConnection(Reactor, -1, 64, 8);
            conn.InitRefs();
            Track(Reactor, conn);
            return conn;
        }).ToArray();

        public void Tick()
        {
            Reactor.NowMs = Native.MonotonicMs;
            LoadAtOf(Other) = Native.MonotonicMs;
            DecideBalance(Reactor);
        }

        public void Weigh(TcpConnection conn, long took) => WeighOf(Reactor, conn, took);

        public void Dispose() => _ring.Dispose();
    }

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "JoinFleet")]
    private static extern void JoinFleet(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "LeaveFleet")]
    private static extern void LeaveFleet(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_config")]
    private static extern ref readonly ServerConfig ConfigOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "DecideBalance")]
    private static extern void DecideBalance(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "LeastLoaded")]
    private static extern Reactor? LeastLoaded(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Weigh")]
    private static extern void WeighOf(Reactor reactor, TcpConnection conn, long took);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Track")]
    private static extern void Track(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_fleet")]
    private static extern ref Reactor?[] FleetOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_loadPercent")]
    private static extern ref int LoadOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_loadAtMs")]
    private static extern ref long LoadAtOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_giver")]
    private static extern ref Reactor? GiverOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_taker")]
    private static extern ref Reactor? TakerOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_budget")]
    private static extern ref long BudgetOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_weight")]
    private static extern ref long WeightOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ring")]
    private static extern ref Ring RingOf(Reactor reactor);

    private static int BalanceOf(Reactor reactor) => (int)(byte)typeof(Reactor).GetField("_balance",
        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(reactor)!;
}
