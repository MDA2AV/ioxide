using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Who gives connections to whom, and which ones (<see cref="TcpOptions.Rebalance"/>), on readings and weights put there by
/// hand: the reactors never run, and their tickers are called at the ticks a test names.
/// </summary>
internal static class RebalanceTests
{
    // A look, as a tick by the clock (NowMs / TickMs): a whole number of the fleet's interval of 2 s (8 ticks).
    private const long Look = 1_000_000;

    public static void Register(Runner runner)
    {
        RegisterPairing(runner);
        RegisterSchedule(runner);
        RegisterGiving(runner);
        RegisterReading(runner);
        RegisterFleet(runner);
    }

    private static void RegisterPairing(Runner runner)
    {
        runner.Test("rebalance: the busiest is paired with the idlest, the next busiest with the next idlest, while far enough apart", () =>
        {
            Reactor[] fleet = Fleet(99, 75, 0, 50);
            TickAt(fleet[2], Look + 1);
            Assert.True(ReferenceEquals(AssignedOf(fleet[0]), fleet[2]), "the busiest was not paired with the idlest");
            Assert.True(AssignedOf(fleet[1]) is null, "75 was paired with 50, 25 points apart");
            Assert.True(ReferenceEquals(GiverOf(fleet[2]), fleet[0]) && GiverOf(fleet[3]) is null, "the takers are not as paired");

            fleet = Fleet(100, 90, 10, 0);
            TickAt(fleet[0], Look + 1);
            Assert.True(ReferenceEquals(TakerOf(fleet[0]), fleet[3]), "100 does not give to 0");   // its own pairing, taken up in the same tick
            Assert.True(ReferenceEquals(AssignedOf(fleet[1]), fleet[2]), "90 was not paired with 10");

            fleet = Fleet(90, 100, 10, 0);   // the busiest read second
            TickAt(fleet[2], Look + 1);
            Assert.True(ReferenceEquals(AssignedOf(fleet[1]), fleet[3]) && ReferenceEquals(AssignedOf(fleet[0]), fleet[2]),
                "the reactors were paired in the order they read, not by how busy they were");
        });

        runner.Test("rebalance: a reactor already given to is not given to by another, and the next idlest is", () =>
        {
            Reactor[] fleet = Fleet(100, 0, 20);
            Reactor other = Fleet(0, 0)[0];
            GiverOf(fleet[1]) = other;   // still giving to it
            TickAt(fleet[2], Look + 1);
            Assert.True(ReferenceEquals(AssignedOf(fleet[0]), fleet[2]), "it was paired with one given to already, or with nobody");
            Assert.True(ReferenceEquals(GiverOf(fleet[1]), other), "the other giver lost its taker");
        });

        runner.Test("rebalance: a taker goes by the busier of its two ticks, so one quiet for a moment between bursts is given nothing", () =>
        {
            Reactor[] fleet = Fleet(100, 10);
            PeakOf(fleet[1]) = 90;   // busy in the first of the two ticks
            TickAt(fleet[1], Look + 1);
            Assert.True(AssignedOf(fleet[0]) is null, "one that was busy a tick before was given connections");

            fleet = Fleet(100, 10);
            PeakOf(fleet[1]) = 20;
            TickAt(fleet[1], Look + 1);
            Assert.True(ReferenceEquals(AssignedOf(fleet[0]), fleet[1]), "one quiet in both ticks was not given connections");
            Assert.Equal(80, AssignedGapOf(fleet[0]));   // by the busier of its two
        });

        runner.Test("rebalance: from 75 percent on, to one 30 points below, and to nobody else", () =>
        {
            foreach ((int own, int other, bool paired) in new[] { (74, 0, false), (75, 45, true), (75, 46, false), (100, 70, true), (100, 71, false) })
            {
                Reactor[] fleet = Fleet(own, other);
                TickAt(fleet[1], Look + 1);
                Assert.True((AssignedOf(fleet[0]) is not null) == paired, $"{own} next to {other}: paired {!paired}");
            }
        });

        runner.Test("rebalance: a reactor that didn't read for the look, or stops, is paired with nobody", () =>
        {
            Reactor[] fleet = Fleet(100, 0, 0);
            LoadLookOf(fleet[1]) = Look - 8;   // read for the look before, as one stuck since would have
            StopRequestedOf(fleet[2]) = true;
            TickAt(fleet[0], Look + 1);
            Assert.True(TakerOf(fleet[0]) is null, "it was given a taker that was stuck or stopping");

            fleet = Fleet(100, 0);
            StopRequestedOf(fleet[0]) = true;
            TickAt(fleet[1], Look + 1);
            Assert.True(AssignedOf(fleet[0]) is null, "one that stops was given a taker");
        });

        runner.Test("rebalance: one reactor pairs them all for a look: the first to get to it", () =>
        {
            Reactor[] fleet = Fleet(100, 90, 0, 10);
            TickAt(fleet[3], Look + 1);
            Assert.Equal(Look, FleetOf(fleet[0]).Paired);
            Reactor? first = AssignedOf(fleet[1]);
            Volatile.Write(ref AssignedOf(fleet[1]), null);
            TickAt(fleet[2], Look + 1);   // another reactor, the same tick
            Assert.True(AssignedOf(fleet[1]) is null && first is not null, "the look was paired twice");
        });

        runner.Test("rebalance: a busy reactor that weighed nothing for the look is left for the next, which comes soon", () =>
        {
            Reactor[] fleet = Fleet(100, 0);
            WeighedForOf(fleet[0]) = Look - 8;   // it wasn't busy at the look before, so it didn't weigh
            TickAt(fleet[1], Look + 1);
            Assert.True(AssignedOf(fleet[0]) is null, "it was paired with nothing to give by");
            Assert.Equal(Look + 4, FleetOf(fleet[0]).NextLook);
        });

        runner.Test("rebalance: a giver that gave nothing is left out until the look at the interval, and the taker is another's", () =>
        {
            Reactor[] fleet = Fleet(100, 95, 0);
            TickAt(fleet[0], Look + 1);   // pairs, and takes its own pairing up
            Assert.True(ReferenceEquals(TakerOf(fleet[0]), fleet[2]), "the busiest does not give to the idle one");
            TickAt(fleet[0], Look + 2);   // gave nothing: one connection is all its load, say
            Assert.True(TakerOf(fleet[0]) is null && GiverOf(fleet[2]) is null, "the taker was not let go of");

            long soon = FleetOf(fleet[0]).NextLook;
            Assert.Equal(Look + 4, soon);
            Read(fleet[0], 100, soon);
            Read(fleet[1], 95, soon);
            Read(fleet[2], 0, soon);
            TickAt(fleet[2], soon + 1);
            Assert.True(AssignedOf(fleet[0]) is null, "one that gave nothing was paired again before the interval");
            Assert.True(ReferenceEquals(AssignedOf(fleet[1]), fleet[2]), "the next busiest was not given the idle one");
        });
    }

    private static void RegisterSchedule(Runner runner)
    {
        runner.Test("rebalance: a look that pairs anyone has the next three ticks after it, and one that pairs nobody at the interval, by the clock", () =>
        {
            Reactor[] fleet = Fleet(100, 0);
            TickAt(fleet[1], Look + 1);
            Assert.Equal(Look + 4, FleetOf(fleet[0]).NextLook);

            fleet = Fleet(50, 40);
            TickAt(fleet[1], Look + 1);
            Assert.Equal(Look + 8, FleetOf(fleet[0]).NextLook);

            fleet = Fleet(50, 40);
            TickAt(fleet[1], Look + 7);   // late: the next is far enough on to read two ticks before it
            Assert.Equal(Look + 16, FleetOf(fleet[0]).NextLook);
        });

        runner.Test("rebalance: a reactor reads its load over the two ticks before a look, and weighs if it read busy at the one before, or over the first of the two", () =>
        {
            foreach ((int before, bool busyFirst, bool weighsFromStart, bool weighs) in new[] { (100, false, true, true), (60, false, false, false), (60, true, false, true) })
            {
                Reactor[] fleet = Fleet(0, 0);
                Reactor reactor = fleet[0];
                LoadOf(reactor) = before;
                FleetOf(reactor).NextLook = Look + 8;
                TickAt(reactor, Look + 5);
                Assert.True(!MeasuringOf(reactor) && !WeighingOf(reactor), "it measured three ticks before the look");
                TickAt(reactor, Look + 6);
                Assert.True(MeasuringOf(reactor), "it did not measure over the two ticks before the look");
                Assert.Equal(weighsFromStart, WeighingOf(reactor));
                if (busyFirst)
                {
                    long until = Native.ThreadCpuNs + 20_000_000;
                    while (Native.ThreadCpuNs < until)
                    {
                        Thread.SpinWait(100);
                    }
                }
                else
                {
                    Thread.Sleep(50);
                }
                TickAt(reactor, Look + 7);
                Assert.True(MeasuringOf(reactor) && FirstOf(reactor) >= 0, "it did not read the first of the two ticks");
                Assert.Equal(weighs, WeighingOf(reactor));
                int first = FirstOf(reactor);
                Thread.Sleep(50);   // the second tick asleep
                TickAt(reactor, Look + 8);
                Assert.True(!MeasuringOf(reactor) && !WeighingOf(reactor), "it went on measuring past the look");
                Assert.Equal(Look + 8, LoadLookOf(reactor));
                Assert.Equal(weighs ? Look + 8 : Look, WeighedForOf(reactor));
                Assert.Equal(Math.Max(first, LoadOf(reactor)), PeakOf(reactor));
                if (busyFirst)
                {
                    Assert.True(LoadOf(reactor) < 10 && first > LoadOf(reactor), $"the last tick, asleep, read {LoadOf(reactor)}%, after {first}%: the two were read as one");
                }
            }
        });

        runner.Test("rebalance: a fleet's first look is the next whole interval by the clock, the same for every reactor", () =>
        {
            var config = new ServerConfig { ReactorCount = 2, Udp = null, Tcp = new TcpOptions { Rebalance = true, RebalanceIntervalMs = 2_000 } };
            Reactor a = new(0, config), b = new(1, config);
            JoinFleet(a);
            JoinFleet(b);
            long first = FleetOf(a).NextLook;
            Assert.True(ReferenceEquals(FleetOf(a), FleetOf(b)), "two reactors of one config have two fleets");
            Assert.True(first % 8 == 0 && first > Native.MonotonicMs / Reactor.TickMs, $"the first look is at tick {first}");
        });

        runner.Test("rebalance: the interval is in whole ticks, three at the least", () =>
        {
            foreach ((int ms, int ticks) in new[] { (2_000, 8), (2_100, 8), (750, 3), (250, 3), (0, 3), (3_600_000, 14_400) })
            {
                var config = new ServerConfig { ReactorCount = 2, Udp = null, Tcp = new TcpOptions { Rebalance = true, RebalanceIntervalMs = ms } };
                Reactor reactor = new(0, config);
                JoinFleet(reactor);
                Assert.Equal(ticks, LookTicksOf(reactor));
            }
        });
    }

    private static void RegisterGiving(Runner runner)
    {
        runner.Test("rebalance: a giver gives for one tick, connections worth half the difference, and then lets the taker go", () =>
        {
            foreach ((int own, int other, long budget) in new[] { (100, 0, 500L), (100, 40, 300L), (80, 0, 500L) })
            {
                Reactor[] fleet = Fleet(own, other);
                TickAt(fleet[0], Look + 1);
                Assert.True(ReferenceEquals(TakerOf(fleet[0]), fleet[1]), "it does not give");
                Assert.Equal(budget, BudgetOf(fleet[0]));   // of the 1,000 weighed
                TickAt(fleet[0], Look + 2);
                Assert.True(TakerOf(fleet[0]) is null && GiverOf(fleet[1]) is null, "it gave for longer than a tick");
            }
        });

        runner.Test("rebalance: a pairing not taken up by the next tick but one is dropped, as its giver was stuck", () =>
        {
            Reactor[] fleet = Fleet(100, 0);
            TickAt(fleet[1], Look + 1);
            Assert.True(AssignedOf(fleet[0]) is not null, "nobody was paired");
            TickAt(fleet[0], Look + 4);
            Assert.True(TakerOf(fleet[0]) is null && AssignedOf(fleet[0]) is null && GiverOf(fleet[1]) is null, "a stale pairing was taken up");
        });

        runner.Test("rebalance: each connection is looked at once, as it first comes by, by what it weighed for the look", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(8);
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 100);
                rig.Weigh(conn, 25);
            }
            rig.Give();
            Assert.Equal(500L, BudgetOf(rig.Reactor));   // half of 1,000

            // A first completion that takes next to nothing says nothing of what its connection weighs. Half the load is to
            // go, so one in two of those that come by goes.
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 1);
            }
            Assert.Equal(4, conns.Count(conn => conn.MoveState == TcpConnection.MoveCancelling));
            Assert.True(conns.Where((_, i) => i % 2 == 0).All(conn => ReferenceEquals(conn.MoveTo, rig.Other)), "not one in two that came by, or not to the taker");
            Assert.Equal(0L, BudgetOf(rig.Reactor));

            for (int i = 0; i < 20; i++)
            {
                rig.Weigh(conns[7], 1);   // once looked at, it stays
            }
            Assert.Equal(TcpConnection.MoveNone, conns[7].MoveState);
        });

        runner.Test("rebalance: a connection passed over as it first came by is not looked at again in that tick", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(4);
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 100);
            }
            rig.Give();   // 200 of 400, one in two
            rig.Weigh(conns[0], 1);
            rig.Weigh(conns[1], 1);   // passed over: not its turn
            rig.Weigh(conns[1], 1);
            Assert.True(conns[0].MoveState == TcpConnection.MoveCancelling && conns[1].MoveState == TcpConnection.MoveNone,
                "one passed over went when it came by again");
        });

        runner.Test("rebalance: of two that weigh the same one goes, and of one that has it all none", () =>
        {
            foreach ((int other, int goes) in new[] { (0, 1), (4, 1), (20, 0) })   // an idle one reads a little over 0
            {
                using Rig rig = new(100, other);
                TcpConnection[] two = rig.Connections(2);
                rig.Weigh(two[0], 500);
                rig.Weigh(two[1], 500);
                rig.Give();
                rig.Weigh(two[0], 1);
                rig.Weigh(two[1], 1);
                Assert.True(two.Count(conn => conn.MoveState != TcpConnection.MoveNone) == goes, $"next to one at {other}, {two.Count(conn => conn.MoveState != TcpConnection.MoveNone)} of two went");
            }

            using (Rig rig = new(100, 0))
            {
                TcpConnection[] conns = rig.Connections(3);
                rig.Weigh(conns[0], 900);
                rig.Weigh(conns[1], 60);
                rig.Weigh(conns[2], 40);
                rig.Give();
                foreach (TcpConnection conn in conns)
                {
                    rig.Weigh(conn, 1);
                }
                Assert.True(conns[0].MoveState == TcpConnection.MoveNone && conns[1].MoveState != TcpConnection.MoveNone && conns[2].MoveState != TcpConnection.MoveNone,
                    "the one that is the load went, or the others didn't");
            }
        });

        runner.Test("rebalance: a connection not weighed for the look is taken for what its completion took", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(4);
            rig.Weigh(conns[0], 100);
            rig.Weigh(conns[1], 100);
            rig.Give(weight: 400);   // gives 200, one in two
            rig.Weigh(conns[2], 300);   // weighed nothing, and this one is too much
            Assert.Equal(TcpConnection.MoveNone, conns[2].MoveState);
            rig.Weigh(conns[3], 10);
            Assert.Equal(TcpConnection.MoveCancelling, conns[3].MoveState);
            Assert.Equal(190L, BudgetOf(rig.Reactor));
        });

        runner.Test("rebalance: nothing goes to a taker whose ticker has not run since", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(4);
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 100);
            }
            rig.Give();
            TickedAtOf(rig.Other) = Native.MonotonicMs - 1_000;   // stuck since
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 1);
            }
            Assert.True(conns.All(conn => conn.MoveState == TcpConnection.MoveNone), "one went to a reactor stuck in something");
        });

        runner.Test("rebalance: pinned connections, and ones that are over, stay, and the rest go for them", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection[] conns = rig.Connections(4);
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 100);
            }
            conns[0].Pinned = true;
            conns[1].MarkClosed();
            rig.Give();
            foreach (TcpConnection conn in conns)
            {
                rig.Weigh(conn, 1);
            }
            Assert.True(conns[0].MoveState == TcpConnection.MoveNone && conns[1].MoveState == TcpConnection.MoveNone, "a pinned one, or one that is over, went");
            Assert.True(conns[2].MoveState == TcpConnection.MoveCancelling || conns[3].MoveState == TcpConnection.MoveCancelling, "the others stayed for them");
        });

        runner.Test("rebalance: a connection is weighed afresh on the reactor it came to", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection conn = rig.Connections(1)[0];
            rig.Weigh(conn, 100);
            conn.LeaveFor(rig.Other);
            conn.ArriveOn(rig.Other);
            Assert.True(conn.Weight == 0 && conn.WeighedTick == long.MinValue, "what it weighed elsewhere came along");
        });
    }

    private static void RegisterReading(Runner runner)
    {
        runner.Test("rebalance: a reactor reads the share of the tick before a look its thread was on a CPU", () =>
        {
            Reactor reactor = Fleet(0, 0)[0];
            BeginMeasuring(reactor, Look);
            long until = Native.ThreadCpuNs + 50_000_000;
            while (Native.ThreadCpuNs < until)
            {
                Thread.SpinWait(100);   // on a CPU for 50 ms, however long that takes on a busy machine
            }
            ReadLoad(reactor, Look);
            int spun = LoadOf(reactor);
            BeginMeasuring(reactor, Look + 8);
            Thread.Sleep(100);
            ReadLoad(reactor, Look + 8);
            int slept = LoadOf(reactor);
            Assert.True(spun > 0 && slept < 10, $"{spun}% for a tick spent spinning, and {slept}% for one spent asleep");
            Assert.Equal(Look + 8, LoadLookOf(reactor));
        });

        runner.Test("rebalance: a reactor kept from its completions, as by a handler that blocks, reads busy though its thread is off a CPU", () =>
        {
            Reactor reactor = Fleet(0, 0)[0];
            BeginMeasuring(reactor, Look);
            Thread.Sleep(100);
            WorkedOf(reactor) = System.Diagnostics.Stopwatch.Frequency / 10;   // 100 ms, all of it outside the ring's wait
            ReadLoad(reactor, Look);
            Assert.True(LoadOf(reactor) >= 80, $"{LoadOf(reactor)}%");
        });

        runner.Test("rebalance: what a connection weighs is what its completions took in the tick before the look", () =>
        {
            using Rig rig = new(100, 0);
            TcpConnection conn = rig.Connections(1)[0];
            WeighLookOf(rig.Reactor) = Look - 8;
            rig.Weigh(conn, 300);   // for the look before
            WeighLookOf(rig.Reactor) = Look;
            rig.Weigh(conn, 100);
            rig.Weigh(conn, 50);
            Assert.True(conn.Weight == 150 && conn.WeighedTick == Look, $"{conn.Weight} for look {conn.WeighedTick}");
        });
    }

    private static void RegisterFleet(Runner runner)
    {
        runner.Test("rebalance: off by default, and for a reactor alone, or numbered out of its fleet", () =>
        {
            foreach ((ServerConfig config, int id) in new[]
            {
                (new ServerConfig { ReactorCount = 2, Udp = null, Tcp = new TcpOptions() }, 0),
                (new ServerConfig { ReactorCount = 1, Udp = null, Tcp = new TcpOptions { Rebalance = true } }, 0),
                (new ServerConfig { ReactorCount = 2, Udp = null, Tcp = new TcpOptions { Rebalance = true } }, 2),
            })
            {
                Reactor reactor = new(id, config);
                JoinFleet(reactor);
                Assert.True(FleetMembersOf(reactor).Length == 0, "it joined a fleet");
            }
            Assert.Equal(60_000, new TcpOptions().RebalanceIntervalMs);
        });

        runner.Test("rebalance: a fleet is the reactors of one config, not of an equal one", () =>
        {
            var tcp = new TcpOptions { Rebalance = true };
            var one = new ServerConfig { ReactorCount = 2, Udp = null, Tcp = tcp };
            var other = new ServerConfig { ReactorCount = 2, Udp = null, Tcp = tcp };
            Reactor a = new(0, one), b = new(0, other);
            JoinFleet(a);
            JoinFleet(b);
            Assert.True(!ReferenceEquals(FleetMembersOf(a), FleetMembersOf(b)), "two configs share a fleet");
        });

        runner.Test("rebalance: a reactor that has stopped leaves its fleet, lets its taker go, and not the one that came in its place", () =>
        {
            Reactor[] fleet = Fleet(100, 0);
            TickAt(fleet[0], Look + 1);
            Assert.True(ReferenceEquals(GiverOf(fleet[1]), fleet[0]), "nothing was paired");
            LeaveFleet(fleet[0]);
            Assert.True(GiverOf(fleet[1]) is null && !FleetMembersOf(fleet[1]).Contains(fleet[0]), "it did not leave, or kept its taker");

            var next = new Reactor(0, ConfigOf(fleet[1]));
            JoinFleet(next);
            LeaveFleet(fleet[0]);   // again: the one in its place stays
            Assert.True(FleetMembersOf(next).Contains(next), "the reactor that came in its place left with it");
        });
    }

    // Reactors of one fleet, with an interval of 2 s, that read these loads for Look and weighed 1,000 for it.
    private static Reactor[] Fleet(params int[] loads)
    {
        var config = new ServerConfig { ReactorCount = loads.Length, Udp = null, Tcp = new TcpOptions { Rebalance = true, RebalanceIntervalMs = 2_000 } };
        Reactor[] fleet = loads.Select((_, i) => new Reactor(i, config)).ToArray();
        foreach (Reactor reactor in fleet)
        {
            JoinFleet(reactor);
        }
        for (int i = 0; i < loads.Length; i++)
        {
            Read(fleet[i], loads[i], Look);
            TickedAtOf(fleet[i]) = Native.MonotonicMs;
        }
        FleetOf(fleet[0]).NextLook = Look;
        return fleet;
    }

    private static void Read(Reactor reactor, int percent, long look, long weight = 1_000)
    {
        LoadOf(reactor) = percent;
        PeakOf(reactor) = percent;
        LoadLookOf(reactor) = look;
        WeighedForOf(reactor) = look;
        WindowWeightOf(reactor) = weight;
    }

    private static void TickAt(Reactor reactor, long tick)
    {
        reactor.NowMs = tick * Reactor.TickMs;
        BalanceTick(reactor);
    }

    /// <summary>A busy reactor with a ring, so its moves can begin, next to another: weighed for Look, then giving for it.</summary>
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
            WeighLookOf(Reactor) = Look;
        }

        public TcpConnection[] Connections(int count) => Enumerable.Range(0, count).Select(_ =>
        {
            var conn = new TcpConnection(Reactor, -1, 64, 8);
            conn.InitRefs();
            Track(Reactor, conn);
            return conn;
        }).ToArray();

        public void Weigh(TcpConnection conn, long took) => WeighOf(Reactor, conn, took);

        // Paired for Look with the weight weighed for it so far, or the one given, and giving.
        public void Give(long? weight = null)
        {
            WindowWeightOf(Reactor) = weight ?? WeightOf(Reactor);
            TickedAtOf(Other) = Native.MonotonicMs;
            TickAt(Reactor, Look + 1);
            Assert.True(ReferenceEquals(TakerOf(Reactor), Other), "the rig's reactor does not give");
            Reactor.NowMs = Native.MonotonicMs;   // the clock the giving goes by
        }

        public void Dispose() => _ring.Dispose();
    }

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "JoinFleet")]
    private static extern void JoinFleet(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "LeaveFleet")]
    private static extern void LeaveFleet(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "BalanceTick")]
    private static extern void BalanceTick(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "BeginMeasuring")]
    private static extern void BeginMeasuring(Reactor reactor, long look);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "ReadLoad")]
    private static extern void ReadLoad(Reactor reactor, long look);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Weigh")]
    private static extern void WeighOf(Reactor reactor, TcpConnection conn, long took);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Track")]
    private static extern void Track(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_config")]
    private static extern ref readonly ServerConfig ConfigOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_fleetOf")]
    private static extern ref Reactor.Fleet? FleetField(Reactor reactor);

    private static Reactor.Fleet FleetOf(Reactor reactor) => FleetField(reactor)!;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_fleet")]
    private static extern ref Reactor?[] FleetMembersOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_lookTicks")]
    private static extern ref int LookTicksOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_loadPercent")]
    private static extern ref int LoadOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_loadPeak")]
    private static extern ref int PeakOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_firstPercent")]
    private static extern ref int FirstOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_assignedGap")]
    private static extern ref int AssignedGapOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_loadLook")]
    private static extern ref long LoadLookOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_tickedAtMs")]
    private static extern ref long TickedAtOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_measuring")]
    private static extern ref bool MeasuringOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_weighing")]
    private static extern ref bool WeighingOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_worked")]
    private static extern ref long WorkedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_weighLook")]
    private static extern ref long WeighLookOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_weight")]
    private static extern ref long WeightOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_windowWeight")]
    private static extern ref long WindowWeightOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_weighedFor")]
    private static extern ref long WeighedForOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_assigned")]
    private static extern ref Reactor? AssignedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_giver")]
    private static extern ref Reactor? GiverOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_taker")]
    private static extern ref Reactor? TakerOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_budget")]
    private static extern ref long BudgetOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_stopRequested")]
    private static extern ref bool StopRequestedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ring")]
    private static extern ref Ring RingOf(Reactor reactor);
}
