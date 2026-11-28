using System.Diagnostics;
using System.Runtime.CompilerServices;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// Which connections move, and where (<see cref="TcpOptions.Rebalance"/>). The kernel spreads connections over the
/// reactors as they connect, knowing nothing of what each will ask for, so some reactors can end up with all the busy ones.
/// </summary>
/// <remarks>
/// The reactors of one <see cref="ServerConfig"/> look at their loads together, every
/// <see cref="TcpOptions.RebalanceIntervalMs"/>, at the same moments by the clock. Over each of the two ticks before a look
/// each one reads how busy it is: the share of the tick its thread spent on a CPU, or kept from waiting for completions if
/// that is more. One that read busy at the last look also weighs its connections meanwhile, by the time their recv
/// completions take. Once every reading is in, the first reactor to get to it pairs the busiest, by its last tick, with the
/// idlest, by the busier of its two, so not one quiet for a moment between bursts; then the next busiest with the next
/// idlest, and so on, for as long as the one is busy and the other at least 30 points less so. Each giver then gives its
/// taker, for a tick, connections worth half the difference, each as it next completes a recv. While a look pairs anyone
/// the next comes three ticks later, as one round leaves the next one to do; otherwise at the interval.
/// </remarks>
public sealed unsafe partial class Reactor
{
    /// <summary>The share of a tick on a CPU, in percent, from which a reactor gives connections away.</summary>
    private const int BusyPercent = 75;

    /// <summary>How far below that share, in points, one has to be to be given them.</summary>
    private const int GapPercent = 30;

    /// <summary>A taker whose last tick is older is stuck in something: nothing more is given to it.</summary>
    private const int LoadStaleMs = 2 * TickMs;

    /// <summary>
    /// From a look that pairs reactors to the next: the tick its givers give in, and two more, which the next look reads the
    /// loads over.
    /// </summary>
    private const int RoundTicks = 3;

    /// <summary>A look reads the two ticks before it; with the look's own, an interval is three ticks at the least.</summary>
    private const int ReadTicks = 2;

    // The reactors sharing one ServerConfig, by ShardIndex, as QuicFleets has them, and when they next look together.
    internal sealed class Fleet(int size)
    {
        public readonly Reactor?[] Members = new Reactor?[size];

        /// <summary>The tick, by the clock (NowMs / TickMs), whose reading the next look goes by. Its members read their loads over the tick before.</summary>
        public long NextLook = long.MaxValue;

        /// <summary>The last look whose pairs are made: by one reactor, the first to get to it.</summary>
        public long Paired = long.MinValue;
    }

    private static readonly ConditionalWeakTable<ServerConfig, Fleet> Fleets = new();
    private Fleet? _fleetOf;
    private Reactor?[] _fleet = [];   // its members, for ReturnLate too
    private int _lookTicks;           // TcpOptions.RebalanceIntervalMs, in ticks

    // Its reading for a look: how busy it was over the last tick before it, and over the busier of the two.
    private int _loadPercent;
    private int _loadPeak;
    private int _firstPercent = -1;           // of the first of the two, while it reads the second
    private long _loadLook = long.MinValue;   // which look
    private long _loadCpuNs;
    private long _loadTimestamp;
    private long _tickedAtMs;                 // when its ticker last ran, whatever it did

    // Over the ticks before a look: its passes are timed, and its receives weighed if it read busy at the look before, or
    // over the first of the two ticks.
    private bool _measuring;
    private bool _weighWindow;
    private long _worked;                     // outside the ring's wait, in Stopwatch ticks
    private long _passFrom;

    // Whether the loop times receives and charges them to their connections (DispatchWeighed): while weighing, and while giving.
    private bool _weighing;
    private long _weighLook;                  // the look the weights being taken are for
    private long _weight;                     // of its receives so far, for that look
    private long _windowWeight;               // of its receives over the tick of the last look it weighed for
    private long _weighedFor = long.MinValue; // that look

    private Reactor? _assigned;               // a taker a look paired it with, not taken up yet
    private int _assignedGap;
    private long _assignedLook;
    private Reactor? _taker;                  // given to, for the tick after it took the pairing up
    private Reactor? _giver;                  // the one giving to this reactor
    private long _givingLook;
    private long _budget;                     // of weight, what may still be given to _taker
    private double _share;                    // of the connections that come by, the one in so many that goes
    private double _credit;                   // towards the next of them
    private bool _gave;
    private long _restUntil = long.MinValue;  // a giver that could give nothing isn't paired before this look
    private Reactor[]? _pairing;              // scratch

    // Before the loop, once the reactor is all there to be given connections.
    private void JoinFleet()
    {
        if (!_tcp.Rebalance || ShardCount <= 1 || (uint)_id >= (uint)ShardCount)
        {
            return;
        }

        _lookTicks = Math.Max(ReadTicks + 1, _tcp.RebalanceIntervalMs / TickMs);
        _fleetOf = Fleets.GetValue(_config, static config => new Fleet(config.ReactorCount));
        _fleet = _fleetOf.Members;
        Volatile.Write(ref _fleet[_id], this);

        // The first look of a fleet: at the next whole interval by the clock, which every member finds the same.
        Interlocked.CompareExchange(ref _fleetOf.NextLook, NextRegularLook(Native.MonotonicMs / TickMs), long.MaxValue);
        AddTicker(BalanceTick);
    }

    // For good: the config can outlive its reactors, and have others after them. Moves under way end here, and what they
    // had reserved on other reactors goes back.
    private void LeaveFleet()
    {
        ReleaseTaker();
        Volatile.Write(ref _assigned, null);
        foreach (TcpConnection? conn in _slots.AsSpan(0, _slotsUsed))
        {
            if (conn is not null)
            {
                EndMove(conn);
            }
        }
        if (_fleet.Length > 0)
        {
            Interlocked.CompareExchange(ref _fleet[_id], null, this);
        }
    }

    // The first whole interval by the clock far enough on to read the two ticks before it.
    private long NextRegularLook(long now) => (now + ReadTicks + 1 + _lookTicks - 1) / _lookTicks * _lookTicks;

    private void BalanceTick()
    {
        Fleet fleet = _fleetOf!;
        long now = NowMs / TickMs;
        Volatile.Write(ref _tickedAtMs, NowMs);

        long look = Volatile.Read(ref fleet.NextLook);
        if (now >= look - ReadTicks && now < look && !_measuring)
        {
            BeginMeasuring(look);
        }
        else if (now == look - 1 && _measuring && _firstPercent < 0)
        {
            _firstPercent = Reading();   // the first of the two ticks
            StartReading();
            if (!_weighWindow && _firstPercent >= BusyPercent && !_stopRequested)
            {
                _weighWindow = true;   // busy since the look before: its weights are for the second tick alone
                _weight = 0;
            }
        }
        else if (now >= look && _measuring)
        {
            ReadLoad(look);
        }

        // Once everyone has read for it: the first one here pairs them all.
        long paired = Volatile.Read(ref fleet.Paired);
        if (now > look && paired < look && Interlocked.CompareExchange(ref fleet.Paired, look, paired) == paired)
        {
            Pair(fleet, look, now);
        }

        if (_taker is not null)
        {
            EndGiving(now);
        }
        else if (Volatile.Read(ref _assigned) is { } taker)
        {
            BeginGiving(taker, now);
        }

        _weighing = (_measuring && _weighWindow) || _taker is not null;
    }

    private void BeginMeasuring(long look)
    {
        _measuring = true;
        _firstPercent = -1;
        _weighWindow = _loadPercent >= BusyPercent && !_stopRequested;
        _weighLook = look;
        _weight = 0;
        StartReading();
        _passFrom = _loadTimestamp;
    }

    private void StartReading()
    {
        _loadCpuNs = Native.ThreadCpuNs;
        _loadTimestamp = Stopwatch.GetTimestamp();
        _worked = 0;
    }

    // Since StartReading: the share on a CPU, or outside the ring's wait if more.
    private int Reading()
    {
        double wall = Stopwatch.GetElapsedTime(_loadTimestamp).TotalNanoseconds;
        double busy = Math.Max(Native.ThreadCpuNs - _loadCpuNs, _worked * (1e9 / Stopwatch.Frequency));
        return (int)Math.Min(100, 100 * busy / Math.Max(1, wall));
    }

    private void ReadLoad(long look)
    {
        int last = Reading();
        _measuring = false;
        if (_weighWindow)
        {
            _windowWeight = _weight;
            _weighedFor = look;
        }
        Volatile.Write(ref _loadPercent, last);
        Volatile.Write(ref _loadPeak, Math.Max(last, _firstPercent));
        Volatile.Write(ref _loadLook, look);   // last: whoever sees it sees the reading
    }

    // Busiest with idlest, while one is busy and the other far enough below, by readings of the same ticks: givers by their
    // last tick, takers by the busier of their two. A busy one that weighed nothing (it wasn't busy at the look before) is
    // left for the next look, which comes soon.
    private void Pair(Fleet fleet, long look, long now)
    {
        int size = fleet.Members.Length;
        Reactor[] givers = _pairing ??= new Reactor[2 * size];
        int giving = 0, taking = 0;
        foreach (Reactor? reactor in fleet.Members)
        {
            if (reactor is not null && !reactor._stopRequested && Volatile.Read(ref reactor._loadLook) == look)
            {
                if (reactor._loadPercent >= BusyPercent)
                {
                    givers[giving++] = reactor;
                }
                if (reactor._loadPeak + GapPercent <= 100)
                {
                    givers[size + taking++] = reactor;
                }
            }
        }
        Sort(givers.AsSpan(0, giving), static (a, b) => b._loadPercent - a._loadPercent);   // busiest first
        Span<Reactor> takers = givers.AsSpan(size, taking);
        Sort(takers, static (a, b) => a._loadPeak - b._loadPeak);                            // idlest first

        bool soon = false;
        int next = 0;
        for (int i = 0; i < giving && next < taking; i++)
        {
            Reactor giver = givers[i], taker = takers[next];
            int gap = giver._loadPercent - taker._loadPeak;
            if (gap < GapPercent)
            {
                break;
            }
            if (Volatile.Read(ref giver._restUntil) > look)
            {
                continue;   // the next busiest, to the same idle one
            }
            if (Volatile.Read(ref taker._giver) is not null)
            {
                next++;
                i--;
                continue;
            }
            soon = true;
            if (Volatile.Read(ref giver._weighedFor) != look)
            {
                continue;   // it weighs at the next look
            }

            Volatile.Write(ref taker._giver, giver);
            giver._assignedGap = gap;
            giver._assignedLook = look;
            Volatile.Write(ref giver._assigned, taker);
            next++;
        }

        Volatile.Write(ref fleet.NextLook, soon ? now + RoundTicks : NextRegularLook(now));
    }

    // Insertion: a fleet is a few reactors.
    private static void Sort(Span<Reactor> reactors, Comparison<Reactor> order)
    {
        for (int i = 1; i < reactors.Length; i++)
        {
            Reactor reactor = reactors[i];
            int j = i - 1;
            for (; j >= 0 && order(reactors[j], reactor) > 0; j--)
            {
                reactors[j + 1] = reactors[j];
            }
            reactors[j + 1] = reactor;
        }
    }

    private void BeginGiving(Reactor taker, long now)
    {
        Volatile.Write(ref _assigned, null);
        if (_stopRequested || now > _assignedLook + 2)   // stuck past its round, or stopping: it isn't its any more
        {
            Volatile.Write(ref taker._giver, null);
            return;
        }

        _taker = taker;
        _givingLook = _assignedLook;
        _budget = _windowWeight * _assignedGap / (2 * Math.Max(1, _loadPercent));
        _share = _assignedGap / (2.0 * Math.Max(1, _loadPercent));
        _credit = 0.5;
        _gave = false;
    }

    // A tick of giving is over. One that could give nothing (one connection is all its load, or pinned ones are) isn't
    // paired again before the next look at the interval, so the taker is the others'.
    private void EndGiving(long now)
    {
        if (!_gave)
        {
            Volatile.Write(ref _restUntil, NextRegularLook(now));
        }
        ReleaseTaker();
    }

    private void ReleaseTaker()
    {
        if (_taker is { } taker)
        {
            _taker = null;
            Volatile.Write(ref taker._giver, null);
        }
    }

    // A completion while weighing or giving: dispatched as any other, and a receive timed, its handler's part included, and
    // charged to its connection. Otherwise the loop calls the dispatchers directly, which weigh nothing.
    private void DispatchWeighed(in IoUringCqe cqe)
    {
        if ((byte)(cqe.user_data >> KindShift) != KindTcpRecv)
        {
            Dispatch(in cqe);
            return;
        }
        long started = Stopwatch.GetTimestamp();
        Dispatch(in cqe);
        if (cqe.res > 0 && ConnAt((int)(uint)cqe.user_data, (ushort)(cqe.user_data >> GenShift)) is { } conn)
        {
            Weigh(conn, Stopwatch.GetTimestamp() - started);
        }
    }

    private void Dispatch(in IoUringCqe cqe)
    {
        if (_incremental)
        {
            DispatchIncremental(in cqe);
        }
        else
        {
            DispatchSharedRing(in cqe);
        }
    }

    // Weighing, what a connection's receives take adds up for the look. Giving, each connection is looked at once, as it
    // first comes by: by what it weighed for that look, or by what this completion took if it weighed nothing then.
    private void Weigh(TcpConnection conn, long took)
    {
        if (_taker is not null)
        {
            if (conn.WeighedTick != -_givingLook)
            {
                long weighs = conn.WeighedTick == _givingLook ? conn.Weight : took;
                conn.WeighedTick = -_givingLook;
                Give(conn, weighs);
            }
            return;
        }

        if (conn.WeighedTick != _weighLook)
        {
            conn.WeighedTick = _weighLook;
            conn.Weight = 0;
        }
        conn.Weight += took;
        _weight += took;
    }

    // A tenth over the budget is near enough: an idle reactor reads a little over 0, and of two that weigh the same neither
    // would go to it. Of all that come by, no more go than the share of the load that is to go, so ones whose work after an
    // await weighs nothing don't all go at once.
    private void Give(TcpConnection conn, long weighs)
    {
        _credit += _share;
        if (_credit >= 1 && weighs <= _budget + (_budget / 10) && NowMs - Volatile.Read(ref _taker!._tickedAtMs) <= LoadStaleMs
            && StartMove(conn, _taker))
        {
            _credit -= 1;
            _budget -= weighs;
            _gave = true;
        }
    }
}
