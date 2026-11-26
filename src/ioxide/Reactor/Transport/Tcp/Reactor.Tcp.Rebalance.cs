using System.Diagnostics;
using static ioxide.Native;
using System.Runtime.CompilerServices;

namespace ioxide;

/// <summary>
/// Which connections move, and where (<see cref="TcpOptions.Rebalance"/>). The kernel spreads connections over the
/// reactors as they connect, knowing nothing of what each will ask for, so some reactors can end up with all the busy ones.
/// On its tick a reactor compares how busy it was with how busy the others were: the share of the tick its thread spent
/// on a CPU, or kept from waiting for completions if that is more. A busy one with a much less busy one beside it, less
/// busy in both of its last two ticks, weighs its connections for a tick, by the time their recv completions take, and
/// then gives away enough of them to halve the difference, each as it next completes a recv. One with nothing to do is
/// never looked at.
/// </summary>
public sealed unsafe partial class Reactor
{
    /// <summary>The share of a tick on a CPU, in percent, from which a reactor gives connections away.</summary>
    private const int BusyPercent = 75;

    /// <summary>How far below that share, in points, one has to be to be given them.</summary>
    private const int GapPercent = 30;

    /// <summary>A reactor whose last reading is older is stuck in something, whatever the reading says.</summary>
    private const int LoadStaleMs = 2 * TickMs;

    /// <summary>For how many ticks a connection's weight is taken for what it still is.</summary>
    private const int WeightTicks = 8;

    private enum Balance : byte
    {
        Off,        // not busy, or nowhere to give to: nothing is weighed
        Weighing,   // for a tick, so there is something to choose by
        Giving,     // for a tick, to _taker
        Settling,   // for a tick: both loads are read again before anything is decided anew
    }

    private Balance _balance;

    // The reactors sharing one ServerConfig, by ShardIndex, as QuicFleets has them.
    private static readonly ConditionalWeakTable<ServerConfig, Reactor?[]> Fleets = new();
    private Reactor?[] _fleet = [];

    // This reactor's last reading, and the higher of it and the one before: as a taker it goes by that, so one that was
    // quiet for a moment, between two bursts, is given nothing.
    private int _loadPercent;
    private int _loadPeak;
    private long _loadAtMs;
    private long _loadCpuNs;
    private long _loadTimestamp;

    // Of this tick, outside the ring's wait, in Stopwatch ticks: a handler that blocks, or a CPU shared with others, keeps
    // a reactor from its completions without its thread being on a CPU. The ms clock is too coarse for a pass.
    private long _worked;
    private long _passFrom;

    private Reactor? _taker;     // given to, while Giving and Settling
    private Reactor? _giver;     // the one giving to this reactor, if any: one at a time, or two would fill the same gap
    private long _budget;        // what may still be given to _taker
    private double _share;       // of the connections that fit it, the one in so many that goes
    private double _credit;      // towards the next of them
    private bool _gave;          // since _taker was claimed
    private long _weight;        // of the recv completions of this tick
    private long _weighTick;

    // Before the loop, once the reactor is all there to be given connections.
    private void JoinFleet()
    {
        if (!_tcp.Rebalance || ShardCount <= 1 || (uint)_id >= (uint)ShardCount)
        {
            return;
        }

        _loadCpuNs = Native.ThreadCpuNs;
        _loadTimestamp = _passFrom = Stopwatch.GetTimestamp();
        Volatile.Write(ref _loadAtMs, Native.MonotonicMs);

        _fleet = Fleets.GetValue(_config, static config => new Reactor?[config.ReactorCount]);
        Volatile.Write(ref _fleet[_id], this);
        AddTicker(BalanceTick);
    }

    // For good: the config can outlive its reactors, and have others after them. Moves under way end here, and what they
    // had reserved on other reactors goes back.
    private void LeaveFleet()
    {
        ReleaseTaker();
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

    private void BalanceTick()
    {
        ReadLoad();
        DecideBalance();
    }

    private void DecideBalance()
    {
        long weight = _weight;
        _weight = 0;
        _weighTick++;

        if (_balance == Balance.Giving)
        {
            _balance = Balance.Settling;
            return;
        }

        // Nothing of it could go (one connection is all its load, or pinned ones are): the taker is for the others, until
        // this one has weighed anew.
        bool futile = _balance == Balance.Settling && !_gave;
        ReleaseTaker();
        if (futile)
        {
            _balance = Balance.Off;
            return;
        }

        Reactor? taker = _loadPercent >= BusyPercent && !_stopRequested ? LeastLoaded() : null;
        if (taker is null)
        {
            _balance = Balance.Off;
            return;
        }

        if (_balance == Balance.Off || Interlocked.CompareExchange(ref taker._giver, this, null) is not null)
        {
            _balance = Balance.Weighing;
            return;
        }

        _taker = taker;
        int gap = _loadPercent - Volatile.Read(ref taker._loadPeak);
        _budget = weight * gap / (2 * _loadPercent);
        _share = gap / (2.0 * _loadPercent);
        _credit = 0.5;
        _gave = false;
        _balance = Balance.Giving;
    }

    private void ReadLoad()
    {
        long cpu = Native.ThreadCpuNs;
        long timestamp = Stopwatch.GetTimestamp();
        double wall = Stopwatch.GetElapsedTime(_loadTimestamp, timestamp).TotalNanoseconds;

        double busy = Math.Max(cpu - _loadCpuNs, _worked * (1e9 / Stopwatch.Frequency));
        int reading = (int)Math.Min(100, 100 * busy / Math.Max(1, wall));
        Volatile.Write(ref _loadPeak, Math.Max(reading, _loadPercent));
        Volatile.Write(ref _loadPercent, reading);
        Volatile.Write(ref _loadAtMs, NowMs);
        _loadCpuNs = cpu;
        _loadTimestamp = timestamp;
        _worked = 0;
    }

    private Reactor? LeastLoaded()
    {
        Reactor? least = null;
        long now = Native.MonotonicMs;   // not the pass's: a busy reactor's passes are long
        foreach (Reactor? reactor in _fleet)
        {
            if (reactor is not null && !reactor._stopRequested
                && Volatile.Read(ref reactor._giver) is null
                && now - Volatile.Read(ref reactor._loadAtMs) <= LoadStaleMs
                && Volatile.Read(ref reactor._loadPeak) + GapPercent <= _loadPercent   // so never this one
                && (least is null || reactor._loadPeak < least._loadPeak))
            {
                least = reactor;
            }
        }
        return least;
    }

    private void ReleaseTaker()
    {
        if (_taker is { } taker)
        {
            _taker = null;
            Volatile.Write(ref taker._giver, null);
        }
    }

    // A completion in a round: dispatched as any other, and a receive timed, its handler's part included, and charged to its
    // connection. Outside a round the loop calls the dispatchers directly, which weigh nothing.
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

    private void Weigh(TcpConnection conn, long took)
    {
        bool first = conn.WeighedTick != _weighTick;
        if (first)
        {
            conn.LastWeight = conn.WeighedTick >= _weighTick - WeightTicks ? conn.Weight : 0;
            conn.WeighedTick = _weighTick;
            conn.Weight = 0;
        }
        conn.Weight += took;
        _weight += took;

        if (_balance == Balance.Giving && first)
        {
            Give(conn, conn.LastWeight > 0 ? conn.LastWeight : took);
        }
    }

    // Once a tick, as it first comes by: by what it weighed over the last whole tick, or what this completion took if it
    // weighed nothing lately. A tenth over the budget is near enough: an idle reactor reads a little over 0, and of two that
    // weigh the same neither would go to it. Of all that come by, no more go than the share of the load that is to go, so
    // ones whose work after an await weighs nothing don't all go at once.
    private void Give(TcpConnection conn, long weighs)
    {
        _credit += _share;
        if (_credit >= 1 && weighs <= _budget + (_budget / 10) && NowMs - Volatile.Read(ref _taker!._loadAtMs) <= LoadStaleMs
            && StartMove(conn, _taker))
        {
            _credit -= 1;
            _budget -= weighs;
            _gave = true;
        }
    }
}
