using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace ioxide;

/// <summary>
/// Which connections move, and where (<see cref="TcpOptions.Rebalance"/>). The kernel spreads connections over the
/// reactors as they connect, knowing nothing of what each will ask for, so some reactors can end up with all the busy ones.
/// On its tick a reactor compares what its thread spent on a CPU with what the others' did. A busy one with a much less
/// busy one beside it weighs its connections for a tick, by the time their recv completions take, and then gives away
/// enough of them to halve the difference, each as it next completes a recv. One with nothing to do is never looked at.
/// </summary>
public sealed unsafe partial class Reactor
{
    /// <summary>The share of a tick on a CPU, in percent, from which a reactor gives connections away.</summary>
    private const int BusyPercent = 75;

    /// <summary>How far below that share, in points, one has to be to be given them.</summary>
    private const int GapPercent = 30;

    /// <summary>A reactor whose last reading is older is stuck in something, whatever the reading says.</summary>
    private const int LoadStaleMs = 3 * TickMs;

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

    // This reactor's last reading, which the others go by.
    private int _loadPercent;
    private long _loadAtMs;
    private long _loadCpuNs;
    private long _loadTimestamp;

    private Reactor? _taker;     // given to, while Giving and Settling
    private Reactor? _giver;     // the one giving to this reactor, if any: one at a time, or two would fill the same gap
    private long _budget;        // what may still be given to _taker
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
        _loadTimestamp = Stopwatch.GetTimestamp();
        Volatile.Write(ref _loadAtMs, Native.MonotonicMs);

        _fleet = Fleets.GetValue(_config, static config => new Reactor?[config.ReactorCount]);
        Volatile.Write(ref _fleet[_id], this);
        AddTicker(BalanceTick);
    }

    // For good: the config can outlive its reactors, and have others after them.
    private void LeaveFleet()
    {
        ReleaseTaker();
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
        ReleaseTaker();

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
        _budget = weight * (_loadPercent - taker._loadPercent) / (2 * _loadPercent);
        _balance = Balance.Giving;
    }

    private void ReadLoad()
    {
        long cpu = Native.ThreadCpuNs;
        long timestamp = Stopwatch.GetTimestamp();
        double wall = Stopwatch.GetElapsedTime(_loadTimestamp, timestamp).TotalNanoseconds;

        Volatile.Write(ref _loadPercent, (int)(100 * (cpu - _loadCpuNs) / Math.Max(1, wall)));
        Volatile.Write(ref _loadAtMs, NowMs);
        _loadCpuNs = cpu;
        _loadTimestamp = timestamp;
    }

    private Reactor? LeastLoaded()
    {
        Reactor? least = null;
        foreach (Reactor? reactor in _fleet)
        {
            if (reactor is not null && !reactor._stopRequested
                && Volatile.Read(ref reactor._giver) is null
                && NowMs - Volatile.Read(ref reactor._loadAtMs) <= LoadStaleMs
                && Volatile.Read(ref reactor._loadPercent) + GapPercent <= _loadPercent   // so never this one
                && (least is null || reactor._loadPercent < least._loadPercent))
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

    // After one of its recv completions, its handler's part included, unless the balance is off.
    private void Weigh(TcpConnection conn, long took)
    {
        if (conn.WeighedTick != _weighTick)
        {
            conn.LastWeight = conn.WeighedTick >= _weighTick - WeightTicks ? conn.Weight : 0;
            conn.WeighedTick = _weighTick;
            conn.Weight = 0;
        }
        conn.Weight += took;
        _weight += took;

        // By what it weighed over a whole tick, this one's being a part. A tenth over the budget is near enough: an idle
        // reactor reads a little over 0, and of two that weigh the same neither would go to it.
        if (_balance == Balance.Giving && conn.LastWeight > 0 && conn.LastWeight <= _budget + (_budget / 10)
            && StartMove(conn, _taker!))
        {
            _budget -= conn.LastWeight;
        }
    }
}
