using static ioxide.Native;

namespace ioxide;

/// <summary>
/// A TCP connection changes reactors. The socket belongs to the process, so any ring can receive and send on it; what
/// ties a connection to its reactor is the recv armed in its ring, what was received into its buffers, a send in flight,
/// and its place in the table. A move undoes those here and redoes them there:
/// <list type="number">
/// <item>its recv is cancelled (<see cref="StartMove"/>). What the peer sends from then on stays in the socket;</item>
/// <item>its handler goes on as ever, on this reactor, through what had arrived (<see cref="RecvOver"/>);</item>
/// <item>once it is idle, it leaves the table and is posted to the other reactor (<see cref="HandOver"/>);</item>
/// <item>that one gives it a place, and arms a recv on the same descriptor in its own ring (<see cref="Adopt"/>).</item>
/// </list>
/// Its handler, waiting in a read, is on no thread: it resumes on the other reactor's, whose completion that read's is.
/// </summary>
/// <remarks>
/// One thread has the connection at any time, the giver's until it posts it and the taker's once it takes it, and in
/// between there is nothing for a completion to come from, so none of this locks. The cancel comes first because under
/// load the next bytes have nearly always arrived by the time a handler waits: with the recv armed, a busy connection is
/// hardly ever idle.
///
/// What other threads send a moving connection's way reaches it wherever it is by then (<see cref="TcpConnection.Reactor"/>),
/// but for one thing: a flush another thread asks for while the connection is between two reactors can get lost.
/// </remarks>
public sealed unsafe partial class Reactor
{
    /// <summary>How long a connection without a recv, whose handler waits in a read, waits to become idle before it stays after all.</summary>
    private const int MoveGiveUpMs = 100;

    /// <summary>How long it waits for a handler at work to wait in a read at all.</summary>
    private const int MoveAtMostMs = 2_000;

    // Their recv is over and they are not idle yet: looked at on every pass. (tag generation << 32) | slot.
    private readonly List<ulong> _leaving = [];

    // On their way here: posted, or about to be, and not taken. A stop waits for them.
    private int _arriving;

    // Given away and not taken yet: until then other threads send what they have for one this reactor's way, so a stop
    // waits for them too.
    private int _givenAway;

    private long _connectionsGiven;
    private long _connectionsTaken;

    /// <summary>Connections this reactor gave to another one (<see cref="TcpOptions.Rebalance"/>).</summary>
    public long ConnectionsGiven => Volatile.Read(ref _connectionsGiven);

    /// <summary>Connections another reactor gave to this one.</summary>
    public long ConnectionsTaken => Volatile.Read(ref _connectionsTaken);

    /// <summary>A connection in transit.</summary>
    /// <param name="FlushDone">Its last send is over, and whoever waits for that flush has not been told.</param>
    /// <param name="From">Where it came from, to go back to; null on the way back.</param>
    private sealed record Arrival(Reactor Target, TcpConnection Conn, bool FlushDone, Reactor? From);

    /// <summary>
    /// Begins moving a connection, whose recv is armed, to another reactor. False when it stays: it is no fleet's, pinned,
    /// over or moving already, or the other reactor is stopping or has no room for it.
    /// </summary>
    internal bool StartMove(TcpConnection conn, Reactor target)
    {
        if (target == this || !conn.Movable || conn.MoveState != TcpConnection.MoveNone || conn.Pinned || conn.IsClosed || conn.HandlerReleased
            || _stopRequested || target._stopRequested)
        {
            return false;
        }

        // Its recv is parked for a buffer, so there is none to cancel.
        if (_recvStarved.Count > 0 && _recvStarved.Contains(NameOf(conn)))
        {
            return false;
        }

        // Its group id there, before anything is undone here: once it has left there is no way to be refused.
        if (_incremental && !target.TryReserveGid())
        {
            return false;
        }

        conn.MoveTo = target;
        conn.MoveSinceMs = NowMs;
        conn.MoveState = TcpConnection.MoveCancelling;
        SubmitCancel(Tag(KindTcpRecv, (ushort)conn.TagGen, conn.Slot));
        return true;
    }

    // As the queues name one: what is over or has left is not found by it.
    private static ulong NameOf(TcpConnection conn) => ((ulong)(ushort)conn.TagGen << 32) | (uint)conn.Slot;

    // Its recv is over, by the cancel or by itself: nothing more arrives here. Idle, it goes. Whether it stays is for the
    // next pass to say, past the rest of this batch: a recv armed now would be submitted after whatever the batch does with
    // the connection, such as closing its descriptor, whose number may be another socket's by then.
    private void RecvOver(TcpConnection conn)
    {
        conn.MoveState = TcpConnection.MoveWaiting;
        if (!conn.Idle || !HandOver(conn, flushDone: false))
        {
            _leaving.Add(NameOf(conn));
        }
    }

    // Every pass, past the handlers it ran: whoever became idle leaves, and whoever won't stays.
    private void RunLeaving()
    {
        for (int i = _leaving.Count - 1; i >= 0; i--)
        {
            ulong name = _leaving[i];
            if (ConnAt((int)(uint)name, (ushort)(name >> 32)) is not { MoveState: TcpConnection.MoveWaiting } conn || SettleMove(conn))
            {
                _leaving[i] = _leaving[^1];
                _leaving.RemoveAt(_leaving.Count - 1);
            }
        }
    }

    // True once it is decided, one way or the other.
    private bool SettleMove(TcpConnection conn)
    {
        if (conn.Idle)
        {
            if (!HandOver(conn, flushDone: false))
            {
                StayHere(conn);
            }
            return true;
        }

        // Over, held back, or waiting for the rest of something it holds a part of in this reactor's buffers. A handler at
        // work is waited for, for a while; once it waits in a read, what keeps the connection from being idle has 100 ms.
        if (conn.IsClosed || conn.HandlerReleased || conn.Pinned || (conn.ReadParked && !conn.HoldsNothing)
            || NowMs - conn.MoveSinceMs >= MoveAtMostMs
            || (conn.ReadParked && NowMs - Math.Max(Volatile.Read(ref conn.ReadParkedMs), conn.MoveSinceMs) >= MoveGiveUpMs))
        {
            StayHere(conn);
            return true;
        }

        return false;   // its handler is at work, or a send is in flight
    }

    private void StayHere(TcpConnection conn)
    {
        EndMove(conn);
        SubmitRecvMultishot(conn, (ushort)conn.TagGen, _incremental ? conn.Bgid : BgId);
    }

    // The move is off, for whatever reason; its recv is someone else's business.
    private void EndMove(TcpConnection conn)
    {
        if (conn.MoveState is TcpConnection.MoveCancelling or TcpConnection.MoveWaiting)
        {
            if (_incremental)
            {
                conn.MoveTo!.UnreserveGid();
            }
            conn.MoveState = TcpConnection.MoveNone;
        }
    }

    // Idle, so nothing of it is left here but its place. False when the target has begun to stop, and nothing has changed.
    private bool HandOver(TcpConnection conn, bool flushDone)
    {
        Reactor target = conn.MoveTo!;
        if (!target.ExpectArrival())
        {
            return false;
        }

        Untrack(conn);
        _freeSlots.Push(conn.Slot);
        if (_incremental)
        {
            TeardownConnectionBufRing(conn);   // out of this ring; its memory goes along
        }
        Volatile.Write(ref _connectionsGiven, _connectionsGiven + 1);

        Interlocked.Increment(ref _givenAway);
        conn.LeaveFor(target);
        target.ScheduleOnReactor(Arrive, new Arrival(target, conn, flushDone, this));   // the last this thread touches of it
        return true;
    }

    // Any thread, for a connection in nobody's table. Counted before it is asked whether the reactor stops: one that says
    // no waits for it (Stopped).
    private bool ExpectArrival()
    {
        Interlocked.Increment(ref _arriving);
        if (!_stopRequested)
        {
            return true;
        }
        Interlocked.Decrement(ref _arriving);
        return false;
    }

    private static readonly Action<object?> Arrive = static state =>
    {
        var arrival = (Arrival)state!;
        arrival.Target.Adopt(arrival);
    };

    private void Adopt(Arrival arrival)
    {
        TcpConnection conn = arrival.Conn;

        if (_incremental && !SetupConnectionBufRing(conn, reserved: true))
        {
            SendBack(arrival);
            return;
        }

        Track(conn);
        conn.ArriveOn(this);
        Interlocked.Decrement(ref _arriving);   // in the table now, which a stop waits for too
        Interlocked.Decrement(ref (arrival.From ?? this)._givenAway);   // and others send it here
        Volatile.Write(ref _connectionsTaken, _connectionsTaken + 1);

        // Past the new tag being there for all to see: a shutdown deferred since was queued under it.
        Interlocked.MemoryBarrier();
        if (conn.WriteShutdownDeferred)
        {
            DeferWriteShutdown(conn.Slot, conn.TagGen);
        }

        SubmitRecvMultishot(conn, (ushort)conn.TagGen, _incremental ? conn.Bgid : BgId);

        if (_stopRequested)
        {
            AbortConnection(conn);   // the stop's walk may be past
        }
        if (arrival.FlushDone)
        {
            conn.CompleteFlush();
        }
    }

    // Incremental mode, and no locked memory left to register its ring with: home, which has just given some back. Without
    // room there either it is closed, as an accept past the limit is.
    private void SendBack(Arrival arrival)
    {
        Interlocked.Decrement(ref _arriving);

        if (arrival.From is { } home && home.TryReserveGid())
        {
            if (home.ExpectArrival())
            {
                home.ScheduleOnReactor(Arrive, new Arrival(home, arrival.Conn, arrival.FlushDone, From: null));
                return;
            }
            home.UnreserveGid();
        }

        ReportNoLockedMemory();
        TcpConnection conn = arrival.Conn;
        conn.IncrementalMode = false;   // it has no ring to tear down
        Track(conn);
        conn.ArriveOn(this);
        Interlocked.Decrement(ref (arrival.From ?? this)._givenAway);
        if (arrival.FlushDone)
        {
            conn.CompleteFlush();
        }
        CloseFromRecv(conn);
    }

    // The target stopped before it took it, so it is closed as everything that reactor held was, and stays allocated as
    // what a handler still held past a stop does.
    private static void AbandonArrival(Arrival arrival)
    {
        TcpConnection conn = arrival.Conn;
        conn.SuppressWriteShutdown();
        shutdown(conn.ClientFd, SHUT_RDWR);
        if (arrival.FlushDone)
        {
            conn.CompleteFlush();
        }
        conn.MarkClosed();
        ResetPeer(conn.ClientFd);
        Interlocked.Decrement(ref (arrival.From ?? arrival.Target)._givenAway);
    }
}
