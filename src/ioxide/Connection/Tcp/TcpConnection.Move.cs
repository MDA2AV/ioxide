namespace ioxide;

/// <summary>
/// What a connection needs to change reactors (<see cref="TcpOptions.Rebalance"/>, Reactor.Tcp.Move.cs): whose it is, and
/// whether it is idle as TCP sees it. Nothing here knows which protocol it carries.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // The reactor serving it: the one whose table it is in, or was in until the one it was given to takes it. Only the
    // taker writes it, so what another thread sends to it meanwhile reaches the giver, which passes it on.
    private Reactor _reactor;

    // The same, or the reactor it was given to. Only the thread of the one serving it writes it.
    private Reactor _home;

    /// <summary>
    /// The reactor this connection is on. It changes only under <see cref="TcpOptions.Rebalance"/>, while a read waits, so
    /// after every read it can be another one than before.
    /// </summary>
    /// <remarks>
    /// While it is on its way to another reactor it is that one to the thread of the reactor it left, and the one it left
    /// to every other thread, as that one passes on what it is sent.
    ///
    /// On that reactor's own thread it doesn't change until the code running there returns or waits. Anywhere else it can
    /// change at any moment: what must run on the connection's reactor asks again once it got there, as in
    /// <c>while (!connection.Reactor.OnReactorThread) await new ReactorSwitch(connection.Reactor);</c>
    /// </remarks>
    public Reactor Reactor
    {
        get
        {
            // In this order: a home read here that a later reactor wrote brings that reactor's own arrival with it, so
            // the read below then finds it, and not this thread's.
            Reactor home = Volatile.Read(ref _home);
            Reactor serving = Volatile.Read(ref _reactor);
            return serving.OnReactorThread ? home : serving;
        }
    }

    /// <summary>
    /// Keeps the connection on its reactor while set: for code that holds on to something of its reactor's across a read,
    /// a transaction on one of its database connections, say. Set by the code that reads from the connection, before the
    /// read. Reset with the connection's life. Only <see cref="TcpOptions.Rebalance"/> ever moves one.
    /// </summary>
    /// <remarks>
    /// Pins don't nest: code that pins a connection for a while sets back what it found, as
    /// <see cref="ioxide.tls.TlsService.AcceptAsync"/> does, and doesn't unpin one that somebody else pinned.
    /// </remarks>
    public bool Pinned { get; set; }

    // Where it is in a move, on its reactor's thread. With none, its recv is armed as ever.
    internal const int MoveNone       = 0;
    internal const int MoveCancelling = 1;   // its recv is being cancelled
    internal const int MoveWaiting    = 2;   // no recv armed: what the peer sends stays in the socket until the next one is
    internal const int MoveGiven      = 3;   // out of the giver's table, not in the taker's yet

    internal int MoveState;

    /// <summary>Where it is going. Meaningful in a move; written with its state.</summary>
    internal Reactor? MoveTo;

    /// <summary>When its recv was cancelled.</summary>
    internal long MoveSinceMs;

    // The tags of its operations name its slot and this, which the reactor gives it with the slot (Track): a new one on
    // every reactor it comes to, where Generation stays with the life.
    internal int TagGen;

    // What its reactor spent on it, handler included, in the tick being weighed and in the last one before that saw it.
    internal long Weight;
    internal long LastWeight;
    internal long WeighedTick = long.MinValue;

    // Recv buffers handed back, against those taken out of the queue. Not atomic: two threads returning at once can lose
    // one, and then the connection looks as if it held a buffer and stays where it is.
    private long _returned;

    // After the return itself: a reactor that sees it counted has the buffer, or has it queued.
    private void CountReturned() => Volatile.Write(ref _returned, _returned + 1);

    /// <summary>Everything received was taken, and handed back.</summary>
    internal bool HoldsNothing => _recv.IsEmpty() && _recv.TakenCount == Volatile.Read(ref _returned);

    /// <summary>A read waits, so the connection isn't closed either: its close would have ended it.</summary>
    internal bool ReadParked => Volatile.Read(ref _readWaiter) is { } waiter && waiter != Claimed && waiter != ClaimedWoken;

    /// <summary>Nothing can touch it but a completion of its reactor's, the send's included if one is in flight.</summary>
    internal bool IdleButForTheSend => ReadParked && HoldsNothing && !_fileRead.InFlight && !Pinned && !HandlerReleased;

    internal bool Idle => IdleButForTheSend && !FlushOutstanding;

    // The giver, on its thread, as it lets go: what its thread still does for the connection goes to the taker.
    internal void LeaveFor(Reactor target)
    {
        MoveState = MoveGiven;
        Slot = -1;   // which finds nothing
        Volatile.Write(ref _home, target);
    }

    // The taker, on its thread, with a slot of its own given to it.
    internal void ArriveOn(Reactor reactor)
    {
        MoveState = MoveNone;
        MoveTo = null;
        LastWeight = 0;
        WeighedTick = long.MinValue;
        Volatile.Write(ref _home, reactor);
        Volatile.Write(ref _reactor, reactor);
    }

    /// <summary>
    /// Whether a write shutdown waits for a flush (<see cref="ShutdownWrite"/>). It was queued where the connection was,
    /// by whichever thread asked for it, so the taker queues it again.
    /// </summary>
    internal bool WriteShutdownDeferred => Volatile.Read(ref _writeShutdown) == 2;

    private void ClearMove()
    {
        MoveState = MoveNone;
        MoveTo = null;
        Pinned = false;
        LastWeight = 0;
        WeighedTick = long.MinValue;
        Volatile.Write(ref _returned, 0);
    }
}
