using System.Runtime.InteropServices;
using ioxide.utils;

namespace ioxide;

public sealed unsafe partial class TcpConnection
{
    private readonly Reactor _reactor;

    public int ClientFd { get; private set; }

    /// <summary>The listener port this connection was accepted on; set per accept.</summary>
    public ushort ListenerPort { get; internal set; }

    /// <summary>
    /// The reader currently holding recv buffers taken out of this connection's queue, if any.
    /// </summary>
    /// <remarks>
    /// One reference, assigned once when a holder is constructed. Recycle asks it back through
    /// <see cref="ReleaseHeldRecvBuffers"/>, so a buffer a handler stranded by returning early does
    /// not depend on the caller remembering. See <see cref="IRecvBufferHolder"/> for why
    /// <see cref="DrainRecv"/> cannot find those buffers itself.
    /// </remarks>
    internal IRecvBufferHolder? BufferHolder;

    /// <summary>
    /// Hand back whatever a holder is still holding, before the buffers stop being reachable.
    /// Called from the reactor's recycle; a no-op when the holder completed normally, which is the
    /// common path.
    /// </summary>
    /// <remarks>
    /// The slot is claimed rather than read so the reclaim runs at most once. That alone does not
    /// make a double return impossible - the holder still walks its own chain on <c>Complete</c> -
    /// what rules it out is the refcount protocol: recycle runs at refcount zero, so a conforming
    /// handler has finished with the connection before this is reached.
    /// </remarks>
    internal void ReleaseHeldRecvBuffers()
        => Interlocked.Exchange(ref BufferHolder, null)?.ReleaseHeldBuffers();

    /// <summary>
    /// The reactor's coarse clock when the read now parked on this connection started waiting,
    /// read by the sweep (Reactor.Tcp.Sweep.cs) against <see cref="TcpOptions.ReadTimeoutMs"/>.
    /// </summary>
    /// <remarks>
    /// Meaningful only while a read is parked - it is written each time one parks and never
    /// cleared, because clearing it would put a store on the recv completion path to maintain a
    /// value nothing reads in that state. The same shape as <see cref="FlushArmedMs"/>.
    /// </remarks>
    internal long ReadParkedMs;

    // Suspensions of the read clock (SuspendReadTimeout), and when the last one was lifted - the
    // clock restarts from there, since the read may have been parked the whole time it was off.
    private int _readTimeoutSuspensions;
    private long _readTimeoutResumedMs;

    /// <summary>
    /// When the handler released the connection while the peer was still connected; the sweep
    /// bounds how long the peer then has to close. Meaningful only while <see cref="HandlerReleased"/>.
    /// </summary>
    internal long HandlerReleasedMs;

    // Whether the FIN that ends a released connection has gone out; see DecRef.
    private int _finSent;

    /// <summary>
    /// Set once the sweep has shut this connection down, so the next tick skips it instead of
    /// re-issuing shutdown() every 250 ms until the teardown completions land.
    /// </summary>
    internal bool SweepClosed;

    /// <summary>
    /// Whether this connection sends with SEND_ZC (zero-copy). Bound at accept from
    /// <see cref="TcpOptions.ZeroCopySend"/>; kTLS forces it back to plain via the
    /// <see cref="SendOpFlags"/> setter. The reactor branches on this bool per send instead of
    /// dispatching through an indirect function pointer.
    /// </summary>
    internal bool UseZc;

    private uint _sendOpFlags = 0x100;   // MSG_WAITALL

    /// <summary>
    /// op_flags for sends on this connection. Defaults to MSG_WAITALL (the kernel coalesces short
    /// sends into one CQE). kTLS rejects MSG_WAITALL, so <c>ioxide.tls</c> clears this after the
    /// handoff; the reactor's partial-send loop preserves correctness either way. Clearing it (the
    /// kTLS marker) also pins this connection to plain SEND - SEND_ZC through the TLS ULP gives no
    /// benefit and may be rejected.
    /// </summary>
    public uint SendOpFlags
    {
        get => _sendOpFlags;
        set
        {
            _sendOpFlags = value;
            if (value == 0)
            {
                UseZc = false;
            }
        }
    }

    // Bumped on Clear(); the low 16 bits serve as the IVTS token so stale awaiters
    // from a previous pool life are detectable.
    private int _generation;

    // Two owners: the reactor (recv side) and the handler. Init 2 on accept; teardown
    // runs only at 0, so a connection is never recycled under a live handler.
    private int _refs;

    public TcpConnection(Reactor reactor, int fd, int writeSlabSize = 1024 * 16, int recvQueueEntries = 64, WriteOverflowStrategy overflow = WriteOverflowStrategy.Grow)
    {
        _reactor = reactor;
        ClientFd = fd;
        _writeSlabSize = writeSlabSize;
        _baseSlabSize = writeSlabSize;
        _overflow = overflow;
        WriteBuffer = (byte*)NativeMemory.AlignedAlloc((nuint)writeSlabSize, 64);
        _recv = new SpscRecvRing(recvQueueEntries);

        _manager = new UnmanagedMemoryManager(WriteBuffer, writeSlabSize);
    }

    // Wake awaiters with closed=1. Reactor-thread or teardown paths only.
    public void MarkClosed()
    {
        Volatile.Write(ref _closed, 1);

        if (Interlocked.Exchange(ref _armed, 0) == 1)
        {
            _readSignal.SetResult(new RecvSnapshot(_recv.SnapshotTail(), isClosed: true));
        }
        else
        {
            Volatile.Write(ref _pending, 1);
        }

        if (Interlocked.Exchange(ref _flushArmed, 0) == 1)
        {
            Volatile.Write(ref _flushInProgress, 0);
            _flushSignal.SetResult(true);
        }
    }

    internal void InitRefs() => Volatile.Write(ref _refs, 2);

    /// <summary>
    /// The handler's release: it is done with the connection. Whichever of the two owners lets go
    /// last hands the connection to the reactor for recycle.
    /// </summary>
    /// <remarks>
    /// A handler that lets go while the peer is still connected ends the connection: nothing will
    /// read or write it again, so the peer gets a FIN now, behind whatever the last flush left in
    /// the socket. Without it the peer waited on a connection nobody served until it gave up. The
    /// read side stays open until the peer's own FIN, so data it sends meanwhile is drained rather
    /// than answered with a reset, and <see cref="TcpOptions.ReadTimeoutMs"/> bounds a peer that
    /// never closes.
    ///
    /// The shutdown runs BEFORE the decrement, while this ref still keeps the fd open: after it,
    /// the reactor may recycle the connection and the number can belong to someone else. A flush
    /// still in flight defers the FIN to the sweep, since a FIN now would cut that send short.
    /// </remarks>
    public void DecRef()
    {
        // Both refs held: the reactor has not seen the peer go, so the connection is still live.
        if (Volatile.Read(ref _refs) == 2)
        {
            Volatile.Write(ref HandlerReleasedMs, _reactor.NowMs);
            if (!FlushOutstanding)
            {
                SendFin();
            }
        }

        ReleaseRef();
    }

    /// <summary>The reactor's release, from the paths that tore the connection down.</summary>
    internal void ReleaseReactorRef() => ReleaseRef();

    /// <summary>
    /// The connection ended from the reactor's side - the peer closed, the socket failed, the recv
    /// queue overflowed - so there is no one to send a FIN to. Called before the MarkClosed that
    /// wakes the handler: it resumes inline and lets go while the reactor's ref is still held, and
    /// would otherwise pay a shutdown() on every connection the peer closed.
    /// </summary>
    internal void SuppressFin() => Volatile.Write(ref _finSent, 1);

    private void ReleaseRef()
    {
        if (Interlocked.Decrement(ref _refs) == 0)
        {
            _reactor.EnqueueRecycle(this);
        }
    }

    /// <summary>
    /// Whether the handler has let go while the reactor still holds the connection - it is only
    /// waiting for the peer to close. Meaningful only while the connection is in the reactor's
    /// table, which is exactly while the reactor's ref is held.
    /// </summary>
    internal bool HandlerReleased => Volatile.Read(ref _refs) == 1;

    /// <summary>Send the released connection's FIN, once. Safe from any thread while a ref is held.</summary>
    internal void SendFin()
    {
        if (Interlocked.Exchange(ref _finSent, 1) == 0)
        {
            Native.shutdown(ClientFd, Native.SHUT_WR);
        }
    }

    internal bool FinSent => Volatile.Read(ref _finSent) != 0;

    /// <summary>
    /// Stop the read clock (<see cref="TcpOptions.ReadTimeoutMs"/>) until the matching
    /// <see cref="ResumeReadTimeout"/>: a read parked in the meantime is not the server waiting on
    /// the peer.
    /// </summary>
    /// <remarks>
    /// For a layer whose read stays parked while the application is busy. A pump that reads in the
    /// background suspends it, and resumes only while the application actually waits on the pump.
    /// A protocol answering several requests at once suspends it while it owes a response, so a
    /// slow request does not time out the connection it shares with the others. Calls nest; the
    /// clock runs again, from the moment of the last resume, once every suspension is lifted. The
    /// count resets when the connection is recycled.
    /// </remarks>
    public void SuspendReadTimeout() => Interlocked.Increment(ref _readTimeoutSuspensions);

    /// <summary>Lift one <see cref="SuspendReadTimeout"/>.</summary>
    public void ResumeReadTimeout()
    {
        // Stamped before the count drops, so a sweep that sees no suspensions sees this time too.
        Volatile.Write(ref _readTimeoutResumedMs, _reactor.NowMs);
        Interlocked.Decrement(ref _readTimeoutSuspensions);
    }

    /// <summary>
    /// Whether the server is waiting on the peer, and since when: a read is parked and nothing
    /// suspends the clock, or the handler has let go and the peer has yet to close.
    /// </summary>
    internal bool WaitingOnPeer(out long sinceMs)
    {
        if (HandlerReleased)
        {
            sinceMs = Volatile.Read(ref HandlerReleasedMs);
            return true;
        }

        if (Volatile.Read(ref _armed) == 0 || Volatile.Read(ref _readTimeoutSuspensions) > 0)
        {
            sinceMs = 0;
            return false;
        }

        sinceMs = Math.Max(Volatile.Read(ref ReadParkedMs), Volatile.Read(ref _readTimeoutResumedMs));
        return true;
    }

    // Guards the framework's fault-path release of the handler ref; reset per pool life (#94).
    private int _handlerRefReleased;

    /// <summary>
    /// Release the handler's ref on behalf of a handler that faulted before its own DecRef, so the
    /// fd/slab/gid aren't leaked (#94). Generation-guarded - a fault observed after this connection
    /// was recycled must not touch its next life - and idempotent within a life. A handler that
    /// DecRefs and then throws is outside the refcount contract; the guards keep that from
    /// corrupting a reused connection.
    /// </summary>
    internal void ReleaseHandlerRefOnFault(int generationAtStart)
    {
        if (Volatile.Read(ref _generation) == generationAtStart &&
            Interlocked.Exchange(ref _handlerRefReleased, 1) == 0)
        {
            DecRef();
        }
    }

    internal void Clear()
    {
        // Bump generation first so stale IVTS tokens resolve to Closed()/no-op.
        Interlocked.Increment(ref _generation);

        Volatile.Write(ref _armed, 0);
        Volatile.Write(ref _pending, 0);
        Volatile.Write(ref _closed, 0);
        Volatile.Write(ref _flushArmed, 0);
        Volatile.Write(ref _flushInProgress, 0);
        Volatile.Write(ref FlushArmedMs, 0);
        Volatile.Write(ref ReadParkedMs, 0);
        Volatile.Write(ref _readTimeoutSuspensions, 0);
        Volatile.Write(ref _readTimeoutResumedMs, 0);
        Volatile.Write(ref HandlerReleasedMs, 0);
        Volatile.Write(ref _finSent, 0);
        SweepClosed = false;

        WriteHead = 0;
        WriteTail = 0;
        WriteInFlight = 0;
        ZcNotifPending = 0;

        // Segmented: hand any overflow slabs back to the pool (a connection recycled mid-response).
        if (_ovCount > 0)
        {
            ReleaseOverflow();
        }

        // Restore an overgrown write slab to its base size so the pool doesn't retain large buffers.
        if (_writeSlabSize != _baseSlabSize)
        {
            NativeMemory.AlignedFree(WriteBuffer);
            WriteBuffer = (byte*)NativeMemory.AlignedAlloc((nuint)_baseSlabSize, 64);
            _writeSlabSize = _baseSlabSize;
            _manager.Reset(WriteBuffer, _baseSlabSize);
        }

        _readSignal.Reset();
        _flushSignal.Reset();

        _recv.Reset();
        BufferHolder = null;
        Volatile.Write(ref _handlerRefReleased, 0);
        IncrementalMode = false;
        SendOpFlags = 0x100;   // MSG_WAITALL; a kTLS connection re-sets this per handshake
        ListenerPort = 0;
    }

    public void Dispose()
    {
        if (WriteBuffer != null)
        {
            NativeMemory.AlignedFree(WriteBuffer);
            WriteBuffer = null;
        }
        if (_iov != null)
        {
            NativeMemory.AlignedFree(_iov);
            _iov = null;
        }
        if (_msg != null)
        {
            NativeMemory.AlignedFree(_msg);
            _msg = null;
        }
        DisposeIncremental();
    }
}
