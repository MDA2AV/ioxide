using System.Runtime.InteropServices;
using ioxide.utils;

namespace ioxide;

public sealed unsafe partial class TcpConnection
{
    public int ClientFd { get; private set; }

    // Where the reactor's table holds this connection, and what the tags of its operations name: taken at
    // accept (Reactor.Track), kept until recycle. Before the first, -1, which finds nothing.
    internal int Slot = -1;

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

    // When the parked read started waiting (TcpOptions.ReadTimeoutMs). Stale once it completes,
    // like FlushArmedMs - clearing it would cost the recv path a store.
    internal long ReadParkedMs;

    // The last sweep that found a flush in flight. Nothing stamps a flush's completion - that is
    // the send path's hottest point - so this is when the server was last seen sending.
    internal long FlushSeenMs;

    private int _readTimeoutDisabled;
    private long _writeShutdownMs;
    private int _writeShutdown;   // 0, 1 made (or suppressed), 2 deferred behind a flush - the tick makes it

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
    /// op_flags for sends on this connection, bound at accept from <see cref="TcpOptions.SendWaitAll"/>:
    /// MSG_WAITALL by default (the kernel coalesces short sends into one CQE). kTLS rejects
    /// MSG_WAITALL, so <c>ioxide.tls</c> clears this after the handoff; the reactor's partial-send
    /// loop preserves correctness either way. Clearing it through this setter (the kTLS marker) also
    /// pins this connection to plain SEND - SEND_ZC through the TLS ULP gives no benefit and may be
    /// rejected.
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

    // The accept-time binding, past the setter: a 0 here is SendWaitAll off, not kTLS, so ZeroCopySend stays.
    internal void BindSendOpFlags(uint opFlags) => _sendOpFlags = opFlags;

    // Which life of this object: the next number on every Clear(), so no two lives share one whichever reactors they
    // were on. The low 16 bits serve as the IVTS token so stale awaiters from a previous pool life are detectable.
    private int _generation = 1;

    // Two owners: the reactor (recv side) and the handler. Init 2 on accept; teardown
    // runs only at 0, so a connection is never recycled under a live handler.
    private int _refs;

    // Reactor thread only: torn down while the kernel had a send; the reactor lets go when it completes.
    internal bool CloseAfterSend;

    public TcpConnection(Reactor reactor, int fd, int writeSlabSize = 1024 * 16, int recvQueueEntries = 64, WriteOverflowStrategy overflow = WriteOverflowStrategy.Grow)
    {
        _reactor = reactor;
        _home = reactor;
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

        DeliverRead();   // after the store: the read it wakes, or the next one, sees closed = true
        ReleaseParkedFlush();
    }

    internal void InitRefs() => Volatile.Write(ref _refs, 2);

    /// <summary>
    /// The handler's release. A peer still connected gets a FIN; the read side stays open until
    /// it closes, bounded by <see cref="TcpOptions.ReadTimeoutMs"/>.
    /// </summary>
    public void DecRef()
    {
        // Once per life: a handler that lets go and then throws would otherwise be let go again by the
        // fault path, recycling the connection under the reactor's ref (#242).
        if (Interlocked.Exchange(ref _handlerRefReleased, 1) != 0)
        {
            return;
        }

        // Before the decrement, while our ref keeps this life and its fd from being recycled, on any thread.
        if (Volatile.Read(ref _refs) == 2)
        {
            ShutdownWrite();
        }

        ReleaseRef();
    }

    internal void ReleaseReactorRef() => ReleaseRef();

    // The reactor tore the connection down, so the handler's release shuts nothing down. Called before
    // MarkClosed: the handler it wakes lets go inline, while the reactor's ref is still held.
    internal void SuppressWriteShutdown() => Volatile.Write(ref _writeShutdown, 1);

    private void ReleaseRef()
    {
        if (Interlocked.Decrement(ref _refs) == 0)
        {
            _reactor.EnqueueRecycle(this);
        }
    }

    // Only meaningful while the connection is in the reactor's table, i.e. the reactor's ref is held.
    internal bool HandlerReleased => Volatile.Read(ref _refs) == 1;

    // shutdown(SHUT_WR), once: tells the kernel this side is done sending. The FIN is the kernel's, behind
    // the bytes it already took; it takes no more, so a flush still in flight would be cut short.
    private void ShutdownWriteNow()
    {
        if (Interlocked.Exchange(ref _writeShutdown, 1) != 1)
        {
            Volatile.Write(ref _writeShutdownMs, _reactor.NowMs);   // the peer's time to close starts now
            Native.shutdown(ClientFd, Native.SHUT_WR);
        }
    }

    internal bool WriteShutdownDone => Volatile.Read(ref _writeShutdown) == 1;   // or suppressed

    /// <summary>
    /// Half-close, <c>shutdown(SHUT_WR)</c>: the peer gets a FIN once what has been flushed is out, and
    /// the connection stays - its read side open, its descriptor still released by <see cref="DecRef"/>.
    /// For a protocol layer that is done sending (HTTP's <c>Connection: close</c>). Nothing may be
    /// written after it. A flush still in flight defers it to the tick after that flush is done; a
    /// connection the reactor already tore down gets none. Reactor thread only (#211).
    /// </summary>
    public void ShutdownWrite()
    {
        if (!FlushOutstanding)
        {
            ShutdownWriteNow();
        }
        else if (Interlocked.CompareExchange(ref _writeShutdown, 2, 0) == 0)   // not over one made, suppressed or already deferred
        {
            _reactor.DeferWriteShutdown(Slot, TagGen);
        }
    }

    /// <summary>
    /// Reactor thread, from the tick: makes the write shutdown deferred behind a flush, once that flush
    /// is over. False while it is still in flight.
    /// </summary>
    internal bool RunDeferredWriteShutdown()
    {
        if (Volatile.Read(ref _writeShutdown) == 2)
        {
            if (FlushOutstanding)
            {
                return false;
            }
            ShutdownWriteNow();
        }

        return true;
    }

    /// <summary>
    /// Take this connection off the read timeout for the rest of its life - for an adapter whose
    /// read stays parked while its server works, to a server that keeps its own clocks (Kestrel).
    /// The bound on a peer that never closes once the handler has let go still applies.
    /// </summary>
    public void DisableReadTimeout() => Volatile.Write(ref _readTimeoutDisabled, 1);

    // The peer owes the next move: a read is parked on a connection still on the read timeout, or
    // the handler let go and the write side is shut down. The server's own sends restart the clock; the
    // sweep skips it during a flush.
    internal bool WaitingOnPeer(out long sinceMs)
    {
        if (HandlerReleased)
        {
            sinceMs = Volatile.Read(ref _writeShutdownMs);   // 0 until it is made
            return sinceMs != 0;
        }

        if (Volatile.Read(ref _readWaiter) == null || Volatile.Read(ref _readTimeoutDisabled) != 0)
        {
            sinceMs = 0;
            return false;
        }

        sinceMs = Math.Max(Volatile.Read(ref ReadParkedMs), Math.Max(Volatile.Read(ref FlushArmedMs), FlushSeenMs));
        return true;
    }

    // Set by the handler's release, whoever makes it - the handler or the fault path; reset per pool life (#94).
    private int _handlerRefReleased;

    /// <summary>
    /// Release the handler's ref on behalf of a handler that faulted before its own DecRef, so the
    /// fd/slab/gid aren't leaked (#94). Generation-guarded - a fault observed after this connection
    /// was recycled must not touch its next life - and a no-op when the handler let go before it
    /// threw, as a try/finally DecRef does.
    /// </summary>
    internal void ReleaseHandlerRefOnFault(int generationAtStart)
    {
        if (Volatile.Read(ref _generation) == generationAtStart)
        {
            DecRef();
        }
    }

    internal void Clear()
    {
        // Bump generation first so stale IVTS tokens resolve to Closed()/no-op.
        Interlocked.Increment(ref _generation);
        ClearMove();

        // Normally empty already: the teardown's MarkClosed delivered to any read or flush parked here.
        Volatile.Write(ref _readWaiter, null);
        Volatile.Write(ref _pending, 0);
        Volatile.Write(ref _closed, 0);
        Volatile.Write(ref _recvOverflowed, 0);
        Volatile.Write(ref _flushArmed, 0);
        Volatile.Write(ref _flushInProgress, 0);
        _flushListener = null;
        Volatile.Write(ref FlushArmedMs, 0);
        Volatile.Write(ref ReadParkedMs, 0);
        FlushSeenMs = 0;
        Volatile.Write(ref _readTimeoutDisabled, 0);
        Volatile.Write(ref _writeShutdownMs, 0);
        Volatile.Write(ref _writeShutdown, 0);
        SweepClosed = false;
        CloseAfterSend = false;

        WriteHead = 0;
        WriteTail = 0;
        WriteInFlight = 0;
        ZcNotifPending = 0;

        // Segmented: free the overflow segments, in use (a connection recycled mid-response) or kept, so the
        // pool doesn't retain them either.
        if (_ovCount > 0)
        {
            ReleaseOverflow();
        }
        FreeKeptSegments();

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
