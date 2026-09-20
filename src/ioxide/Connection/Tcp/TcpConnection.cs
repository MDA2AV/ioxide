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
    /// <see cref="TryGetItem"/> is a DEQUEUE: the moment a buffer is handed to a reader, the
    /// connection's queue no longer has it, so <see cref="DrainRecv"/> at recycle walks past it and
    /// the buffer comes back only if the reader is completed. Nothing enforced that - the plaintext
    /// <see cref="TcpConnectionDualPipe"/> has no disposal, unlike the TLS one - so a handler that
    /// returned early stranded a buffer per connection, and in shared mode those are slots out of
    /// the one group the whole reactor draws from.
    ///
    /// One reference, assigned once when a holder is constructed. Recycle asks it back through
    /// <see cref="ReleaseHeldRecvBuffers"/>, so the leak cannot depend on the caller remembering.
    /// </remarks>
    internal IRecvBufferHolder? BufferHolder;

    /// <summary>
    /// Hand back whatever a holder is still holding, before the buffers stop being reachable.
    /// Called from the reactor's recycle; a no-op when the holder completed normally, which is the
    /// common path.
    /// </summary>
    /// <remarks>
    /// The slot is claimed rather than read so the reclaim runs at most once, which is all this
    /// buys: the holder still walks its own chain on <c>Complete</c>, so it does not by itself make
    /// a double return impossible. What rules that out is the refcount protocol - recycle runs at
    /// refcount zero, so a conforming handler has finished with the connection before this is
    /// reached, exactly as everywhere else that touches it. A handler that DecRefs and then keeps
    /// using its reader is racing the reactor over the connection generally, not only here.
    /// </remarks>
    internal void ReleaseHeldRecvBuffers()
        => Interlocked.Exchange(ref BufferHolder, null)?.ReleaseHeldBuffers();

    /// <summary>
    /// Environment.TickCount64 at the last completion this connection saw in either direction -
    /// stamped at accept and on every recv and send completion, read by the reactor's sweep
    /// (Reactor.Tcp.Sweep.cs) against <see cref="TcpOptions.IdleTimeoutMs"/>.
    /// </summary>
    /// <remarks>
    /// A coarse tick rather than a precise clock on purpose: the sweep runs at ~250 ms and the
    /// timeouts it serves are second-scale, so the cheapest read that cannot fall back is enough.
    /// Reactor thread only, like the rest of the connection.
    /// </remarks>
    internal long LastActivityMs;

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

    /// <summary>Release one owner's ref; whoever hits 0 hands the connection to the reactor for recycle.</summary>
    public void DecRef()
    {
        if (Interlocked.Decrement(ref _refs) == 0)
        {
            _reactor.EnqueueRecycle(this);
        }
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
        LastActivityMs = _reactor.NowMs;
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
