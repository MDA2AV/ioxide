using System.Runtime.InteropServices;
using epoxide.utils;

namespace epoxide;

/// <summary>
/// A TCP connection on a reactor's epoll set. Reads and writes are ordinary non-blocking syscalls
/// made by whichever thread calls them - the reactor's, for a handler running inline, or any other -
/// and only a read or a flush the socket cannot take yet waits on the reactor, which finishes it when
/// the socket's readiness arrives. One reader and one writer at a time, as with any stream.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    private readonly Reactor _reactor;

    internal Reactor Reactor => _reactor;

    public int ClientFd { get; private set; }

    /// <summary>The listener port this connection was accepted on; 0 for an outbound connection.</summary>
    public ushort ListenerPort { get; internal set; }

    /// <summary>
    /// The reader currently holding recv buffers taken out of this connection's queue, if any. Recycle
    /// asks it back through <see cref="ReleaseHeldRecvBuffers"/>, so a buffer a handler stranded by
    /// returning early does not depend on the caller remembering.
    /// </summary>
    internal IRecvBufferHolder? BufferHolder;

    /// <summary>Hand back whatever a holder is still holding, before the buffers stop being reachable.</summary>
    internal void ReleaseHeldRecvBuffers()
        => Interlocked.Exchange(ref BufferHolder, null)?.ReleaseHeldBuffers();

    // When the parked read started waiting (TcpOptions.ReadTimeoutMs). Stale once it completes.
    internal long ReadParkedMs;

    // The last sweep that found a flush outstanding: when the server was last seen sending.
    internal long FlushSeenMs;

    private int _readTimeoutDisabled;
    private long _finSentMs;
    private int _finSent;   // 0, 1 sent (or suppressed), 2 asked for behind a flush - the sweep sends it

    /// <summary>Set once the sweep has shut this connection down, so the next tick skips it.</summary>
    internal bool SweepClosed;

    // Bumped on Clear(); the low 16 bits serve as the value-task token, so an awaiter from a previous
    // pool life is detectable, and as the epoll data's generation.
    private int _generation;

    internal int Generation => Volatile.Read(ref _generation);

    // Two owners: the reactor and the handler. Set to 2 when a life begins; the descriptor closes only
    // at 0, so it is never closed under a handler that may be in a syscall on it.
    private int _refs;

    // Set by the handler's release, whoever makes it - the handler or the fault path; reset per life.
    private int _handlerRefReleased;

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

    internal TcpConnection SetFd(int fd)
    {
        ClientFd = fd;
        return this;
    }

    /// <summary>
    /// Mark the connection ended and wake whatever waits on it: a parked read gets the end, a parked
    /// flush is released with its bytes dropped. Reactor thread, or a teardown with no loop left.
    /// </summary>
    internal void MarkClosed()
    {
        Volatile.Write(ref _closed, 1);
        WakeParkedRead();
        ReleaseParkedFlush();
        FailParkedConnect();
    }

    internal void InitRefs()
    {
        Volatile.Write(ref _refs, 2);
        Volatile.Write(ref _handlerRefReleased, 0);
    }

    /// <summary>
    /// The handler's release. A peer still connected gets a FIN; the read side stays open until it
    /// closes, bounded by <see cref="TcpOptions.ReadTimeoutMs"/>. Any thread.
    /// </summary>
    public void DecRef()
    {
        // Once per life: a handler that lets go and then throws would otherwise be let go again by the
        // fault path, recycling the connection under the reactor's ref.
        if (Interlocked.Exchange(ref _handlerRefReleased, 1) != 0)
        {
            return;
        }

        // Before the decrement, while our ref keeps the descriptor open. A FIN now would cut a flush
        // still waiting on the socket short, so the sweep sends that one once it is done.
        if (Volatile.Read(ref _refs) == 2 && !FlushOutstanding)
        {
            SendFin();
        }

        if (Interlocked.Decrement(ref _refs) == 0)
        {
            _reactor.EnqueueRecycle(this);
            return;
        }

        // The reactor still holds it, and with edge-triggered events the peer's close may already have
        // come and been noted with nobody reading: the reactor has to look rather than wait for an edge.
        _reactor.Attend(this);
    }

    internal void ReleaseReactorRef()
    {
        if (Interlocked.Decrement(ref _refs) == 0)
        {
            _reactor.EnqueueRecycle(this);
        }
    }

    // The reactor ended the connection, so no FIN. Called before MarkClosed: the handler it wakes may
    // let go inline, while the reactor's ref is still held.
    internal void SuppressFin() => Volatile.Write(ref _finSent, 1);

    // Only meaningful while the reactor tracks the connection, i.e. its ref is held.
    internal bool HandlerReleased => Volatile.Read(ref _handlerRefReleased) != 0;

    internal void SendFin()
    {
        if (Interlocked.Exchange(ref _finSent, 1) != 1)
        {
            Volatile.Write(ref _finSentMs, _reactor.NowMs);   // the peer's time to close starts now
            Native.shutdown(ClientFd, Native.SHUT_WR);
        }
    }

    internal bool FinSent => Volatile.Read(ref _finSent) == 1;

    internal bool FinWanted => Volatile.Read(ref _finSent) == 2;

    /// <summary>
    /// Half-close: the peer gets a FIN once what has been flushed is out, and the connection stays -
    /// its read side open, its descriptor still released by <see cref="DecRef"/>. For a protocol layer
    /// that is done sending (HTTP's <c>Connection: close</c>). Nothing may be written after it.
    /// </summary>
    public void ShutdownWrite()
    {
        if (!FlushOutstanding)
        {
            SendFin();
        }
        else
        {
            Interlocked.CompareExchange(ref _finSent, 2, 0);
        }
    }

    /// <summary>
    /// Take this connection off the read timeout for the rest of its life - for an adapter whose read
    /// stays parked while its server works, to a server that keeps its own clocks.
    /// </summary>
    public void DisableReadTimeout() => Volatile.Write(ref _readTimeoutDisabled, 1);

    // The peer owes the next move: a read is parked on a connection still on the read timeout, or the
    // handler let go and its FIN is out.
    internal bool WaitingOnPeer(out long sinceMs)
    {
        if (HandlerReleased)
        {
            sinceMs = Volatile.Read(ref _finSentMs);   // 0 until the FIN is out
            return sinceMs != 0;
        }

        if (Volatile.Read(ref _rd) != RdParked || Volatile.Read(ref _readTimeoutDisabled) != 0)
        {
            sinceMs = 0;
            return false;
        }

        sinceMs = Math.Max(Volatile.Read(ref ReadParkedMs), Math.Max(Volatile.Read(ref FlushArmedMs), FlushSeenMs));
        return true;
    }

    /// <summary>
    /// Release the handler's ref on behalf of a handler that faulted before its own DecRef, so the
    /// descriptor and slab aren't leaked. Generation-guarded - a fault observed after this connection
    /// was recycled must not touch its next life - and a no-op when the handler let go before it threw.
    /// </summary>
    internal void ReleaseHandlerRefOnFault(int generationAtStart)
    {
        if (Volatile.Read(ref _generation) == generationAtStart)
        {
            DecRef();
        }
    }

    /// <summary>
    /// Read what a peer sends after its handler let go, and drop it, until the peer closes. Reactor
    /// thread only. Without it the end would never be seen: nobody reads, so the close sits behind
    /// unread bytes, and an edge-triggered set reports it only once.
    /// </summary>
    internal void DrainReleased()
    {
        byte* scratch = _reactor.Scratch;
        int size = _reactor.RecvBufferSize;

        // Bounded, so a peer that keeps sending cannot hold the reactor here; the rest is drained on
        // a later pass, after every other connection has had its turn.
        for (int pass = 0; pass < DrainPassesPerEdge; pass++)
        {
            nint n = Native.recv(ClientFd, scratch, (nuint)size, 0);
            if (n > 0)
            {
                continue;
            }

            if (n < 0)
            {
                int errno = Native.Errno;
                if (errno == Native.EINTR)
                {
                    continue;
                }
                if (errno == Native.EAGAIN)
                {
                    return;   // the next edge brings the reactor back here
                }
            }

            Volatile.Write(ref _peerGone, 1);
            _reactor.CloseFromReactor(this);
            return;
        }

        _reactor.AttendLater(this);
    }

    private const int DrainPassesPerEdge = 16;

    internal void Clear()
    {
        // Bump generation first so stale value-task tokens resolve to Closed()/no-op.
        Interlocked.Increment(ref _generation);

        Volatile.Write(ref _rd, RdIdle);
        Volatile.Write(ref _wr, WrIdle);
        Volatile.Write(ref _pending, 0);
        Volatile.Write(ref _closed, 0);
        Volatile.Write(ref _peerGone, 0);
        Volatile.Write(ref _flushInProgress, 0);
        Volatile.Write(ref FlushArmedMs, 0);
        Volatile.Write(ref ReadParkedMs, 0);
        FlushSeenMs = 0;
        Volatile.Write(ref _readTimeoutDisabled, 0);
        Volatile.Write(ref _finSentMs, 0);
        Volatile.Write(ref _finSent, 0);
        Volatile.Write(ref _connecting, 0);
        Volatile.Write(ref _readUntilEmpty, 0);
        SweepClosed = false;

        WriteHead = 0;
        WriteTail = 0;
        WriteInFlight = 0;

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
    }
}
