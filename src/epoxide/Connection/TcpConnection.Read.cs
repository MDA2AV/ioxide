using System.Threading.Tasks.Sources;
using epoxide.utils;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace epoxide;

/// <summary>
/// Read side, pulled by the reader. <see cref="ReadAsync"/> receives on the caller's own thread
/// while the socket has data, and parks only once it is empty; the reactor then receives on the
/// reader's behalf at the next readiness edge and completes the read. Pool-managed: the generation
/// invalidates awaiters from a previous life.
/// </summary>
public sealed unsafe partial class TcpConnection : IValueTaskSource<RecvSnapshot>
{
    // Who may receive, handed between the reader and the reactor with CAS so exactly one does:
    //   Idle   - the socket was found empty and no edge has come since: a reader parks.
    //   Ready  - an edge, or a recv that filled its buffer, since: a reader tries the socket.
    //   Parked - a reader waits, and the reactor receives for it on the next edge.
    private const int RdIdle = 0, RdReady = 1, RdParked = 2;
    private int _rd;

    private ManualResetValueTaskSourceCore<RecvSnapshot> _readSignal;
    private int _pending;   // a wake no reader was parked for, kept for the next ReadAsync
    private int _closed;
    private int _peerGone;

    private readonly SpscRecvRing _recv;   // sized by TcpOptions.RecvQueueEntries

    // What Receive found.
    private const int RecvEmpty = -1, RecvEnd = 0, RecvSome = 1, RecvFull = 2;

    /// <summary>
    /// Whether this connection has been torn down. A writer needs this: once it is true nothing
    /// will ever drain what it stages, so continuing to buffer is not backpressure, it is a leak.
    /// A peer's close is seen by the next read or a failed send, not before.
    /// </summary>
    public bool IsClosed => Volatile.Read(ref _closed) == 1;

    /// <summary>
    /// Always false: reads are pulled, so a reader that falls behind stops the reading and TCP pushes
    /// back on the peer, rather than a queue overflowing and dropping data. Kept for code written
    /// against ioxide, where it can be true.
    /// </summary>
    public bool RecvOverflowed => false;

    /// <summary>Whether the peer is gone: a recv saw its close or an error, or a send failed.</summary>
    internal bool PeerGone => Volatile.Read(ref _peerGone) != 0;

    private int _readUntilEmpty;

    /// <summary>
    /// Read until the socket says EAGAIN instead of stopping at the first short recv - for a socket
    /// whose recv can return short with more already waiting: kTLS RX stops at a record boundary, and
    /// a recv stops at the peer's FIN or an urgent mark, which the reactor sets this for. Costs one
    /// recv per read; set for the life of the connection, cleared on recycle.
    /// </summary>
    internal void ReadUntilEmpty() => Interlocked.Exchange(ref _readUntilEmpty, 1);

    // A new life, at accept or connect. The reactor has not seen an edge yet, so "may hold data" is a guess.
    internal void BeginLife(bool readable) => Volatile.Write(ref _rd, readable ? RdReady : RdIdle);

    public ValueTask<RecvSnapshot> ReadAsync()
    {
        // Received and not taken yet, a wake, or the end: answer now.
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1 || Volatile.Read(ref _closed) != 0)
        {
            Volatile.Write(ref _pending, 0);
            return new ValueTask<RecvSnapshot>(Snapshot());
        }

        while (true)
        {
            int state = Volatile.Read(ref _rd);
            if (state == RdReady)
            {
                if (Interlocked.CompareExchange(ref _rd, RdIdle, RdReady) != RdReady)
                {
                    continue;
                }

                int found = Receive();
                if (found == RecvFull)
                {
                    Interlocked.CompareExchange(ref _rd, RdReady, RdIdle);   // a full buffer may have left more behind
                }
                if (found == RecvEnd)
                {
                    OnPeerGone();
                }
                if (found != RecvEmpty)
                {
                    return new ValueTask<RecvSnapshot>(Snapshot());
                }

                continue;   // empty: park, unless an edge came in meanwhile
            }

            if (state == RdIdle)
            {
                _readSignal.Reset();
                ReadParkedMs = _reactor.NowMs;   // the read clock; before parking, so the sweep sees both

                if (Interlocked.CompareExchange(ref _rd, RdParked, RdIdle) != RdIdle)
                {
                    continue;
                }

                // MarkClosed sets _closed before it looks for a parked reader, so one of the two sees the other.
                if (Volatile.Read(ref _closed) != 0 && Interlocked.CompareExchange(ref _rd, RdIdle, RdParked) == RdParked)
                {
                    return new ValueTask<RecvSnapshot>(Snapshot());
                }

                // Generation is the token: a Clear() during recycle invalidates this awaiter.
                return new ValueTask<RecvSnapshot>(this, (short)Volatile.Read(ref _generation));
            }

            throw new InvalidOperationException("ReadAsync already armed.");
        }
    }

    // One recv into a pooled buffer, queued for the reader. The caller owns the receive - the reader
    // after taking Ready, or the reactor for a parked reader - so the queue, which is empty whenever a
    // read reaches the socket, has room.
    private int Receive()
    {
        BufferPool pool = _reactor.RecvPool;
        int size = pool.BufferSize;
        byte* buffer = pool.Rent(out int id);

        while (true)
        {
            nint n = Native.recv(ClientFd, buffer, (nuint)size, 0);
            if (n > 0)
            {
                _recv.TryEnqueue(new SpscRecvRing.Item
                {
                    Ptr = buffer,
                    Bid = id,
                    Len = (int)n,
                    HasBuffer = true,
                    Gen = (ushort)Volatile.Read(ref _generation),
                });
                // Short means the socket ran dry, and the next arrival raises a new edge - unless
                // ReadUntilEmpty says a short recv can have stopped in front of more.
                return n == size || Volatile.Read(ref _readUntilEmpty) != 0 ? RecvFull : RecvSome;
            }

            int errno = n < 0 ? Native.Errno : 0;
            if (errno == Native.EINTR)
            {
                continue;
            }

            pool.Return(id);
            return errno == Native.EAGAIN ? RecvEmpty : RecvEnd;
        }
    }

    // The peer closed or failed the connection, seen by whichever thread received or sent. Closed for
    // this connection's readers and writers at once; the reactor's end follows, inline or posted.
    private void OnPeerGone()
    {
        Volatile.Write(ref _peerGone, 1);
        Volatile.Write(ref _closed, 1);
        _reactor.Attend(this);
    }

    /// <summary>
    /// An edge reported the socket readable, closed or failed. Reactor thread only. Every state change
    /// happens before the reader is resumed: it may run inline, let the connection go, and leave this
    /// object recycled by the time the call returns.
    /// </summary>
    internal void OnReadable()
    {
        while (true)
        {
            int state = Volatile.Read(ref _rd);
            if (state == RdParked)
            {
                // The reader is parked, so nothing else moves the state until it is resumed.
                int found = Receive();
                if (found == RecvEmpty)
                {
                    return;   // nothing after all: it stays parked for the next edge
                }
                if (found == RecvEnd)
                {
                    OnPeerGone();   // the reactor's end wakes the parked reader with it
                    return;
                }

                Volatile.Write(ref _rd, found == RecvFull ? RdReady : RdIdle);
                _readSignal.SetResult(Snapshot());
                return;
            }

            if (HandlerReleased)
            {
                DrainReleased();
                return;
            }

            if (state == RdReady || Interlocked.CompareExchange(ref _rd, RdReady, RdIdle) == RdIdle)
            {
                return;
            }
        }
    }

    // Wake a parked read with whatever is queued and the closed state.
    private void WakeParkedRead()
    {
        if (Interlocked.CompareExchange(ref _rd, RdIdle, RdParked) == RdParked)
        {
            _readSignal.SetResult(Snapshot());
        }
    }

    /// <summary>
    /// Wakes a parked <see cref="ReadAsync"/> with whatever is queued, possibly nothing; with none
    /// parked, the next one returns at once. Reactor thread only.
    /// </summary>
    internal void WakeRead()
    {
        if (Interlocked.CompareExchange(ref _rd, RdIdle, RdParked) == RdParked)
        {
            _readSignal.SetResult(Snapshot());
        }
        else
        {
            Volatile.Write(ref _pending, 1);
        }
    }

    private RecvSnapshot Snapshot() => new(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0);

    /// <summary>
    /// Take the next item of a snapshot. This is a DEQUEUE and it transfers ownership: every item
    /// with <c>HasBuffer</c> must be handed back with <see cref="ReturnBuffer"/>, exactly once.
    /// </summary>
    /// <remarks>
    /// The connection stops tracking the buffer here, so nothing else will return it for you. The
    /// adapters that hide buffers from their caller - <see cref="TcpConnectionPipeReader"/> and
    /// <see cref="TcpConnectionStream"/> - own that cleanup themselves; this is the raw seam.
    /// </remarks>
    public bool TryGetItem(in RecvSnapshot snap, out SpscRecvRing.Item item)
        => _recv.TryDequeueUntil(snap.Tail, out item);

    /// <summary>
    /// Drain the snapshot into one array of memory views - the multi-item way to reconstruct a request
    /// that arrived fragmented. Hand everything back with <see cref="ReturnBuffers"/>. Allocates one
    /// array per call; the raw TryGetItem loop and TcpConnectionPipeReader are the allocation-free paths.
    /// </summary>
    public UnmanagedMemoryManager[] GetSnapshotMemories(in RecvSnapshot snap)
    {
        int count = _recv.CountUntil(snap.Tail);
        if (count == 0)
        {
            return [];
        }

        var memories = new UnmanagedMemoryManager[count];
        int n = 0;
        while (n < count && _recv.TryDequeueUntil(snap.Tail, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                memories[n++] = item.AsMemoryManager();
            }
        }

        if (n == count)
        {
            return memories;
        }
        Array.Resize(ref memories, n);
        return memories;
    }

    /// <summary>Return every buffer obtained from <see cref="GetSnapshotMemories"/> to the pool.</summary>
    public void ReturnBuffers(UnmanagedMemoryManager[] memories)
    {
        foreach (UnmanagedMemoryManager memory in memories)
        {
            _reactor.RecvPool.Return(memory.BufferId);
        }
    }

    /// <summary>Hand a consumed recv buffer back, from any thread.</summary>
    public void ReturnBuffer(in SpscRecvRing.Item item) => _reactor.RecvPool.Return(item.Bid);

    /// <summary>
    /// Kept for code written against ioxide, which resets its read source here; epoxide resets it in
    /// the next <see cref="ReadAsync"/>, so this does nothing.
    /// </summary>
    public void ResetRead()
    {
    }

    // Return what is still queued at recycle.
    internal void DrainRecv()
    {
        while (_recv.TryDequeue(out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                _reactor.RecvPool.Return(item.Bid);
            }
        }
    }

    // IVTS: token = generation snapshot (cross-life guard); the core's own Version is passed through.
    RecvSnapshot IValueTaskSource<RecvSnapshot>.GetResult(short token)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            return RecvSnapshot.Closed();
        }

        return _readSignal.GetResult(_readSignal.Version);
    }

    ValueTaskSourceStatus IValueTaskSource<RecvSnapshot>.GetStatus(short token)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            return ValueTaskSourceStatus.Succeeded;
        }

        return _readSignal.GetStatus(_readSignal.Version);
    }

    void IValueTaskSource<RecvSnapshot>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            // Stale - unblock now; GetResult returns Closed().
            continuation(state);
            return;
        }

        Continuations.OnCompleted(ref _readSignal, _reactor, continuation, state, _readSignal.Version, flags);
    }
}
