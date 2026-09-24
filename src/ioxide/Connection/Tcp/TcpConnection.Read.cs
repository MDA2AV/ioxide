using System.Threading.Tasks.Sources;
using ioxide.utils;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Read side. The handler may run on any thread; coordination uses Interlocked on the arm flag
/// plus a sticky _pending to close the lost-wakeup race. Pool-managed: _generation invalidates
/// awaiters from a previous life.
/// </summary>
public sealed unsafe partial class TcpConnection : IValueTaskSource<RecvSnapshot>
{
    internal TcpConnection SetFd(int fd)
    {
        ClientFd = fd;
        return this;
    }

    private ManualResetValueTaskSourceCore<RecvSnapshot> _readSignal = new()
    {
        RunContinuationsAsynchronously = false,
    };
    private int _armed;
    private int _pending;
    private int _closed;

    private readonly SpscRecvRing _recv;   // sized by TcpOptions.RecvQueueEntries

    /// <summary>
    /// Whether this connection has been torn down. A writer needs this: once it is true nothing
    /// will ever drain what it stages, so continuing to buffer is not backpressure, it is a leak.
    /// </summary>
    public bool IsClosed => Volatile.Read(ref _closed) == 1;

    public ValueTask<RecvSnapshot> ReadAsync()
    {
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1)
        {
            Volatile.Write(ref _pending, 0);
            return new ValueTask<RecvSnapshot>(
                new RecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
        }

        if (Volatile.Read(ref _closed) != 0)
        {
            return new ValueTask<RecvSnapshot>(RecvSnapshot.Closed());
        }

        // The read clock starts here (TcpOptions.ReadTimeoutMs). Stamped before arming, so a sweep
        // that sees the read parked also sees when it parked.
        ReadParkedMs = _reactor.NowMs;

        if (Interlocked.Exchange(ref _armed, 1) == 1)
        {
            throw new InvalidOperationException("ReadAsync already armed.");
        }

        // Generation is the IVTS token: a Clear() during pool recycle invalidates this awaiter.
        int gen = Volatile.Read(ref _generation);

        // Race recovery: re-check between arming and returning the task.
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1 || Volatile.Read(ref _closed) != 0)
        {
            Volatile.Write(ref _pending, 0);
            Interlocked.Exchange(ref _armed, 0);

            return new ValueTask<RecvSnapshot>(
                new RecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
        }

        return new ValueTask<RecvSnapshot>(this, (short)gen);
    }

    /// <summary>
    /// Take the next item of a snapshot. This is a DEQUEUE and it transfers ownership: every item
    /// with <c>HasBuffer</c> must be handed back with <see cref="ReturnBuffer"/>, exactly once.
    /// </summary>
    /// <remarks>
    /// The connection stops tracking the buffer here - it is out of the recv queue, so the teardown
    /// drain no longer sees it and nothing else will return it for you. In shared mode a buffer that
    /// is never handed back is a slot gone from the group the whole reactor draws from, for the life
    /// of the process. The adapters that hide buffers from their caller -
    /// <see cref="TcpConnectionPipeReader"/> and <see cref="TcpConnectionStream"/> - own that
    /// cleanup themselves (see <see cref="IRecvBufferHolder"/>); this is the raw seam, so returning
    /// the id is yours.
    /// </remarks>
    public bool TryGetItem(in RecvSnapshot snap, out SpscRecvRing.Item item)
        => _recv.TryDequeueUntil(snap.Tail, out item);

    /// <summary>
    /// Drain the snapshot into one array of memory views - the multi-item way to reconstruct a
    /// request that arrived fragmented. Build a sequence with ToReadOnlySequence(), parse, then
    /// hand everything back with <see cref="ReturnBuffers"/>. Allocates one array per call; the
    /// raw TryGetItem loop and TcpConnectionPipeReader remain the allocation-free paths.
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
        Array.Resize(ref memories, n);   // rare: an item carried no buffer
        return memories;
    }

    /// <summary>Return every buffer obtained from <see cref="GetSnapshotMemories"/> to its ring.</summary>
    public void ReturnBuffers(UnmanagedMemoryManager[] memories)
    {
        foreach (UnmanagedMemoryManager memory in memories)
        {
            if (IncrementalMode)
            {
                _reactor.EnqueueReturnQIncremental(ClientFd, memory.Gen, memory.BufferId);
            }
            else
            {
                _reactor.EnqueueReturnQ(memory.BufferId);
            }
        }
    }

    public void ResetRead() => _readSignal.Reset();

    // Returns false on recv-queue overflow; the reactor then tears the connection down.
    public bool Complete(int res, ushort bid, bool hasBuffer, byte* ptr)
    {
        if (!_recv.TryEnqueue(new SpscRecvRing.Item
                 {
                     Ptr = ptr,
                     Bid = bid,
                     Len = res,
                     HasBuffer = hasBuffer,
                     Gen = (ushort)Volatile.Read(ref _generation)
                 }))
        {
            Console.Error.WriteLine("[conn] recv queue overflow; closing connection.");
            if (hasBuffer && !IncrementalMode)
            {
                _reactor.ReturnBufferDirect(bid);   // per-conn rings are freed wholesale instead
            }
            return false;
        }

        if (Interlocked.Exchange(ref _armed, 0) == 1)
        {
            _readSignal.SetResult(new RecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
        }
        else
        {
            Volatile.Write(ref _pending, 1);
        }
        return true;
    }

    internal void DrainRecv()
    {
        // Return buffer IDs still sitting in the SPSC ring at teardown.
        while (_recv.TryDequeue(out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                _reactor.ReturnBufferDirect(item.Bid);
            }
        }
    }

    // IVTS: token = generation snapshot (cross-life guard); the core's own Version is
    // passed through for the mid-life dispatch.
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

        // This source only completes on the owning reactor thread, so the continuation already
        // runs where ReactorSynchronizationContext would post it. Strip the scheduling-context
        // flag or MRVTSC posts every resume to the mailbox instead of invoking it inline
        // (RunContinuationsAsynchronously=false only covers the null-context case).
        _readSignal.OnCompleted(continuation, state, _readSignal.Version,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }
}
