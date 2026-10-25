using System.Threading.Tasks.Sources;
using ioxide.utils;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Read side. The handler may run on any thread. A read that has to wait parks in one slot,
/// _readWaiter: it claims the slot, readies its value task, then publishes itself there, and only the
/// completion that takes it back delivers - while a sticky _pending keeps a completion that found
/// nothing parked for the next read. Pool-managed: _generation invalidates awaiters from a previous
/// life.
/// </summary>
public sealed unsafe partial class TcpConnection : IValueTaskSource<RecvSnapshot>, IRecvListener
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

    // The read parked on this connection, or null: the adapter that parked itself, or this connection
    // for ReadAsync's awaiter. While a read readies its listener the slot holds Claimed, or
    // ClaimedWoken once a completion has come to it meanwhile. The one field the park and the
    // completion race on.
    private IRecvListener? _readWaiter;

    // Marks, never called: a read that has claimed the slot and is readying its listener - no completion
    // delivers to it - and one a completion came to meanwhile, which serves what is queued instead.
    private static readonly IRecvListener Claimed = new SlotMark();
    private static readonly IRecvListener ClaimedWoken = new SlotMark();

    private sealed class SlotMark : IRecvListener
    {
        public void OnParking() { }

        public void OnRecvReady(RecvSnapshot snapshot) { }
    }

    private int _pending;
    private int _closed;

    private readonly SpscRecvRing _recv;   // sized by TcpOptions.RecvQueueEntries

    /// <summary>
    /// Whether this connection has been torn down. A writer needs this: once it is true nothing
    /// will ever drain what it stages, so continuing to buffer is not backpressure, it is a leak.
    /// </summary>
    public bool IsClosed => Volatile.Read(ref _closed) == 1;

    /// <summary>
    /// Whether a receive-queue overflow closed this connection (<see cref="TcpOptions.RecvQueueEntries"/>):
    /// the delivery that did not fit was dropped, so the closed snapshot that follows is not the peer's clean
    /// end. The pipe readers report it as an <see cref="System.IO.IOException"/>.
    /// </summary>
    public bool RecvOverflowed => Volatile.Read(ref _recvOverflowed) != 0;

    private int _recvOverflowed;

    internal static IOException RecvOverflowError()
        => new("The connection's receive queue overflowed (TcpOptions.RecvQueueEntries): data was dropped and the connection closed.");

    public ValueTask<RecvSnapshot> ReadAsync()
    {
        // Generation is the IVTS token: a Clear() during pool recycle invalidates this awaiter.
        int gen = Volatile.Read(ref _generation);

        // The connection parks itself: its OnParking readies _readSignal, its OnRecvReady completes it.
        return TryReadOrPark(this, out RecvSnapshot snapshot)
            ? new ValueTask<RecvSnapshot>(snapshot)
            : new ValueTask<RecvSnapshot>(this, (short)gen);
    }

    /// <summary>
    /// The one way a read waits - for <see cref="ReadAsync"/>, and for an adapter that parks itself
    /// instead of an awaiter: true with the snapshot when one is ready now, false when
    /// <paramref name="listener"/> was parked - and then the completion that takes the park back
    /// calls it, once, on the completing thread.
    /// </summary>
    internal bool TryReadOrPark(IRecvListener listener, out RecvSnapshot snapshot)
    {
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1)
        {
            return Serve(out snapshot);
        }

        if (Volatile.Read(ref _closed) != 0)
        {
            snapshot = RecvSnapshot.Closed();
            return true;
        }

        // A read overlapping a parked one is refused before it writes anything - the read clock below
        // included.
        if (Volatile.Read(ref _readWaiter) != null)
        {
            throw new InvalidOperationException("ReadAsync already armed.");
        }

        ReadParkedMs = _reactor.NowMs;   // the read clock; before the claim, so the sweep sees both

        // The claim. The slot is this read's from here, so one racing it is refused having touched
        // nothing of it - the listener's value task above all, which the two may share. No completion
        // delivers to a claim; the park is published below.
        if (Interlocked.CompareExchange(ref _readWaiter, Claimed, null) != null)
        {
            throw new InvalidOperationException("ReadAsync already armed.");
        }

        // Race recovery: data or a close landed between the checks above and the claim.
        if (!_recv.IsEmpty() || Volatile.Read(ref _pending) == 1 || Volatile.Read(ref _closed) != 0)
        {
            Volatile.Write(ref _readWaiter, null);
            return Serve(out snapshot);
        }

        listener.OnParking();   // its value task, ready before the park: the completion can follow at once

        // The park. A completion that came while the listener was being readied marked the claim
        // instead of delivering, and then this read serves what it queued.
        if (Interlocked.CompareExchange(ref _readWaiter, listener, Claimed) != Claimed)
        {
            Volatile.Write(ref _readWaiter, null);
            return Serve(out snapshot);
        }

        snapshot = default;
        return false;
    }

    // A read that does not wait: what is queued now, and whether the connection has closed.
    private bool Serve(out RecvSnapshot snapshot)
    {
        Volatile.Write(ref _pending, 0);
        snapshot = new RecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0);
        return true;
    }

    // The completion side of the park, after what it brought is queued (or the close is set): the read
    // parked, if any, is taken back and handed what is queued; a claim still readying its listener is
    // marked, and serves that itself; with nothing parked, _pending makes the next read return at once.
    private void DeliverRead()
    {
        IRecvListener? waiter = Volatile.Read(ref _readWaiter);
        while (true)
        {
            if (waiter == null || waiter == ClaimedWoken)
            {
                // Nothing to deliver to, as far as that read saw. Fenced and read again before leaving
                // it at that, so a read claiming the slot from here on sees what this completion queued.
                Interlocked.MemoryBarrier();
                IRecvListener? again = Volatile.Read(ref _readWaiter);
                if (again != waiter)
                {
                    waiter = again;
                    continue;
                }

                if (waiter == null)
                {
                    Volatile.Write(ref _pending, 1);
                }
                return;
            }

            // A park, taken back - or a claim, marked. Lost to the read moving on, or to another
            // completion: look again.
            IRecvListener? seen = Interlocked.CompareExchange(ref _readWaiter, waiter == Claimed ? ClaimedWoken : null, waiter);
            if (seen != waiter)
            {
                waiter = seen;
                continue;
            }

            if (waiter != Claimed)
            {
                waiter.OnRecvReady(new RecvSnapshot(_recv.SnapshotTail(), Volatile.Read(ref _closed) != 0));
            }
            return;
        }
    }

    // ReadAsync parks the connection itself, and its awaiter's value task is _readSignal.
    void IRecvListener.OnParking() => _readSignal.Reset();

    void IRecvListener.OnRecvReady(RecvSnapshot snapshot) => _readSignal.SetResult(snapshot);

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

    /// <summary>
    /// Nothing to do any more. Code written for the earlier contract calls this after every read, to
    /// recycle the value task the next one waits on; <see cref="ReadAsync"/> now readies that itself,
    /// when it parks. Calling it is harmless - including while a read is parked, which used to throw
    /// that read's continuation away.
    /// </summary>
    public void ResetRead() { }

    /// <summary>
    /// Wakes a parked <see cref="ReadAsync"/> with whatever is queued, possibly nothing, the way a
    /// recv completion does. Reactor thread only.
    /// </summary>
    internal void WakeRead() => DeliverRead();

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
            Volatile.Write(ref _recvOverflowed, 1);
            if (hasBuffer && !IncrementalMode)
            {
                _reactor.ReturnBufferDirect(bid);   // per-conn rings are freed wholesale instead
            }
            return false;
        }

        DeliverRead();
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
