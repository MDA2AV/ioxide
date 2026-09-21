using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using ioxide.utils;
using static ioxide.Native;

namespace ioxide;

public sealed unsafe partial class Reactor
{
    private readonly Mpsc<ushort> _returnQ = new(1 << 14);
    private readonly Mpsc<ulong>  _flushQ  = new(1 << 12);   // (gen << 32) | fd

    // Recycle must run on the reactor (buf_ring + pool are reactor-owned). TcpConnection is a
    // ref type, so this queue is a ConcurrentQueue rather than the unmanaged Mpsc<T>.
    private readonly ConcurrentQueue<TcpConnection> _recycleQ = new();

#region Wake

    // Writers currently holding the eventfd's number, so Teardown can wait them out before it
    // closes. Without the gate a writer that read the old number puts 8 bytes into whatever socket
    // took it next. Off-reactor callers only, next to a syscall, so the two interlocks are free.
    // Reading 0 means the reactor is gone and there is nothing to wake.
    private int _wakeUsers;

    private void WakeFdWrite()
    {
        Interlocked.Increment(ref _wakeUsers);
        try
        {
            int fd = Volatile.Read(ref _wakeFd);
            if (fd > 0)
            {
                ulong v = 1;
                write(fd, &v, 8);   // eventfd becomes readable → multishot poll CQE wakes the loop
            }
        }
        finally
        {
            Interlocked.Decrement(ref _wakeUsers);
        }
    }

    private void ArmWakePoll()
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_POLL_ADD;
        sqe->fd        = _wakeFd;
        sqe->op_flags  = POLLIN;                  // poll32_events
        sqe->len       = IORING_POLL_ADD_MULTI;
        sqe->user_data = Tag(KindWake, 0, _wakeFd);
    }

#endregion

#region Return

    public void EnqueueReturnQ(ushort bid)
    {
        if (Environment.CurrentManagedThreadId == _reactorThreadId)
        {
            ReturnBufferDirect(bid);
            return;
        }
        SpinWait sw = default;
        while (!_returnQ.TryEnqueue(bid))
        {
            sw.SpinOnce();
        }
        // Without the wake, a queued return waits for an unrelated CQE; if the ring
        // drains meanwhile, recvs fail with ENOBUFS.
        WakeFdWrite();
    }

    private void DrainReturnQ()
    {
        bool any = false;
        while (_returnQ.TryDequeue(out ushort bid))
        {
            ReturnBufferLocal(bid);
            any = true;
        }
        if (any)
        {
            PublishBufRingTail();
        }
    }

#endregion

#region Recycle

    // Called by TcpConnection.DecRef at refcount 0.
    internal void EnqueueRecycle(TcpConnection conn)
    {
        if (Environment.CurrentManagedThreadId == _reactorThreadId)
        {
            Recycle(conn, conn.ClientFd);
            return;
        }
        _recycleQ.Enqueue(conn);
        WakeFdWrite();
    }

    private void DrainRecycleQ()
    {
        while (_recycleQ.TryDequeue(out TcpConnection? conn))
        {
            Recycle(conn, conn.ClientFd);
        }
    }

    private void Recycle(TcpConnection conn, int fd)
    {
        conn.MarkClosed();
        SubmitCancel(Tag(KindTcpRecv, (ushort)conn.Generation, fd));   // before Clear() bumps the generation

        // Before DrainRecv, which only sees what is still QUEUED: a reader or stream that pulled
        // buffers out holds the only record of them, and nothing obliges a handler to give them
        // back. A holder can still be GROWING when it gets here: MarkClosed completes a parked read
        // inline, which runs the reader's ingest and dequeues more items - that happens on whichever
        // path marked the connection closed first, so by now the chain holds everything it ever will.
        //
        // Shared mode is where this matters: a stranded id is gone from the one group the reactor
        // draws from. Incremental mode frees the per-connection ring wholesale just below.
        conn.ReleaseHeldRecvBuffers();

        if (_incremental)
        {
            TeardownConnectionBufRing(conn);   // per-conn ring freed wholesale
        }
        else
        {
            conn.DrainRecv();   // return leftover buffers to the shared ring
        }
        // The kernel may still be reading the write slab. io_uring copies from user memory when the
        // socket drains, not at submit, so closing the fd and handing this object back to the pool
        // now is exactly how the previous peer ends up receiving the next connection's bytes (#221).
        // Hold everything - fd, slab, object - until the send's terminal CQE lands.
        //
        // TrackDrainingSend already put this connection on _sendDraining, at the instant it left the
        // connection table; all that is decided here is who finishes the recycle. Refs are gone, so
        // if the kernel is done it is this call, and if it is not it is the completion.
        if (conn.SendsInFlight > 0)
        {
            conn.RecycleDeferred = true;

            // Best effort, and only a latency win: correctness comes from waiting for the CQE, not
            // from the cancel landing. A send that already completed answers -ENOENT, which is the
            // ordinary case and needs no handling.
            SubmitCancel(Tag(KindTcpSend, (ushort)conn.Generation, fd));

            return;
        }

        FinishRecycle(conn, fd);
    }

    /// <summary>
    /// Start holding a connection that is leaving the connection table with a send the kernel has
    /// not finished with. Called by every path that nulls the table slot.
    /// </summary>
    /// <remarks>
    /// It has to happen HERE, not in <see cref="Recycle"/>. Recycle runs at refcount zero, which is
    /// both refs - and the reactor's goes first, while the handler may still be parked on something
    /// that is not this connection (a pg query, an upstream request, a delay). In that window the
    /// connection is off the table and not yet draining, so a send completing in it found no owner
    /// at all: the count was never decremented, and the connection then sat in _sendDraining for
    /// the life of the process, never closing its fd and never returning to the pool.
    /// </remarks>
    private void TrackDrainingSend(TcpConnection conn)
    {
        if (conn.SendsInFlight > 0)
        {
            conn.DrainingSince = NowMs;
            _sendDraining.Add(conn);
        }
    }

    /// <summary>
    /// The half of recycle that must wait for the kernel: close the fd, reset the connection and
    /// pool it. Runs once, either inline from <see cref="Recycle"/> or later from the send's
    /// terminal completion.
    /// </summary>
    private void FinishRecycle(TcpConnection conn, int fd)
    {
        close(fd);
        conn.Clear();

        if (_pool.Count < _poolMax)
        {
            _pool.Push(conn);
        }
        else
        {
            conn.Dispose();
        }
    }

    /// <summary>
    /// Terminal completion for a send on a connection that is torn down but not yet recycled.
    /// </summary>
    /// <remarks>
    /// Deliberately separate from <see cref="OnSendCompletion"/>'s normal path, and it must stay
    /// that way. A cancelled send reports the bytes it managed to transfer, not -ECANCELED - only a
    /// send with zero progress gives that - so to the normal path a cancelled send is
    /// indistinguishable from a partial one, and the partial branch RESUBMITS the remainder - onto
    /// a connection that is already torn down, with nobody left to wait for it, restarting the very
    /// hold this exists to end.
    ///
    /// Nothing here inspects res. Success, error and -ECANCELED all mean the same thing - the
    /// kernel has finished with the slab.
    /// </remarks>
    private void FinishDrainingSend(int fd, ushort gen, uint cqeFlags)
    {
        for (int i = 0; i < _sendDraining.Count; i++)
        {
            TcpConnection conn = _sendDraining[i];
            if (conn.ClientFd != fd || (ushort)conn.Generation != gen)
            {
                continue;
            }

            // A ZC data CQE still has its notif to come; the slab is not free yet.
            if ((cqeFlags & IORING_CQE_F_MORE) != 0)
            {
                return;
            }

            if (--conn.SendsInFlight > 0)
            {
                return;
            }

            // The kernel is done. Whether the connection can be recycled is a separate question:
            // it is held here from the moment it left the table, which can be well before its
            // handler let go. Recycle sets the flag when the refs have run out.
            _sendDraining.RemoveAt(i);

            if (conn.RecycleDeferred)
            {
                FinishRecycle(conn, fd);
            }

            return;
        }
    }

    /// <summary>
    /// Connections that have left the connection table with a send the kernel has not finished
    /// with. Their handler may still be running, so being here does not imply a pending recycle -
    /// RecycleDeferred is what says that. Normally empty; walked only when it is not.
    /// </summary>
    private readonly List<TcpConnection> _sendDraining = [];

    /// <summary>
    /// Forces a decision on connections whose send has not completed. Called from the reactor's
    /// ticker alongside <see cref="TcpSweep"/>.
    /// </summary>
    /// <remarks>
    /// The idle and send sweeps walk the connection table, and a deferred connection has already
    /// been removed from it by whichever path tore it down - so SendTimeoutMs cannot see exactly
    /// the connections it exists to bound. This is that clock, for the deferred set.
    ///
    /// Two things happen here, on different clocks. The cancel is re-issued on the FIRST pass,
    /// because the one submitted at track time reliably answers -ENOENT: issued in the same loop
    /// iteration as the FIN that tore the connection down, it does not find the send. One tick
    /// later it answers -EALREADY and the send's CQE arrives in the same batch - the difference
    /// between releasing the fd in 250ms and holding it for the whole deadline.
    ///
    /// shutdown() is the deadline's answer, a syscall that takes effect now rather than a request
    /// the ring has to match: it completes a wedged plain send with whatever it transferred and
    /// fails any retry with EPIPE. It does NOT bound a zero-copy send, whose notif waits on skb
    /// release and which shutdown does not purge from the write queue - see #245.
    ///
    /// Never force-finishes. Recycling a connection whose send the kernel has not given back is
    /// precisely the defect this exists to prevent, so a connection that will not drain is held,
    /// not reclaimed.
    /// </remarks>
    private void SweepDrainingSends()
    {
        // The deferred set is the one case SendTimeoutMs = 0 must not leave unbounded: without a
        // clock here, a peer that refuses to read pins an fd and a slab for the life of the process.
        int deadline = _sendTimeoutMs > 0 ? _sendTimeoutMs : 60_000;

        for (int i = 0; i < _sendDraining.Count; i++)
        {
            TcpConnection conn = _sendDraining[i];

            if (!conn.CancelRetried)
            {
                conn.CancelRetried = true;
                SubmitCancel(Tag(KindTcpSend, (ushort)conn.Generation, conn.ClientFd));
            }

            if (conn.SweepClosed || NowMs - conn.DrainingSince <= deadline)
            {
                continue;
            }

            conn.SweepClosed = true;
            shutdown(conn.ClientFd, SHUT_RDWR);
            SubmitCancel(Tag(KindTcpSend, (ushort)conn.Generation, conn.ClientFd));
        }
    }

    /// <summary>
    /// Last resort at reactor shutdown: the ring is about to go, so no further CQE will arrive and
    /// these fds have no other owner. Closing them releases the kernel's reference to the socket.
    /// </summary>
    private void CloseDrainingSends()
    {
        foreach (TcpConnection conn in _sendDraining)
        {
            close(conn.ClientFd);
        }

        _sendDraining.Clear();
    }

#endregion

#region Flush

    internal void EnqueueFlush(int fd, int gen)
    {
        if (Environment.CurrentManagedThreadId == _reactorThreadId)
        {
            TcpConnection? conn = ConnAt(fd, (ushort)gen);
            if (conn != null)
            {
                SubmitFlush(conn, fd, (ushort)gen);
            }
            return;
        }
        ulong packed = ((ulong)(ushort)gen << 32) | (uint)fd;
        SpinWait sw = default;
        while (!_flushQ.TryEnqueue(packed))
        {
            sw.SpinOnce();
        }
        WakeFdWrite();

    }
    private void DrainFlushQ()
    {
        while (_flushQ.TryDequeue(out ulong packed))
        {
            int    fd  = (int)(uint)packed;
            ushort gen = (ushort)(packed >> 32);
            // Gen check drops flushes for connections that closed (or whose fd was reused)
            // after queuing.
            TcpConnection? conn = ConnAt(fd, gen);
            if (conn == null)
            {
                continue;
            }
            SubmitFlush(conn, fd, gen);
        }
    }

    // Submits the right send for a pending flush: a vectored SENDMSG for a segmented (multi-segment)
    // response, or the plain contiguous SEND for everything else (incl. the fast path and Grow mode).
    private void SubmitFlush(TcpConnection conn, int fd, ushort gen)
    {
        if (conn.FlushVectored)
        {
            SubmitSendMsg(conn, fd, gen);
        }
        else
        {
            SubmitSend(conn, fd, gen, conn.WriteBuffer, (uint)conn.WriteInFlight, conn.SendOpFlags);
        }
    }

#endregion
}
