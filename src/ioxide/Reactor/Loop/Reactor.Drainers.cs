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
