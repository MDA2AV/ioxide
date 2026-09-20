using System.Runtime.InteropServices;
using ioxide.utils;
using static ioxide.Native;

namespace ioxide;

// Loop - Incremental, Ring per connection

/// <summary>
/// Incremental-buffer (IOU_PBUF_RING_INC) path: each connection gets its own buffer ring, and one
/// buffer accumulates its byte stream across many recvs. A buffer recycles only when the kernel is
/// done appending AND the handler returned every slice. Selected by ServerConfig.Incremental.
/// </summary>
public sealed unsafe partial class Reactor
{
    private Stack<ushort>?  _freeGids;
    private Mpsc<ulong>? _returnQInc;

    private void InitIncremental()
    {
        // GID 1 reserved; per-conn GIDs 2..MaxConnections+1.
        _freeGids = new Stack<ushort>(_maxConnections);
        for (int g = _maxConnections + 1; g >= 2; g--)
        {
            _freeGids.Push((ushort)g);
        }

        _returnQInc = new Mpsc<ulong>(1 << 16);
    }

    private ushort AllocGid() => _freeGids!.Pop();
    private void   FreeGid(ushort gid) => _freeGids!.Push(gid);

    private void SetupConnectionBufRing(TcpConnection conn)
    {
        ushort gid = AllocGid();
        int entries = _connBufRingEntries;

        // Allocations are reused across pool lives; only the kernel registration is per-life.
        if (conn.BufRing == null)
        {
            conn.BufRing = (byte*)NativeMemory.AlignedAlloc((nuint)entries * 16, 4096);
        }
        NativeMemory.Clear(conn.BufRing, (nuint)entries * 16);

        if (conn.BufSlab == null)
        {
            conn.BufSlab = (byte*)NativeMemory.AlignedAlloc((nuint)entries * (nuint)_incRecvBufferSize, 64);
        }

        conn.CumOffset  ??= new int[entries];
        conn.RefCount   ??= new int[entries];
        conn.KernelDone ??= new bool[entries];
        Array.Clear(conn.CumOffset, 0, entries);
        Array.Clear(conn.RefCount, 0, entries);
        Array.Clear(conn.KernelDone, 0, entries);

        var reg = new io_uring_buf_reg
        {
            ring_addr    = (ulong)conn.BufRing,
            ring_entries = (uint)entries,
            bgid         = gid,
            flags        = IOU_PBUF_RING_INC,
        };
        int ret = io_uring_register(_ring.Fd, IORING_REGISTER_PBUF_RING, &reg, 1);
        if (ret < 0)
        {
            throw new InvalidOperationException($"register pbuf_ring (inc) failed with errno {-ret}, gid={gid}");
        }

        conn.Bgid            = gid;
        conn.BufRingEntries  = entries;
        conn.BufRingMask     = (uint)(entries - 1);
        conn.IncrementalMode = true;

        for (ushort bid = 0; bid < entries; bid++)
        {
            byte* slot = conn.BufRing + (uint)bid * 16;
            *(ulong*)(slot + 0)   = (ulong)(conn.BufSlab + bid * (nuint)_incRecvBufferSize);
            *(uint*)(slot + 8)    = _incRecvBufferSize;
            *(ushort*)(slot + 12) = bid;
        }
        Volatile.Write(ref *(ushort*)(conn.BufRing + 14), (ushort)entries);
    }

    private void TeardownConnectionBufRing(TcpConnection conn)
    {
        if (conn.IncrementalMode)
        {
            // Recycle() cancelled the multishot recv first, so the kernel won't select
            // from this group again before unregister.
            var reg = new io_uring_buf_reg { bgid = conn.Bgid };
            io_uring_register(_ring.Fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);
            FreeGid(conn.Bgid);
        }
        // Allocations stay for pool reuse.
    }

    // Re-add a fully-consumed buffer to its connection's ring. Reactor-thread-only.
    private void ReturnConnectionBuffer(TcpConnection conn, ushort bid)
    {
        conn.CumOffset![bid]  = 0;
        conn.RefCount![bid]   = 0;
        conn.KernelDone![bid] = false;

        ushort tail = Volatile.Read(ref *(ushort*)(conn.BufRing + 14));
        byte* slot  = conn.BufRing + (tail & conn.BufRingMask) * 16;
        *(ulong*)(slot + 0)   = (ulong)(conn.BufSlab + bid * (nuint)_incRecvBufferSize);
        *(uint*)(slot + 8)    = _incRecvBufferSize;
        *(ushort*)(slot + 12) = bid;
        Volatile.Write(ref *(ushort*)(conn.BufRing + 14), (ushort)(tail + 1));
        _buffersReturned = true;   // lets the loop re-arm recvs parked on -ENOBUFS (#93)
    }

    // Return queue payload: fd in the high 32 bits, gen in the next 16, bid in the low 16.
    private static ulong PackReturn(int fd, ushort gen, ushort bid)
        => ((ulong)(uint)fd << 32) | ((ulong)gen << 16) | bid;

    private static void UnpackReturn(ulong packed, out int fd, out ushort gen, out ushort bid)
    {
        fd  = (int)(packed >> 32);
        gen = (ushort)((packed >> 16) & 0xFFFF);
        bid = (ushort)(packed & 0xFFFF);
    }

    // Safe from any thread.
    public void EnqueueReturnQIncremental(int fd, ushort gen, ushort bid)
    {
        if (Environment.CurrentManagedThreadId == _reactorThreadId)
        {
            ApplyReturnIncremental(fd, gen, bid);
            return;
        }
        ulong packed = PackReturn(fd, gen, bid);
        SpinWait sw = default;
        while (!_returnQInc!.TryEnqueue(packed))
        {
            sw.SpinOnce();
        }
        WakeFdWrite();
    }

    private void DrainReturnQIncremental()
    {
        while (_returnQInc!.TryDequeue(out ulong packed))
        {
            UnpackReturn(packed, out int fd, out ushort gen, out ushort bid);
            ApplyReturnIncremental(fd, gen, bid);
        }
    }

    private void ApplyReturnIncremental(int fd, ushort gen, ushort bid)
    {
        // The gen check also rejects stale returns from a reused fd's previous life.
        TcpConnection? conn = ConnAt(fd, gen);
        if (conn is not { IncrementalMode: true })
        {
            return;
        }

        conn.RefCount![bid]--;
        if (conn.RefCount[bid] <= 0 && conn.KernelDone![bid])
        {
            ReturnConnectionBuffer(conn, bid);
        }
    }

    private void LoopIncremental()
    {
        while (!_stopRequested)
        {
            DrainReturnQIncremental();
            DrainFlushQ();
            DrainRecycleQ();
            DrainRemoteOps();
            DrainPostQ();
            RearmStarvedRecvs();
            QuicFireDueTimers();

            // These three are the transient ones and the loop simply carries on: EINTR is a signal,
            // EAGAIN is the kernel short of resources, EBUSY means overflow entries could not be
            // flushed - and the fall-through below drains the CQ, which is exactly what EBUSY wants.
            // Until #220 this comparison could never match, because the wrapper returned -1 for
            // every failure, so the first signal delivered to a reactor thread ended it.
            //
            // Anything else is a lifecycle or programming error (EBADF, EINVAL, ENXIO on a dying
            // ring). Throwing rather than breaking, because a reactor that vanishes while the
            // process keeps reporting healthy is the worst of both. Run's finally tears the ring
            // down; whether the process then dies is the host's decision, via Reactor.OnFault -
            // on a bare Thread with no handler, an unhandled exception ends the process.
            int rc = _ring.SubmitAndWait(1);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN && rc != -EBUSY)
            {
                throw new InvalidOperationException(
                    $"[r{_id}] io_uring_enter failed with errno {-rc}; this reactor cannot continue");
            }

            NowMs = Environment.TickCount64;   // one read per batch; see Reactor.Tcp.Sweep.cs

            uint ready = _ring.CqReady();
            for (uint i = 0; i < ready; i++)
            {
                DispatchIncremental(in _ring.CqeAt(i));
            }
            _ring.CqAdvance(ready);
        }
    }

    private void DispatchIncremental(in IoUringCqe cqe)
    {
        byte   kind = (byte)(cqe.user_data >> KindShift);
        ushort gen  = (ushort)(cqe.user_data >> GenShift);
        int    fd   = (int)(uint)cqe.user_data;
        bool   more = (cqe.flags & IORING_CQE_F_MORE) != 0;

        switch (kind)
        {
            case KindTcpRecv:
                OnTcpRecvCompletionIncremental(fd, gen, cqe.res, cqe.flags);
                return;

            case KindTcpSend:
                OnSendCompletion(fd, gen, cqe.res, cqe.flags);
                return;

            case KindClient:
                OnClientCompletion(fd, cqe.res);
                return;

            case KindTcpAccept:
                OnTcpAcceptCompletion(fd, cqe.res, more);
                return;

            case KindUdpRecv:
                OnUdpRecvCompletion(fd, cqe.res, cqe.flags);
                return;

            case KindUdpSend:
                OnUdpSendCompletion(fd, cqe.res);
                return;

            case KindWake:
                OnWakeCompletion(more);
                return;

            case KindTimer:
                OnTimerTick();
                return;

            case KindCancel:
                return;
        }
    }
}
