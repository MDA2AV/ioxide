using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

// Loop - SharedRing
public sealed unsafe partial class Reactor
{
    private void InitSharedRingBuffer()
    {
        nuint ringBytes = (nuint)_bufferRingEntries * 16;
        _bufRing = (byte*)NativeMemory.AlignedAlloc(ringBytes, 4096);
        NativeMemory.Clear(_bufRing, ringBytes);

        nuint slabBytes = _bufferRingEntries * (nuint)_recvBufferSize;
        _bufSlab = (byte*)NativeMemory.AlignedAlloc(slabBytes, 64);

        _bufRingMask = _bufferRingEntries - 1;

        var reg = new io_uring_buf_reg {
            ring_addr    = (ulong)_bufRing,
            ring_entries = _bufferRingEntries,
            bgid         = BgId,
        };

        int ret = io_uring_register(_ring.Fd, IORING_REGISTER_PBUF_RING, &reg, 1);
        if (ret < 0)
        {
            int err = Marshal.GetLastPInvokeError();

            throw new InvalidOperationException($"register pbuf_ring failed: ret={ret} errno={err}");
        }

        // Slot 0 overlaps the ring's tail field at offset 14; writing only addr/len/bid
        // (offsets 0..13) keeps tail zero until published explicitly.
        for (ushort bid = 0; bid < _bufferRingEntries; bid++) {
            byte* slot = _bufRing + (uint)bid * 16;
            *(ulong*)(slot + 0)  = (ulong)(_bufSlab + bid * (nuint)_recvBufferSize);
            *(uint*)(slot + 8)   = _recvBufferSize;
            *(ushort*)(slot + 12) = bid;
        }
        _bufRingTail = (ushort)_bufferRingEntries;

        PublishBufRingTail();
    }

    private void LoopSharedRing()
    {
        while (!_stopRequested)
        {
            DrainReturnQ();
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
            // process keeps reporting healthy is the worst of both: Run's finally tears the ring
            // down and the exception reaches whoever started the thread.
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
                DispatchSharedRing(in _ring.CqeAt(i));
            }
            _ring.CqAdvance(ready);
        }
    }

    private void DispatchSharedRing(in IoUringCqe cqe)
    {
        byte   kind = (byte)(cqe.user_data >> KindShift);
        ushort gen  = (ushort)(cqe.user_data >> GenShift);
        int    fd   = (int)(uint)cqe.user_data;
        bool   more = (cqe.flags & IORING_CQE_F_MORE) != 0;

        switch (kind)
        {
            // TCP
            case KindTcpAccept:
                OnTcpAcceptCompletion(fd, cqe.res, more);
                return;

            case KindTcpRecv:
                OnTcpRecvCompletionShared(fd, gen, cqe.res, cqe.flags);
                return;

            case KindTcpSend:
                OnSendCompletion(fd, gen, cqe.res, cqe.flags);
                return;

            // UDP
            case KindUdpRecv:
                OnUdpRecvCompletion(fd, cqe.res, cqe.flags);
                return;

            case KindUdpSend:
                OnUdpSendCompletion(fd, cqe.res);
                return;

            // OTHER
            case KindClient:
                OnClientCompletion(fd, cqe.res);
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
