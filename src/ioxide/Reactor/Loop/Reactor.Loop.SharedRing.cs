using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

// Loop - SharedRing
public sealed unsafe partial class Reactor
{
    private void InitSharedRingBuffer()
    {
        nuint ringBytes = (nuint)_bufferRingEntries * 16;
        // On the kernel's page, which it requires of a ring and which is 16 or 64 KiB on some arm64 kernels.
        _bufRing = (byte*)NativeMemory.AlignedAlloc(ringBytes, (nuint)Environment.SystemPageSize);
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
            throw new InvalidOperationException($"register pbuf_ring failed with errno {-ret}");
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

            case KindCancel:
                return;
        }
    }
}
