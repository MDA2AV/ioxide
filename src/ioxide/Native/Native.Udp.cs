using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// UDP/datagram ABI: datagram socket type, the GSO/GRO offload knobs, TOS/ECN delivery, and the
/// control-message (cmsg) machinery RECVMSG completions are parsed with. The QUIC transport rides
/// this layer.
/// </summary>
public static unsafe partial class Native {
    // SOL_UDP == IPPROTO_UDP; UDP_SEGMENT/UDP_GRO are the GSO/GRO offload knobs - GSO splits one
    // large send into wire-size datagrams in the kernel, GRO coalesces a burst from one peer into
    // a single recv (segment size arrives as a cmsg).
    public const int SOCK_DGRAM   = 2;
    public const int IPPROTO_UDP  = 17;
    public const int SOL_UDP      = 17;
    public const int UDP_SEGMENT  = 103;
    public const int UDP_GRO      = 104;

    // TOS/TCLASS delivery (the ECN bits QUIC's congestion controller reads live in the low
    // two bits). RECVTOS/RECVTCLASS opt in; the value arrives as a cmsg per datagram.
    public const int IPPROTO_IP       = 0;
    public const int IP_TOS           = 1;
    public const int IP_RECVTOS       = 13;
    public const int IPV6_TCLASS      = 67;
    public const int IPV6_RECVTCLASS  = 66;

    // msg_flags bits worth checking on a recvmsg completion.
    public const int MSG_TRUNC  = 0x20;   // payload didn't fit the iovec - datagram tail dropped
    public const int MSG_CTRUNC = 0x08;   // control buffer too small - cmsgs dropped

#pragma warning disable CS8981 // lower-cased name deliberately mirrors the kernel struct name (uapi)
    // struct io_uring_recvmsg_out: the 16-byte header the kernel prepends to each multishot RECVMSG
    // buffer, followed by the reserved name region, the reserved control region, then the payload -
    // all at offsets fixed by the reserved namelen/controllen from the arm-time msghdr template.
    [StructLayout(LayoutKind.Sequential)]
    public struct io_uring_recvmsg_out {
        public uint namelen;      // actual peer-address bytes (region is reserved-namelen wide)
        public uint controllen;   // actual cmsg bytes
        public uint payloadlen;   // actual datagram bytes
        public uint flags;        // MSG_TRUNC / MSG_CTRUNC
    }
#pragma warning restore CS8981

#pragma warning disable CS8981 // lower-cased name deliberately mirrors the kernel struct name (uapi)
    // struct cmsghdr (x86_64: size_t len, then two ints; data follows the 16-byte header,
    // entries aligned to 8). Walked manually - glibc's CMSG_* are macros, not symbols.
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct cmsghdr {
        public nuint cmsg_len;     // header + data, unpadded
        public int   cmsg_level;
        public int   cmsg_type;
    }
#pragma warning restore CS8981

    public const int CmsgHdrLen = 16;

    public static byte* CmsgData(cmsghdr* c) => (byte*)c + CmsgHdrLen;

    public static nuint CmsgAlign(nuint len) => (len + 7) & ~(nuint)7;

    /// <summary>Total control-buffer space for a cmsg carrying <paramref name="dataLen"/> bytes.</summary>
    public static nuint CmsgSpace(nuint dataLen) => CmsgHdrLen + CmsgAlign(dataLen);

    public static cmsghdr* CmsgFirst(msghdr* m)
        => m->msg_controllen >= CmsgHdrLen ? (cmsghdr*)m->msg_control : null;

    public static cmsghdr* CmsgNext(msghdr* m, cmsghdr* c)
    {
        if (c->cmsg_len < CmsgHdrLen)
        {
            return null;   // malformed - stop rather than loop
        }
        byte* next = (byte*)c + (long)CmsgAlign(c->cmsg_len);
        byte* end  = (byte*)m->msg_control + (long)m->msg_controllen;
        return next + CmsgHdrLen <= end ? (cmsghdr*)next : null;
    }
}
