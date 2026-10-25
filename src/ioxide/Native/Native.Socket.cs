using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// Shared socket ABI: the libc socket calls, address families and options every transport uses,
/// the sockaddr layouts, and the iovec/msghdr pair (scatter-gather for TCP's segmented flush,
/// name+control carrier for UDP). Transport-specific constants live in Native.Tcp.cs /
/// Native.Udp.cs.
/// </summary>
public static unsafe partial class Native {
    public const int AF_INET      = 2;
    public const int SOL_SOCKET   = 1;
    public const int SO_REUSEADDR = 2;
    public const int SO_SNDBUF    = 7;
    public const int SO_RCVBUF    = 8;
    public const int SO_REUSEPORT = 15;

    /// <summary>shutdown(2) how: the write side only.</summary>
    public const int SHUT_WR      = 1;

    /// <summary>shutdown(2) how: both directions.</summary>
    public const int SHUT_RDWR    = 2;

    public const int AF_INET6     = 10;

    /// <summary>socket(2) type flag, accept4(2) flag: not inherited by a process the host starts.</summary>
    public const int SOCK_CLOEXEC = 0x80000;
    public const int IPPROTO_IPV6 = 41;
    public const int IPV6_V6ONLY  = 26;

    [DllImport("libc")] public static extern int socket(int domain, int type, int proto);
    [DllImport("libc")] public static extern int bind(int fd, void* addr, uint len);
    [DllImport("libc")] public static extern int connect(int fd, void* addr, uint len);
    /// Read a socket's local address - the only way to learn the port the kernel picked for a
    /// bind to port 0 (QUIC client sockets take an ephemeral port).
    [DllImport("libc")] public static extern int getsockname(int fd, void* addr, uint* len);
    [DllImport("libc")] public static extern int listen(int fd, int backlog);
    /// End a connection at the socket: the peer gets a FIN and any outstanding io_uring recv or
    /// send completes, which is what releases a connection the reactor still holds a ref to.
    [DllImport("libc")] public static extern int shutdown(int fd, int how);
    [DllImport("libc")] public static extern int setsockopt(int fd, int level, int optname, void* optval, uint optlen);
    [DllImport("libc")] public static extern int getsockopt(int fd, int level, int optname, void* optval, uint* optlen);

    // Off the ring: what a stopping reactor sends once its loop will not submit again.
    internal const int MSG_DONTWAIT = 0x40;
    [DllImport("libc", SetLastError = true)] internal static extern long sendmsg(int fd, msghdr* msg, int flags);

    // Off the ring too: the sweep asks a socket whether it has hung up, without waiting (#403).
    internal const short POLLHUP = 0x10;
    [DllImport("libc")] internal static extern int poll(pollfd* fds, nuint nfds, int timeout);

    public static ushort Htons(ushort x) => (ushort)((x << 8) | (x >> 8));

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr { public uint s_addr; }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct sockaddr_in {
        public ushort  sin_family;
        public ushort  sin_port;
        public in_addr sin_addr;
        public fixed byte sin_zero[8];
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct sockaddr_in6 {
        public ushort     sin6_family;
        public ushort     sin6_port;
        public uint       sin6_flowinfo;
        public fixed byte sin6_addr[16];  // in6_addr - zeroed == in6addr_any (::)
        public uint       sin6_scope_id;
    }

#pragma warning disable CS8981 // lower-cased names deliberately mirror the kernel struct names (uapi)
    // struct iovec (scatter/gather entry) - one per write segment for IORING_OP_SENDMSG.
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct iovec {
        public void* iov_base;
        public nuint iov_len;
    }

    // struct msghdr (x86_64 layout). The SENDMSG/RECVMSG SQE's addr points here; msg_iov/msg_iovlen
    // carry the segment vector, msg_name the peer sockaddr, msg_control the cmsg buffer. Explicit
    // offsets so the internal/trailing padding matches the kernel ABI exactly.
    [StructLayout(LayoutKind.Explicit, Size = 56)]
    public unsafe struct msghdr {
        [FieldOffset(0)]  public void*  msg_name;
        [FieldOffset(8)]  public uint   msg_namelen;
        [FieldOffset(16)] public iovec* msg_iov;
        [FieldOffset(24)] public nuint  msg_iovlen;
        [FieldOffset(32)] public void*  msg_control;
        [FieldOffset(40)] public nuint  msg_controllen;
        [FieldOffset(48)] public int    msg_flags;
    }

    // struct pollfd, for poll(2). POLLHUP and POLLERR come back in revents whatever events asks for.
    [StructLayout(LayoutKind.Sequential)]
    internal struct pollfd {
        public int   fd;
        public short events;
        public short revents;
    }
#pragma warning restore CS8981
}
