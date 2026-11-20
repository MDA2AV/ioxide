using System.Runtime.InteropServices;

namespace epoxide;

/// <summary>
/// The socket ABI: the libc calls every connection makes, the address families and options, the
/// sockaddr layouts, and the iovec/msghdr pair for the segmented flush. Every call that can fail
/// with an errno the caller acts on sets the last P/Invoke error; read it with
/// <see cref="Marshal.GetLastPInvokeError"/> right after a -1.
/// </summary>
public static unsafe partial class Native
{
    public const int AF_INET      = 2;
    public const int AF_INET6     = 10;
    public const int SOL_SOCKET   = 1;
    public const int SO_REUSEADDR = 2;
    public const int SO_ERROR     = 4;
    public const int SO_SNDBUF    = 7;
    public const int SO_RCVBUF    = 8;
    public const int SO_REUSEPORT = 15;
    public const int IPPROTO_IPV6 = 41;
    public const int IPV6_V6ONLY  = 26;

    /// <summary>shutdown(2) how: the write side only.</summary>
    public const int SHUT_WR   = 1;

    /// <summary>shutdown(2) how: both directions.</summary>
    public const int SHUT_RDWR = 2;

    /// <summary>socket(2) type flag and accept4(2) flag: not inherited by a process the host starts.</summary>
    public const int SOCK_CLOEXEC  = 0x80000;

    /// <summary>socket(2) type flag and accept4(2) flag: every call on the socket returns EAGAIN instead of blocking.</summary>
    public const int SOCK_NONBLOCK = 0x800;

    /// <summary>send flag: a peer that has gone returns EPIPE instead of raising SIGPIPE.</summary>
    public const int MSG_NOSIGNAL = 0x4000;

    public const int EINTR       = 4;
    public const int EAGAIN      = 11;
    public const int ENOMEM      = 12;
    public const int ENFILE      = 23;
    public const int EMFILE      = 24;
    public const int ENOSYS      = 38;
    public const int ENOBUFS     = 105;
    public const int EINPROGRESS = 115;

    [DllImport("libc", SetLastError = true)] public static extern int socket(int domain, int type, int proto);
    [DllImport("libc", SetLastError = true)] public static extern int bind(int fd, void* addr, uint len);
    [DllImport("libc", SetLastError = true)] public static extern int connect(int fd, void* addr, uint len);
    [DllImport("libc", SetLastError = true)] public static extern int listen(int fd, int backlog);
    [DllImport("libc", SetLastError = true)] public static extern int accept4(int fd, void* addr, uint* len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int getsockname(int fd, void* addr, uint* len);

    /// End a connection at the socket: the peer gets a FIN, and the readiness it raises is what
    /// wakes a reactor waiting on a silent or stalled peer.
    [DllImport("libc", SetLastError = true)] public static extern int shutdown(int fd, int how);
    [DllImport("libc", SetLastError = true)] public static extern int setsockopt(int fd, int level, int optname, void* optval, uint optlen);
    [DllImport("libc", SetLastError = true)] public static extern int getsockopt(int fd, int level, int optname, void* optval, uint* optlen);

    [DllImport("libc", SetLastError = true)] public static extern nint recv(int fd, void* buf, nuint len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern nint send(int fd, void* buf, nuint len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern nint sendmsg(int fd, msghdr* msg, int flags);

    [DllImport("libc", SetLastError = true)] public static extern int close(int fd);
    [DllImport("libc", SetLastError = true)] public static extern nint read(int fd, void* buf, nuint count);
    [DllImport("libc", SetLastError = true)] public static extern nint write(int fd, void* buf, nuint count);

    public static ushort Htons(ushort x) => (ushort)((x << 8) | (x >> 8));

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr { public uint s_addr; }

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
        public ushort  sin_family;
        public ushort  sin_port;
        public in_addr sin_addr;
        public fixed byte sin_zero[8];
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in6
    {
        public ushort     sin6_family;
        public ushort     sin6_port;
        public uint       sin6_flowinfo;
        public fixed byte sin6_addr[16];  // in6_addr - zeroed == in6addr_any (::)
        public uint       sin6_scope_id;
    }

#pragma warning disable CS8981 // lower-cased names deliberately mirror the kernel struct names (uapi)
    // struct iovec (scatter/gather entry) - one per write segment for the vectored flush.
    [StructLayout(LayoutKind.Sequential)]
    public struct iovec
    {
        public void* iov_base;
        public nuint iov_len;
    }

    // struct msghdr (64-bit layout). Explicit offsets so the padding after msg_namelen matches the ABI.
    [StructLayout(LayoutKind.Explicit, Size = 56)]
    public struct msghdr
    {
        [FieldOffset(0)]  public void*  msg_name;
        [FieldOffset(8)]  public uint   msg_namelen;
        [FieldOffset(16)] public iovec* msg_iov;
        [FieldOffset(24)] public nuint  msg_iovlen;
        [FieldOffset(32)] public void*  msg_control;
        [FieldOffset(40)] public nuint  msg_controllen;
        [FieldOffset(48)] public int    msg_flags;
    }
#pragma warning restore CS8981

    /// <summary>The errno of the libc call just made on this thread.</summary>
    public static int Errno => Marshal.GetLastPInvokeError();

    /// <summary>The SocketError a connect's errno reads as, for the exception a caller catches.</summary>
    internal static System.Net.Sockets.SocketError ToSocketError(int errno) => errno switch
    {
        111 => System.Net.Sockets.SocketError.ConnectionRefused,     // ECONNREFUSED
        110 => System.Net.Sockets.SocketError.TimedOut,              // ETIMEDOUT
        113 => System.Net.Sockets.SocketError.HostUnreachable,       // EHOSTUNREACH
        101 => System.Net.Sockets.SocketError.NetworkUnreachable,    // ENETUNREACH
        104 => System.Net.Sockets.SocketError.ConnectionReset,       // ECONNRESET
        99  => System.Net.Sockets.SocketError.AddressNotAvailable,   // EADDRNOTAVAIL
        97  => System.Net.Sockets.SocketError.AddressFamilyNotSupported, // EAFNOSUPPORT
        _   => System.Net.Sockets.SocketError.SocketError,
    };
}
