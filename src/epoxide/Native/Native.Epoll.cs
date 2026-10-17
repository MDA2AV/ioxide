using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace epoxide;

/// <summary>
/// epoll and the eventfd that wakes it. struct epoll_event is packed on x86-64 (12 bytes, data at
/// offset 4) and naturally aligned everywhere else (16 bytes, data at 8), so events are read and
/// written through these helpers rather than a struct whose layout would be right on one of the two.
/// </summary>
public static unsafe partial class Native
{
    public const int EPOLL_CLOEXEC = 0x80000;

    public const int EPOLL_CTL_ADD = 1;
    public const int EPOLL_CTL_DEL = 2;
    public const int EPOLL_CTL_MOD = 3;

    public const uint EPOLLIN    = 0x001;
    public const uint EPOLLPRI   = 0x002;
    public const uint EPOLLOUT   = 0x004;
    public const uint EPOLLERR   = 0x008;
    public const uint EPOLLHUP   = 0x010;
    public const uint EPOLLRDHUP = 0x2000;
    public const uint EPOLLET    = 1u << 31;

    public const int EFD_CLOEXEC  = 0x80000;
    public const int EFD_NONBLOCK = 0x800;

    [DllImport("libc", SetLastError = true)] public static extern int epoll_create1(int flags);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_ctl(int epfd, int op, int fd, void* ev);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_wait(int epfd, void* events, int maxevents, int timeout);
    [DllImport("libc", SetLastError = true)] public static extern int eventfd(uint initval, int flags);

    /// <summary>Bytes per struct epoll_event on this architecture.</summary>
    public static readonly int EpollEventSize = RuntimeInformation.ProcessArchitecture == Architecture.X64 ? 12 : 16;

    private static readonly int EpollDataOffset = RuntimeInformation.ProcessArchitecture == Architecture.X64 ? 4 : 8;

    /// <summary>epoll_ctl with the event built in the layout this architecture uses.</summary>
    public static int EpollCtl(int epfd, int op, int fd, uint events, ulong data)
    {
        byte* ev = stackalloc byte[16];
        *(uint*)ev = events;
        Unsafe.WriteUnaligned(ev + EpollDataOffset, data);
        return epoll_ctl(epfd, op, fd, ev);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint EpollEvents(byte* events, int index) => Unsafe.ReadUnaligned<uint>(events + index * EpollEventSize);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong EpollData(byte* events, int index) => Unsafe.ReadUnaligned<ulong>(events + index * EpollEventSize + EpollDataOffset);
}
