using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// All native interop, one partial class split by concern: io_uring (this file), the shared
/// socket ABI (Native.Socket.cs), TCP (Native.Tcp.cs), UDP/datagram (Native.Udp.cs), and file
/// I/O (Native.File.cs). This file owns the ring itself: syscalls, opcodes, setup/CQE flags,
/// the kernel struct layouts, and the generic fd operations the loop machinery needs
/// (mmap for the rings, eventfd + read/write for the cross-thread wake, close).
/// </summary>
public static unsafe partial class Native {
    private const long SYS_IO_URING_SETUP    = 425;
    private const long SYS_IO_URING_ENTER    = 426;
    private const long SYS_IO_URING_REGISTER = 427;

    public const byte IORING_OP_POLL_ADD = 6;
    public const byte IORING_OP_SENDMSG  = 9;   // vectored send over an iovec; segmented TCP flush + UDP datagram send
    public const byte IORING_OP_RECVMSG  = 10;  // datagram recv - fills msg_name (peer addr) + control (GRO/TOS cmsgs)
    public const byte IORING_OP_TIMEOUT = 11;
    public const byte IORING_OP_ACCEPT = 13;
    public const byte IORING_OP_ASYNC_CANCEL = 14;
    public const byte IORING_OP_CONNECT = 16;
    public const byte IORING_OP_READ   = 22;
    public const byte IORING_OP_WRITE  = 23;
    public const byte IORING_OP_SEND   = 26;
    public const byte IORING_OP_RECV   = 27;

    // Zero-copy send (kernel 6.0+): the NIC DMAs straight from the user buffer instead of the kernel
    // copying into skbuff. Posts the usual completion (with IORING_CQE_F_MORE set) and then a second
    // CQE (IORING_CQE_F_NOTIF) once the buffer can be reused.
    public const byte IORING_OP_SEND_ZC = 47;
    public const uint IORING_ENTER_GETEVENTS = 1u << 0;
    public const long IORING_OFF_SQ_RING = 0;
    public const long IORING_OFF_SQES    = 0x10000000;

    // Multishot / buffer-ring goodies.
    public const ushort IORING_ACCEPT_MULTISHOT = 1 << 0;
    public const ushort IORING_RECV_MULTISHOT   = 1 << 1;
    public const byte   IOSQE_BUFFER_SELECT     = 1 << 5;
    public const uint   IORING_CQE_F_BUFFER     = 1u << 0;
    public const uint   IORING_CQE_F_MORE       = 1u << 1;
    public const uint   IORING_CQE_F_NOTIF      = 1u << 3;   // zero-copy send: buffer is free to reuse
    public const int    IORING_CQE_BUFFER_SHIFT = 16;
    public const uint   IORING_REGISTER_PBUF_RING   = 22;
    public const uint   IORING_UNREGISTER_PBUF_RING = 23;
    public const uint   IORING_POLL_ADD_MULTI   = 1u << 0;

    // Incremental provided-buffer consumption (kernel 6.12+). IOU_PBUF_RING_INC
    // is set in io_uring_buf_reg.flags at registration; IORING_CQE_F_BUF_MORE is
    // set on recv CQEs while the kernel will keep appending to the same buffer.
    public const ushort IOU_PBUF_RING_INC     = 2;
    public const uint   IORING_CQE_F_BUF_MORE = 1u << 4;

    // eventfd flags + poll mask (used for the cross-thread wake mechanism).
    public const int    EFD_CLOEXEC  = 0x80000;
    public const int    EFD_NONBLOCK = 0x800;
    public const uint   POLLIN       = 0x0001;

    // Setup flags. SINGLE_ISSUER tells the kernel only one thread will submit
    // to this ring (skips locking on the SQ). DEFER_TASKRUN defers completion
    // processing until io_uring_enter(GETEVENTS), which lets the kernel batch
    // work and avoids interrupting the reactor with task_work mid-flight.
    public const uint   IORING_SETUP_SINGLE_ISSUER = 1u << 12;
    public const uint   IORING_SETUP_DEFER_TASKRUN = 1u << 13;

    // Kernel 6.6+: drop the SQ indirection array (slot i in the SQ ring is
    // implicitly SQE i). One fewer store + cache line per submission.
    public const uint   IORING_SETUP_NO_SQARRAY    = 1u << 16;

    public const int EINVAL = 22;
    public const int ENOMEM = 12;

    public const int PROT_READ    = 1;
    public const int PROT_WRITE   = 2;
    public const int MAP_SHARED   = 1;
    public const int MAP_POPULATE = 0x8000;

    // All three go through glibc's syscall(), which reports failure as -1 with the code in errno -
    // it never returns -errno. So every one of them needs SetLastError, and the wrappers below
    // normalise to liburing's convention: a negative errno, which is what every caller compares
    // against. Two of these were declared without it (#220), which made three branches dead code:
    // Ring.Create's fallback for kernels without IORING_SETUP_NO_SQARRAY, and the EINTR/EAGAIN/EBUSY
    // tolerance in both reactor loops - so one signal delivered to a reactor thread ended it.
    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall3(long nr, uint a1, IoUringParams* a2);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall6(long nr, uint a1, uint a2, uint a3, uint a4, void* a5, nuint a6);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall4(long nr, uint a1, uint a2, void* a3, uint a4);

    // Test the long before narrowing: a successful io_uring_enter returns a submission count, and
    // errno is only meaningful on the failure branch.
    public static int io_uring_setup(uint entries, IoUringParams* p)
    {
        long rc = syscall3(SYS_IO_URING_SETUP, entries, p);

        return rc < 0 ? -Marshal.GetLastPInvokeError() : (int)rc;
    }

    public static int io_uring_enter(int fd, uint toSubmit, uint minComplete, uint flags)
    {
        long rc = syscall6(SYS_IO_URING_ENTER, (uint)fd, toSubmit, minComplete, flags, null, 0);

        return rc < 0 ? -Marshal.GetLastPInvokeError() : (int)rc;
    }

    public static int io_uring_register(int fd, uint opcode, void* arg, uint nrArgs)
    {
        long rc = syscall4(SYS_IO_URING_REGISTER, (uint)fd, opcode, arg, nrArgs);

        return rc < 0 ? -Marshal.GetLastPInvokeError() : (int)rc;
    }

    [DllImport("libc")] public static extern void* mmap(void* addr, nuint length, int prot, int flags, int fd, long offset);
    [DllImport("libc")] public static extern int   munmap(void* addr, nuint length);
    [DllImport("libc")] public static extern int   close(int fd);
    [DllImport("libc")] public static extern int   eventfd(uint initval, int flags);
    [DllImport("libc")] public static extern long  write(int fd, void* buf, nuint count);
    [DllImport("libc")] public static extern long  read(int fd, void* buf, nuint count);

    // Kernel struct layouts (must match include/uapi/linux/io_uring.h)
    [StructLayout(LayoutKind.Sequential)]
    public struct SqRingOffsets {
        public uint head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
        public ulong resv2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CqRingOffsets {
        public uint head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
        public ulong resv2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoUringParams {
        public uint sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle;
        public uint features, wq_fd, resv0, resv1, resv2;
        public SqRingOffsets sq_off;
        public CqRingOffsets cq_off;
    }

    [StructLayout(LayoutKind.Explicit, Size = 64)]
    public struct IoUringSqe {
        [FieldOffset(0)]  public byte   opcode;
        [FieldOffset(1)]  public byte   flags;
        [FieldOffset(2)]  public ushort ioprio;
        [FieldOffset(4)]  public int    fd;
        [FieldOffset(8)]  public ulong  off;
        [FieldOffset(16)] public ulong  addr;
        [FieldOffset(24)] public uint   len;
        [FieldOffset(28)] public uint   op_flags;
        [FieldOffset(32)] public ulong  user_data;
        [FieldOffset(40)] public ushort buf_index;
        [FieldOffset(42)] public ushort personality;
        [FieldOffset(44)] public int    splice_fd_in;
        [FieldOffset(48)] public ulong  addr3;
        [FieldOffset(56)] public ulong  __pad2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoUringCqe {
        public ulong user_data;
        public int   res;
        public uint  flags;
    }

    // Argument struct for IORING_REGISTER_PBUF_RING.
    [StructLayout(LayoutKind.Sequential)]
    public struct io_uring_buf_reg {
        public ulong  ring_addr;
        public uint   ring_entries;
        public ushort bgid;
        public ushort flags;
        public ulong  resv1, resv2, resv3;
    }

    // include/uapi/linux/time_types.h - the timespec IORING_OP_TIMEOUT reads.
    [StructLayout(LayoutKind.Sequential)]
    public struct __kernel_timespec { public long tv_sec; public long tv_nsec; }
}
