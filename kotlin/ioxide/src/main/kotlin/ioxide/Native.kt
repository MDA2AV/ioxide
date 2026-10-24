package ioxide

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.lang.invoke.MethodHandle

/**
 * libc through FFM: io_uring's three syscalls (glibc wraps none of them, so they go through `syscall`), the
 * mmaps for the rings, and the handful of socket and descriptor calls made outside the ring.
 *
 * Every wrapper returns a negative errno on failure, liburing's convention, which is what every caller
 * compares against. errno is captured by the downcall itself, as the JVM may overwrite it before Java code
 * could read it; a ring passes its own capture segment, everything else uses one per thread. Pointers
 * travel as `Long` addresses, see [MEM].
 */
internal object Native {
    private const val SYS_IO_URING_SETUP = 425L
    private const val SYS_IO_URING_ENTER = 426L
    private const val SYS_IO_URING_REGISTER = 427L

    private val linker: Linker = Linker.nativeLinker()
    private val stateLayout = Linker.Option.captureStateLayout()
    private val errnoOffset = stateLayout.byteOffset(MemoryLayout.PathElement.groupElement("errno"))
    private val threadState: ThreadLocal<MemorySegment> = ThreadLocal.withInitial { Arena.ofAuto().allocate(stateLayout) }

    /** Bytes a capture segment needs; a ring allocates its own so the hot enter skips the thread-local. */
    val captureStateSize: Long = stateLayout.byteSize()

    fun errno(state: MemorySegment): Int = state.get(JAVA_INT, errnoOffset)

    private fun bind(name: String, descriptor: FunctionDescriptor, vararg options: Linker.Option): MethodHandle =
        linker.downcallHandle(linker.defaultLookup().find(name).orElseThrow(), descriptor, *options)

    private val captureErrno = Linker.Option.captureCallState("errno")

    // long syscall(long number, ...): every argument as a full register, as the kernel reads them.
    private val SYSCALL: MethodHandle = bind(
        "syscall",
        FunctionDescriptor.of(JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG),
        Linker.Option.firstVariadicArg(1), captureErrno,
    )

    private val MMAP = bind("mmap", FunctionDescriptor.of(JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG), captureErrno)
    private val MUNMAP = bind("munmap", FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG))
    private val CLOSE = bind("close", FunctionDescriptor.of(JAVA_INT, JAVA_INT))
    private val SOCKET = bind("socket", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT), captureErrno)
    private val SETSOCKOPT = bind("setsockopt", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG, JAVA_INT), captureErrno)
    private val BIND = bind("bind", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, JAVA_INT), captureErrno)
    private val LISTEN = bind("listen", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT), captureErrno)
    private val GETSOCKNAME = bind("getsockname", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, JAVA_LONG), captureErrno)
    private val SHUTDOWN = bind("shutdown", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT))
    private val EVENTFD = bind("eventfd", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT), captureErrno)
    private val WRITE = bind("write", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, JAVA_LONG, JAVA_LONG))
    private val READ = bind("read", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, JAVA_LONG, JAVA_LONG))
    private val SEND = bind("send", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_INT))
    private val RECV = bind("recv", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_INT))
    private val SENDMSG = bind("sendmsg", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, JAVA_LONG, JAVA_INT))
    private val RECVMSG = bind("recvmsg", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, JAVA_LONG, JAVA_INT))
    private val MALLOC = bind("malloc", FunctionDescriptor.of(JAVA_LONG, JAVA_LONG))
    private val ALIGNED_ALLOC = bind("aligned_alloc", FunctionDescriptor.of(JAVA_LONG, JAVA_LONG, JAVA_LONG))
    private val FREE = bind("free", FunctionDescriptor.ofVoid(JAVA_LONG))
    private val SCHED_SETAFFINITY = bind("sched_setaffinity", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, JAVA_LONG), captureErrno)

    private fun failed(rc: Long, state: MemorySegment): Long = if (rc < 0) -errno(state).toLong() else rc

    fun ioUringSetup(entries: Int, params: Long): Int {
        val state = threadState.get()
        val rc = SYSCALL.invokeExact(state, SYS_IO_URING_SETUP, entries.toLong(), params, 0L, 0L, 0L, 0L) as Long
        return failed(rc, state).toInt()
    }

    /** The ring's hot path: its own capture segment, no thread-local. */
    fun ioUringEnter(state: MemorySegment, fd: Int, toSubmit: Int, minComplete: Int, flags: Int, arg: Long, argSize: Long): Int {
        val rc = SYSCALL.invokeExact(
            state, SYS_IO_URING_ENTER, fd.toLong(), toSubmit.toLong() and 0xFFFF_FFFFL,
            minComplete.toLong() and 0xFFFF_FFFFL, flags.toLong(), arg, argSize,
        ) as Long
        return failed(rc, state).toInt()
    }

    fun ioUringRegister(fd: Int, opcode: Int, arg: Long, nrArgs: Int): Int {
        val state = threadState.get()
        val rc = SYSCALL.invokeExact(state, SYS_IO_URING_REGISTER, fd.toLong(), opcode.toLong(), arg, nrArgs.toLong(), 0L, 0L) as Long
        return failed(rc, state).toInt()
    }

    /** The mapping's address, or a negative errno. */
    fun mmap(length: Long, prot: Int, flags: Int, fd: Int, offset: Long): Long {
        val state = threadState.get()
        val rc = MMAP.invokeExact(state, 0L, length, prot, flags, fd, offset) as Long
        return if (rc == -1L) -errno(state).toLong() else rc
    }

    fun munmap(addr: Long, length: Long): Int = MUNMAP.invokeExact(addr, length) as Int

    fun close(fd: Int): Int = CLOSE.invokeExact(fd) as Int

    fun socket(domain: Int, type: Int, protocol: Int): Int {
        val state = threadState.get()
        return failed((SOCKET.invokeExact(state, domain, type, protocol) as Int).toLong(), state).toInt()
    }

    fun setsockopt(fd: Int, level: Int, name: Int, value: Long, length: Int): Int {
        val state = threadState.get()
        return failed((SETSOCKOPT.invokeExact(state, fd, level, name, value, length) as Int).toLong(), state).toInt()
    }

    fun bind(fd: Int, addr: Long, length: Int): Int {
        val state = threadState.get()
        return failed((BIND.invokeExact(state, fd, addr, length) as Int).toLong(), state).toInt()
    }

    fun listen(fd: Int, backlog: Int): Int {
        val state = threadState.get()
        return failed((LISTEN.invokeExact(state, fd, backlog) as Int).toLong(), state).toInt()
    }

    fun getsockname(fd: Int, addr: Long, lengthAddr: Long): Int {
        val state = threadState.get()
        return failed((GETSOCKNAME.invokeExact(state, fd, addr, lengthAddr) as Int).toLong(), state).toInt()
    }

    fun shutdown(fd: Int, how: Int): Int = SHUTDOWN.invokeExact(fd, how) as Int

    fun eventfd(initval: Int, flags: Int): Int {
        val state = threadState.get()
        return failed((EVENTFD.invokeExact(state, initval, flags) as Int).toLong(), state).toInt()
    }

    fun write(fd: Int, buf: Long, count: Long): Long = WRITE.invokeExact(fd, buf, count) as Long

    fun read(fd: Int, buf: Long, count: Long): Long = READ.invokeExact(fd, buf, count) as Long

    // The direct socket calls TLS makes beside the ring: a teardown close_notify, and the kTLS RX handoff's
    // look at what is waiting. Best effort, so no errno: -1 is all a caller acts on.
    fun send(fd: Int, buf: Long, length: Long, flags: Int): Long = SEND.invokeExact(fd, buf, length, flags) as Long

    fun recv(fd: Int, buf: Long, length: Long, flags: Int): Long = RECV.invokeExact(fd, buf, length, flags) as Long

    fun sendmsg(fd: Int, msg: Long, flags: Int): Long = SENDMSG.invokeExact(fd, msg, flags) as Long

    fun recvmsg(fd: Int, msg: Long, flags: Int): Long = RECVMSG.invokeExact(fd, msg, flags) as Long

    fun malloc(size: Long): Long {
        val p = MALLOC.invokeExact(size) as Long
        if (p == 0L) throw OutOfMemoryError("malloc($size)")
        return p
    }

    /** [size] is rounded up to a multiple of [alignment], which aligned_alloc requires. */
    fun alignedAlloc(alignment: Long, size: Long): Long {
        val rounded = (size + alignment - 1) / alignment * alignment
        val p = ALIGNED_ALLOC.invokeExact(alignment, rounded) as Long
        if (p == 0L) throw OutOfMemoryError("aligned_alloc($alignment, $size)")
        return p
    }

    fun free(addr: Long) {
        if (addr != 0L) FREE.invokeExact(addr)
    }

    /** Pins the calling thread to one CPU. */
    fun pinCurrentThread(cpu: Int): Int {
        val mask = malloc(128)
        try {
            zeroMemory(mask, 128)
            putLong(mask + (cpu / 64) * 8L, 1L shl (cpu % 64))
            val state = threadState.get()
            return failed((SCHED_SETAFFINITY.invokeExact(state, 0, 128L, mask) as Int).toLong(), state).toInt()
        } finally {
            free(mask)
        }
    }

    // errno values the callers compare against.
    const val EPERM = 1
    const val ENOENT = 2
    const val EINTR = 4
    const val EBADF = 9
    const val EAGAIN = 11
    const val ENOMEM = 12
    const val EBUSY = 16
    const val EINVAL = 22
    const val ENFILE = 23
    const val EMFILE = 24
    const val EPIPE = 32
    const val ENOSYS = 38
    const val ETIME = 62
    const val ECONNABORTED = 103
    const val ECONNRESET = 104
    const val ENOBUFS = 105
    const val ENOTCONN = 107
    const val ECANCELED = 125

    const val PROT_READ = 1
    const val PROT_WRITE = 2
    const val MAP_SHARED = 0x01
    const val MAP_PRIVATE = 0x02
    const val MAP_ANONYMOUS = 0x20
    const val MAP_POPULATE = 0x8000

    const val EFD_NONBLOCK = 0x800
    const val EFD_CLOEXEC = 0x80000
}
