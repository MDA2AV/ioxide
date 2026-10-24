package ioxide

import ioxide.IoUring.ENTER_EXT_ARG
import ioxide.IoUring.ENTER_GETEVENTS
import ioxide.IoUring.ENTER_REGISTERED_RING
import java.lang.foreign.MemorySegment
import java.nio.file.Files
import java.nio.file.Path

/**
 * One io_uring instance: SINGLE_ISSUER | DEFER_TASKRUN, so only the thread that created it may submit, and
 * completions are processed only when that thread enters with GETEVENTS. Indexes are `Int` and wrap the way
 * the kernel's `u32` do; addresses are `Long`, see [MEM].
 */
internal class Ring private constructor(
    val fd: Int,
    private val ringPtr: Long,
    private val ringSize: Long,
    private val sqesPtr: Long,
    private val sqesSize: Long,
    private val sqHead: Long,
    private val sqTail: Long,
    private val sqArray: Long,
    private val sqFlags: Long,
    private val sqMask: Int,
    val sqEntries: Int,
    private val cqHead: Long,
    private val cqTail: Long,
    private val cqes: Long,
    private val cqMask: Int,
    val cqEntries: Int,
    private val hasSqArray: Boolean,
    private val scratch: Long,
) : AutoCloseable {
    // The ring's own errno capture, so the hot enter skips the thread-local Native uses elsewhere.
    private val errnoState: MemorySegment = MEM.asSlice(scratch + SCRATCH_ERRNO, Native.captureStateSize)
    private val timespec = scratch + SCRATCH_TIMESPEC
    private val geteventsArg = scratch + SCRATCH_GETEVENTS

    private var sqeTail = getInt(sqTail)
    private var cqHeadLocal = getInt(cqHead)

    // What every enter is handed: the slot IORING_REGISTER_RING_FDS gave this ring, with
    // IORING_ENTER_REGISTERED_RING, so the kernel takes the file from the thread's table instead of an
    // fget/fput of the descriptor - or, with no slot, the descriptor and no flag.
    var enterFd: Int = fd
        private set
    private var enterFlags = 0

    private var closeFd = true
    private var closed = false

    /** The next free SQE's address, or 0 when the SQ is full. */
    fun getSqe(): Long {
        val head = getIntAcquire(sqHead)
        if (sqeTail - head >= sqEntries) return 0L

        val slot = sqeTail and sqMask
        if (hasSqArray) putInt(sqArray + slot * 4L, slot)
        sqeTail++
        return sqesPtr + slot.toLong() * IoUring.SQE_SIZE
    }

    /** SQEs taken by [getSqe] that no enter has handed to the kernel yet. */
    fun sqPending(): Int = sqeTail - getIntAcquire(sqHead)

    /**
     * Submits every SQE taken since the last enter and waits for [waitFor] completions, at most
     * [timeoutMs] (negative: unbounded). Returns what io_uring_enter returns: the count submitted, or a
     * negative errno; a wait that runs out with nothing submitted is -ETIME.
     */
    fun submitAndWait(waitFor: Int, timeoutMs: Long = -1): Int {
        // liburing-style accounting: derive the submit count from the kernel-consumed head, so SQEs published
        // by an enter that consumed nothing (-EBUSY under CQ-overflow pressure) are re-counted by the next call.
        val khead = getIntAcquire(sqHead)
        val toSubmit = sqeTail - khead

        if (sqeTail != getInt(sqTail)) putIntRelease(sqTail, sqeTail)

        if (toSubmit == 0 && waitFor == 0) return 0

        val flags = (if (waitFor > 0) ENTER_GETEVENTS else 0) or enterFlags

        if (timeoutMs < 0) {
            return Native.ioUringEnter(errnoState, enterFd, toSubmit, waitFor, flags, 0L, 0L)
        }

        // The kernel copies both during the call.
        putLong(timespec, timeoutMs / 1000)
        putLong(timespec + 8, timeoutMs % 1000 * 1_000_000)
        putLong(geteventsArg, 0L)
        putLong(geteventsArg + 8, 0L)
        putLong(geteventsArg + 16, timespec)
        return Native.ioUringEnter(errnoState, enterFd, toSubmit, waitFor, flags or ENTER_EXT_ARG, geteventsArg, IoUring.GETEVENTS_ARG_SIZE)
    }

    // Batched CQ drain (liburing io_uring_for_each_cqe + io_uring_cq_advance): read the kernel-written tail
    // once (acquire), process the batch, then publish the consumed head once (release).

    fun cqReady(): Int = getIntAcquire(cqTail) - cqHeadLocal

    /** Address of the [i]-th unconsumed CQE: user_data at +0, res at +8, flags at +12. */
    fun cqeAt(i: Int): Long = cqes + ((cqHeadLocal + i) and cqMask).toLong() * IoUring.CQE_SIZE

    fun cqAdvance(n: Int) {
        cqHeadLocal += n
        putIntRelease(cqHead, cqHeadLocal)
    }

    /** Completions the CQ had no room for are held in the kernel until the next enter. */
    val cqOverflowed: Boolean get() = (getIntAcquire(sqFlags) and IoUring.SQ_CQ_OVERFLOW) != 0

    // The slot is in the calling thread's table, which is no restriction: only the thread that created a
    // SINGLE_ISSUER | DEFER_TASKRUN ring can enter it. A thread has 16 slots; without one, the descriptor.
    private fun registerFd() {
        val update = scratch + SCRATCH_RSRC
        putInt(update, -1)          // offset: any free slot, the kernel writes back which
        putInt(update + 4, 0)
        putLong(update + 8, fd.toLong())
        if (Native.ioUringRegister(fd, IoUring.REGISTER_RING_FDS, update, 1) == 1) {
            enterFd = getInt(update)
            enterFlags = ENTER_REGISTERED_RING
        }
    }

    /** Unmaps both rings and, unless [closeFd] says otherwise, closes the descriptor. */
    fun close(closeFd: Boolean) {
        this.closeFd = closeFd
        close()
    }

    override fun close() {
        if (closed) return
        closed = true

        Native.munmap(ringPtr, ringSize)
        Native.munmap(sqesPtr, sqesSize)

        // Before the descriptor goes: the slot holds a reference to the ring, which would otherwise outlive
        // its close, memlock charge and all, until the thread exits. On the creating thread, like the rest
        // of the ring - another thread's slot of the same number is that thread's own ring.
        if (enterFlags != 0) {
            val update = scratch + SCRATCH_RSRC
            putInt(update, enterFd)
            putInt(update + 4, 0)
            putLong(update + 8, 0L)
            Native.ioUringRegister(fd, IoUring.UNREGISTER_RING_FDS, update, 1)
            enterFlags = 0
            enterFd = fd
        }

        if (closeFd) Native.close(fd)
        Native.free(scratch)
    }

    companion object {
        private const val SCRATCH_ERRNO = 0L
        private const val SCRATCH_TIMESPEC = 64L
        private const val SCRATCH_GETEVENTS = 96L
        private const val SCRATCH_RSRC = 128L
        private const val SCRATCH_SIZE = 192L

        /**
         * A ring of [entries] SQEs (a power of two the kernel rounds up to) and, when [cqEntries] is positive,
         * that many CQEs instead of the kernel's 2x. Throws with a diagnosis the host can act on.
         */
        fun create(entries: Int, cqEntries: Int = 0): Ring {
            check(Native.captureStateSize <= SCRATCH_TIMESPEC) { "errno capture state does not fit the ring's scratch" }

            val params = Native.malloc(IoUring.PARAMS_SIZE)
            try {
                // Prefer NO_SQARRAY (6.6+): the SQ slot index is implicit, dropping one store + cache line per
                // SQE. Fall back for older kernels (EINVAL).
                var hasSqArray = false
                var fd = setupWithMemlockRetry(entries, params, cqEntries,
                    IoUring.SETUP_SINGLE_ISSUER or IoUring.SETUP_DEFER_TASKRUN or IoUring.SETUP_NO_SQARRAY)
                if (fd == -Native.EINVAL) {
                    hasSqArray = true
                    fd = setupWithMemlockRetry(entries, params, cqEntries,
                        IoUring.SETUP_SINGLE_ISSUER or IoUring.SETUP_DEFER_TASKRUN)
                }
                if (fd < 0) throw IllegalStateException(describeSetupFailure(-fd, entries, kernelRelease()))

                return map(fd, params, hasSqArray)
            } finally {
                Native.free(params)
            }
        }

        private fun map(fd: Int, params: Long, hasSqArray: Boolean): Ring {
            val sqEntries = getInt(params + IoUring.P_SQ_ENTRIES)
            val cqEntries = getInt(params + IoUring.P_CQ_ENTRIES)
            val sqOff = params + IoUring.P_SQ_OFF
            val cqOff = params + IoUring.P_CQ_OFF

            // One mapping covers both rings (IORING_FEAT_SINGLE_MMAP, every kernel 5.4+).
            val sqRingBytes = getInt(sqOff + 24).toLong() + sqEntries * 4L
            val cqRingBytes = getInt(cqOff + 20).toLong() + cqEntries.toLong() * IoUring.CQE_SIZE
            val ringBytes = maxOf(sqRingBytes, cqRingBytes)

            val prot = Native.PROT_READ or Native.PROT_WRITE
            val flags = Native.MAP_SHARED or Native.MAP_POPULATE
            val ringPtr = Native.mmap(ringBytes, prot, flags, fd, IoUring.OFF_SQ_RING)
            if (ringPtr < 0) {
                Native.close(fd)
                throw IllegalStateException("mmap(SQ_RING) failed with errno ${-ringPtr}")
            }

            val sqesBytes = sqEntries.toLong() * IoUring.SQE_SIZE
            val sqesPtr = Native.mmap(sqesBytes, prot, flags, fd, IoUring.OFF_SQES)
            if (sqesPtr < 0) {
                Native.munmap(ringPtr, ringBytes)
                Native.close(fd)
                throw IllegalStateException("mmap(SQES) failed with errno ${-sqesPtr}")
            }

            val scratch = Native.malloc(SCRATCH_SIZE)
            zeroMemory(scratch, SCRATCH_SIZE)

            val ring = Ring(
                fd = fd,
                ringPtr = ringPtr,
                ringSize = ringBytes,
                sqesPtr = sqesPtr,
                sqesSize = sqesBytes,
                sqHead = ringPtr + getInt(sqOff + 0),
                sqTail = ringPtr + getInt(sqOff + 4),
                sqArray = ringPtr + getInt(sqOff + 24),
                sqFlags = ringPtr + getInt(sqOff + 16),
                sqMask = getInt(ringPtr + getInt(sqOff + 8)),
                sqEntries = sqEntries,
                cqHead = ringPtr + getInt(cqOff + 0),
                cqTail = ringPtr + getInt(cqOff + 4),
                cqes = ringPtr + getInt(cqOff + 20),
                cqMask = getInt(ringPtr + getInt(cqOff + 8)),
                cqEntries = cqEntries,
                hasSqArray = hasSqArray,
                scratch = scratch,
            )
            ring.registerFd()
            return ring
        }

        /**
         * ENOMEM here is transient: a ring's memory is charged against RLIMIT_MEMLOCK and released
         * asynchronously after close, so a host cycling reactors faster than the kernel reclaims them gets
         * ENOMEM while nothing is leaking. 5, 10, 20, 40, 80 ms, sized from the measured reclaim latency of a
         * single ring (median ~20 ms, tail 47 ms under load). Every other errno is final.
         */
        private fun setupWithMemlockRetry(entries: Int, params: Long, cqEntries: Int, setupFlags: Int): Int {
            fun attempt(): Int {
                zeroMemory(params, IoUring.PARAMS_SIZE)
                var flags = setupFlags
                if (cqEntries > 0) {
                    flags = flags or IoUring.SETUP_CQSIZE
                    putInt(params + IoUring.P_CQ_ENTRIES, cqEntries)
                }
                putInt(params + IoUring.P_FLAGS, flags)
                return Native.ioUringSetup(entries, params)
            }

            var fd = attempt()
            var delay = 5L
            var tries = 1
            while (fd == -Native.ENOMEM && tries < 6) {
                Thread.sleep(delay)
                fd = attempt()
                delay *= 2
                tries++
            }
            return fd
        }

        /** Roughly what one ring costs against RLIMIT_MEMLOCK, for the diagnostic below. */
        private fun estimateRingKib(entries: Int): Long = (entries * (64L + 4) + entries * 2L * 16 + 4096) / 1024

        // A failed setup in terms a host can act on: a bare "errno 22" sends people to limits and permissions
        // first, when the usual cause is a kernel older than the setup flags.
        internal fun describeSetupFailure(errno: Int, entries: Int, kernelRelease: String): String {
            val failed = "io_uring_setup failed with errno $errno for a ring of $entries entries on Linux $kernelRelease"
            return when {
                errno == Native.EINVAL && entries > 32768 -> "$failed: the kernel allows at most 32768 (ServerConfig.ringEntries)."
                errno == Native.EINVAL && kernelOlderThan(kernelRelease, 6, 1) ->
                    "$failed: the kernel does not know SINGLE_ISSUER | DEFER_TASKRUN, and ioxide needs Linux 6.1 or later."
                errno == Native.ENOMEM ->
                    "$failed: it costs roughly ${estimateRingKib(entries)} KiB of RLIMIT_MEMLOCK, and the kernel reclaims " +
                        "a closed ring's memory asynchronously - raise `ulimit -l`, lower ServerConfig.ringEntries, or " +
                        "create reactors less abruptly."
                errno == Native.EPERM ->
                    "$failed: io_uring is disabled here, by the kernel.io_uring_disabled sysctl or by a seccomp profile " +
                        "such as a container runtime's default."
                errno == Native.ENOSYS -> "$failed: this kernel was built without io_uring."
                else -> "$failed."
            }
        }

        private fun kernelRelease(): String =
            try {
                Files.readString(Path.of("/proc/sys/kernel/osrelease")).trim()
            } catch (_: Exception) {
                System.getProperty("os.version") ?: "unknown"
            }

        // "5.15.167.4-microsoft-standard-WSL2" is older than 6.1; "6.14.0-37-generic" is not.
        internal fun kernelOlderThan(release: String, major: Int, minor: Int): Boolean {
            val parts = release.split('.', '-')
            if (parts.size < 2) return false
            val a = parts[0].toIntOrNull() ?: return false
            val b = parts[1].toIntOrNull() ?: return false
            return a < major || (a == major && b < minor)
        }
    }
}
