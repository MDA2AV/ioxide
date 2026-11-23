package ioxide

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

/**
 * One reactor: one thread, one io_uring, one SO_REUSEPORT listener per port and one connection table.
 * Nothing is shared between reactors. The reactor thread is the only one that touches the ring, the buffer
 * group and the table; other threads reach it through [post] and an eventfd the ring polls.
 *
 * Handlers run on the reactor thread, inside completion dispatch: a connection's handler starts in its accept
 * completion and is resumed by its recv and send completions, inline, with no dispatcher between. Call [run]
 * on the thread meant to be the reactor's (the ring must be created, entered and closed there); [stop] from
 * anywhere.
 */
class Reactor(val id: Int, private val config: ServerConfig) {
    /** Runs on the reactor thread before the first accept is armed, listeners bound. */
    var onStart: ((Reactor) -> Unit)? = null

    /**
     * Raised on the reactor thread when it ends by a fault rather than [stop] - a kernel refusing the ring
     * included - before the teardown. Without it the exception propagates out of [run].
     */
    var onFault: ((Reactor, Throwable) -> Unit)? = null

    /**
     * The per-connection handler, started once per accepted connection on the reactor thread. Its ref on the
     * connection is let go when it returns or throws.
     */
    var tcpHandler: (suspend (TcpConnection) -> Unit)? = null

    /**
     * The coroutine context handlers start in. Empty by default: a handler's suspensions are the
     * connection's own, resumed inline by the reactor. Put a dispatcher that posts to [post] here to have
     * coroutines started inside handlers come back to this reactor.
     */
    var handlerContext: CoroutineContext = EmptyCoroutineContext

    private val tcpOptions = config.tcp
    internal val tcp: TcpTransport? = tcpOptions?.let { TcpTransport(this, config, it) }

    init {
        require(config.ringEntries > 0) { "ringEntries must be positive" }
        require(config.opSlots > 0) { "opSlots must be positive" }
        if (tcpOptions != null) {
            require(isPow2(tcpOptions.recvQueueEntries)) { "tcp.recvQueueEntries (${tcpOptions.recvQueueEntries}) must be a power of two" }
            require(tcpOptions.writeSlabSize > 0) { "tcp.writeSlabSize must be positive" }
            require(isPow2(config.recvSlots) && config.recvSlots <= 32768) { "recvSlots (${config.recvSlots}) must be a power of two up to 32768" }
            require(config.recvBufferSize > 0) { "recvBufferSize must be positive" }
        }
    }

    internal lateinit var ring: Ring
        private set

    private var thread: Thread? = null

    /** True on this reactor's own thread. */
    val onReactorThread: Boolean get() = Thread.currentThread() === thread

    /** The ports this reactor listens on, as bound (a configured 0 reads back as the kernel's pick). */
    val listenPorts: IntArray get() = tcp?.listenPorts?.copyOf() ?: IntArray(0)

    /** The monotonic clock in ms, read once per loop pass. */
    var nowMs: Long = Clock.monotonicMs()
        internal set

    @Volatile private var stopRequested = false
    private var ranLoop = false

    // ---- Lifecycle --------------------------------------------------------------------------------------

    /**
     * The reactor's life, on the calling thread, which becomes the reactor's: create the ring, open the
     * listeners and the buffer group, run [onStart], loop until [stop], tear down.
     */
    fun run() {
        thread = Thread.currentThread()

        // Its own catch: there is nothing to tear down until the ring exists, and a refusal (an old kernel,
        // a seccomp profile) is a fault the host must hear of.
        try {
            ring = Ring.create(config.ringEntries)
        } catch (e: Throwable) {
            val fault = onFault ?: throw e
            fault(this, e)
            return
        }

        try {
            tcp?.openListeners()
            tcp?.initBufferRing()
            openWakeFd()

            onStart?.invoke(this)

            announceListening()
            tcp?.armAccepts()
            armWakePoll()

            // After onStart, so a reactor that serves no TCP registers nothing.
            if (tcp != null) addTicker { tcp.sweep() }

            nowMs = Clock.monotonicMs()
            nextTickMs = nowMs + TICK_MS

            ranLoop = true
            loop()
        } catch (e: Throwable) {
            val fault = onFault ?: throw e
            fault(this, e)
        } finally {
            teardown()
        }
    }

    /**
     * Asks the reactor to stop, from any thread: the loop finishes its pass, then [run] tears down on the
     * reactor thread. Join that thread to wait for it.
     */
    fun stop() {
        stopRequested = true
        // The flag alone is seen only on the next pass; the write wakes a loop parked in the kernel.
        wakeFdWrite()
    }

    private fun announceListening() {
        val ports = tcp?.listenPorts
        System.err.println("[r$id] listening on " + (if (ports != null && ports.isNotEmpty()) "0.0.0.0:${ports.joinToString(",")}" else "(no tcp)"))
    }

    // ---- Loop -------------------------------------------------------------------------------------------

    private fun loop() {
        val tcp = tcp
        while (!stopRequested) {
            clearWakePending()
            tcp?.drainReturnQ()
            drainPostQ()
            tcp?.rearmStarvedRecvs()

            // The transient three, which the loop carries on from - a signal, the kernel short of resources,
            // CQ overflow it could not flush - and ETIME, the wait's own bound running out. Anything else is
            // a lifecycle or programming error, and a reactor that silently vanishes is the worst outcome.
            val rc = waitForCompletions()
            if (rc < 0 && rc != -Native.EINTR && rc != -Native.EAGAIN && rc != -Native.EBUSY && rc != -Native.ETIME) {
                throw IllegalStateException("[r$id] io_uring_enter failed with errno ${-rc}; this reactor cannot continue")
            }

            nowMs = Clock.monotonicMs()   // one read per batch

            val ring = ring
            val ready = ring.cqReady()
            for (i in 0 until ready) {
                val cqe = ring.cqeAt(i)
                dispatch(getLong(cqe), getInt(cqe + 8), getInt(cqe + 12))
            }
            ring.cqAdvance(ready)

            runDueTickers()
        }
    }

    private fun dispatch(userData: Long, res: Int, flags: Int) {
        val fd = userData.toInt()
        val gen = (userData ushr 32).toInt() and 0xFFFF
        when ((userData ushr 56).toInt()) {
            KIND_TCP_RECV -> tcp!!.onRecv(fd, gen, res, flags)
            KIND_TCP_SEND -> tcp!!.onSend(fd, gen, res)
            KIND_TCP_ACCEPT -> tcp!!.onAccept(fd, res, flags)
            KIND_OP -> onOpCompletion(fd, res)
            KIND_WAKE -> onWakeCompletion(flags)
            KIND_CANCEL -> {}
        }
    }

    // The wait, bounded by the next ticker run - read off a fresh clock, as nowMs predates this pass's work.
    // +1: the ms clock can read just short of the deadline when the kernel's timer wakes us.
    private fun waitForCompletions(): Int =
        ring.submitAndWait(1, maxOf(0L, nextTickMs - Clock.monotonicMs()) + 1)

    /** The SQE to fill next; when the SQ is full, what is queued goes to the kernel first. Reactor thread. */
    internal fun getSqeOrFlush(): Long {
        var sqe = ring.getSqe()
        if (sqe != 0L) return sqe

        // A few rounds clear the transient fullness a large CQE batch causes; only a stuck ring falls through.
        var attempt = 0
        while (sqe == 0L && attempt < 16) {
            ring.submitAndWait(0)
            sqe = ring.getSqe()
            attempt++
        }
        check(sqe != 0L) { "io_uring SQ still full after repeated flush" }
        return sqe
    }

    // ---- Handlers ---------------------------------------------------------------------------------------

    internal fun startHandler(conn: TcpConnection) {
        val handler = tcpHandler ?: run {
            conn.releaseHandlerRef(conn.generation)
            return
        }
        handler.startCoroutine(conn, HandlerCompletion(conn, conn.generation, handlerContext))
    }

    private inner class HandlerCompletion(
        private val conn: TcpConnection,
        private val lifeGeneration: Int,
        override val context: CoroutineContext,
    ) : Continuation<Unit> {
        override fun resumeWith(result: Result<Unit>) {
            result.exceptionOrNull()?.let {
                System.err.println("[r$id] connection handler faulted: ${it.stackTraceToString()}")
            }
            conn.releaseHandlerRef(lifeGeneration)
        }
    }

    // ---- Wake and handoff -------------------------------------------------------------------------------

    private val wakeFd = AtomicInteger(0)

    // 1 from a handoff's eventfd write until the loop's next pass clears it: the handoffs in between share
    // that one write.
    private val wakePending = AtomicInteger(0)

    // Writers holding the eventfd's number, so teardown can wait them out before it closes it: a writer
    // that read the old number would otherwise put 8 bytes into whatever socket took it next.
    private val wakeUsers = AtomicInteger(0)

    private var wakeBuffers = 0L   // [0, 8): the 1 every write adds; [8, 16): where the reactor drains it

    private val postQ = ConcurrentLinkedQueue<Runnable>()

    private fun openWakeFd() {
        wakeBuffers = Native.malloc(16)
        putLong(wakeBuffers, 1L)
        val fd = Native.eventfd(0, Native.EFD_NONBLOCK or Native.EFD_CLOEXEC)
        check(fd >= 0) { "eventfd failed with errno ${-fd}" }
        wakeFd.set(fd)
    }

    private fun armWakePoll() {
        val fd = wakeFd.get()
        IoUring.prep(getSqeOrFlush(), IoUring.OP_POLL_ADD, fd, 0L, IoUring.POLL_ADD_MULTI, 0L, tag(KIND_WAKE, 0, fd), opFlags = IoUring.POLLIN)
    }

    private fun onWakeCompletion(flags: Int) {
        // Drain the counter so the next write raises POLLIN again; the queues drain at the next pass's top.
        Native.read(wakeFd.get(), wakeBuffers + 8, 8)
        if (flags and IoUring.CQE_F_MORE == 0) armWakePoll()
    }

    /** Every handoff from another thread ends here, after its enqueue. */
    internal fun wake() {
        if (wakePending.getAndSet(1) == 0) wakeFdWrite()
    }

    // First in each pass, so a handoff landing during the drains still wakes the next one. An exchange, not a
    // store: otherwise a queue can read empty before the clear is visible.
    private fun clearWakePending() {
        wakePending.getAndSet(0)
    }

    private fun wakeFdWrite() {
        wakeUsers.incrementAndGet()
        try {
            val fd = wakeFd.get()
            if (fd > 0) Native.write(fd, wakeBuffers, 8)
        } finally {
            wakeUsers.decrementAndGet()
        }
    }

    /**
     * Runs [task] on the reactor thread, on the loop's next pass. Always queued, so a post from the reactor
     * thread itself runs after the current dispatch; from another thread it wakes the loop.
     */
    fun post(task: Runnable) {
        postQ.offer(task)
        if (!onReactorThread) wake()
    }

    private fun drainPostQ() {
        while (true) {
            val task = postQ.poll() ?: return
            // A task that throws must not unwind the loop and end the reactor.
            try {
                task.run()
            } catch (e: Throwable) {
                System.err.println("[r$id] posted task threw: ${e.stackTraceToString()}")
            }
        }
    }

    // ---- Ticker -----------------------------------------------------------------------------------------

    private var nextTickMs = 0L
    private val tickers = ArrayList<Runnable>()

    /** Runs [ticker] on the reactor thread about every [TICK_MS]. Call from [onStart]. */
    fun addTicker(ticker: Runnable) {
        tickers.add(ticker)
    }

    // Checked on every pass, not left to the wait running out: a busy reactor's wait never does.
    private fun runDueTickers() {
        if (nowMs < nextTickMs) return
        nextTickMs = nowMs + TICK_MS
        for (ticker in tickers) {
            try {
                ticker.run()
            } catch (e: Throwable) {
                System.err.println("[r$id] ticker faulted: ${e.message}")
            }
        }
    }

    // ---- Ring operations (timers) -----------------------------------------------------------------------

    // In-flight operations by slot; the CQE carries the slot. Reactor thread only.
    private var opTargets = arrayOfNulls<RingCompletion>(config.opSlots)
    private var opFree = IntArray(config.opSlots) { config.opSlots - 1 - it }
    private var opFreeTop = config.opSlots

    // One timespec per slot: the kernel reads it when it consumes the SQE, so it must outlive the submit -
    // tied to the slot, its lifetime is exactly the operation's, with no allocation per wait.
    private var opTimespecs = 0L
    private var opTimespecCapacity = 0

    /**
     * Completes [completion] with -ETIME after [nanoseconds], on this reactor. From another thread the
     * submission is handed over.
     */
    internal fun submitTimeout(nanoseconds: Long, completion: RingCompletion) {
        if (!onReactorThread) {
            post { submitTimeout(nanoseconds, completion) }
            return
        }

        val slot = allocOpSlot(completion)
        ensureTimespecCapacity()

        val ts = opTimespecs + slot * 16L
        val ns = maxOf(nanoseconds, 1L)   // a zero timespec disarms rather than fires
        putLong(ts, ns / 1_000_000_000L)
        putLong(ts + 8, ns % 1_000_000_000L)

        IoUring.prep(getSqeOrFlush(), IoUring.OP_TIMEOUT, -1, ts, 1, 0L, tag(KIND_OP, 0, slot))
    }

    private fun onOpCompletion(slot: Int, res: Int) {
        val target = opTargets[slot]
        opTargets[slot] = null
        opFree[opFreeTop++] = slot
        // The slot is free first: the inline continuation may submit its next op.
        target?.complete(res)
    }

    private fun allocOpSlot(completion: RingCompletion): Int {
        if (opFreeTop == 0) {
            val oldLength = opTargets.size
            opTargets = opTargets.copyOf(oldLength * 2)
            opFree = opFree.copyOf(oldLength * 2)
            for (i in oldLength * 2 - 1 downTo oldLength) opFree[opFreeTop++] = i
        }
        val slot = opFree[--opFreeTop]
        opTargets[slot] = completion
        return slot
    }

    // Grown with the slot table, so a slot always has a timespec behind it.
    private fun ensureTimespecCapacity() {
        if (opTimespecCapacity >= opTargets.size) return

        // Queued timeouts point into the old block until submitted.
        if (opTimespecs != 0L) {
            while (ring.sqPending() > 0 && ring.submitAndWait(0) > 0) {
                // until the kernel has consumed them all
            }
        }

        val bytes = opTargets.size * 16L
        val block = Native.malloc(bytes)
        if (opTimespecs != 0L) {
            copyMemory(opTimespecs, block, opTimespecCapacity * 16L)
            Native.free(opTimespecs)
        }
        opTimespecs = block
        opTimespecCapacity = opTargets.size
    }

    // ---- Teardown ---------------------------------------------------------------------------------------

    // Still on the reactor thread, in dependency order: sockets close while the ring is alive, the ring goes
    // next, and memory the kernel could reference is freed only after that.
    private fun teardown() {
        val startFailed = !ranLoop
        stopRequested = true

        tcp?.closeListeners()
        tcp?.closeAcceptedSockets()

        // Taken away before it is closed, and its writers waited out.
        val fd = wakeFd.getAndSet(0)
        if (fd > 0) {
            while (wakeUsers.get() != 0) Thread.onSpinWait()
            Native.close(fd)
        }

        tcp?.unregisterBufferRing()

        // A failed start keeps the ring's descriptor: releasing its number mid-run could close whatever
        // reuses it, a live connection included. It costs the ring's memlock charge until exit.
        ring.close(closeFd = !startFailed)

        if (opTimespecs != 0L) {
            Native.free(opTimespecs)
            opTimespecs = 0L
            opTimespecCapacity = 0
        }
        tcp?.freeMemory()
        Native.free(wakeBuffers)
        wakeBuffers = 0L
    }

    companion object {
        /** The ticker's interval: the granularity of every sweep. */
        const val TICK_MS = 250L

        // user_data: [63:56] kind | [47:32] connection generation | [31:0] fd (or op slot).
        internal const val KIND_TCP_ACCEPT = 1
        internal const val KIND_TCP_RECV = 2
        internal const val KIND_TCP_SEND = 3
        internal const val KIND_WAKE = 4
        internal const val KIND_OP = 5
        internal const val KIND_CANCEL = 6

        internal fun tag(kind: Int, gen: Int, fd: Int): Long =
            (kind.toLong() shl 56) or ((gen.toLong() and 0xFFFF) shl 32) or (fd.toLong() and 0xFFFF_FFFFL)

        private fun isPow2(v: Int): Boolean = v > 0 && v and (v - 1) == 0
    }
}

/** An in-flight ring operation's completion, called on the reactor thread with the CQE's result. */
internal fun interface RingCompletion {
    fun complete(result: Int)
}

/** The monotonic clock in milliseconds, from an origin that makes it start at 1 (0 means "never"). */
internal object Clock {
    private val origin = System.nanoTime()

    fun monotonicMs(): Long = (System.nanoTime() - origin) / 1_000_000 + 1
}
