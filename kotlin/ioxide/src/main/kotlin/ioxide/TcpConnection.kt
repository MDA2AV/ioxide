package ioxide

import java.lang.foreign.MemorySegment
import java.util.Objects
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * One accepted TCP connection: the queue of buffers its recvs filled, the write slab its response is staged
 * in, and the two refs that decide when it is recycled - the handler's and the reactor's.
 *
 * The handler runs on the reactor's thread, and so does everything here: a suspending call made from another
 * thread is carried over with [Reactor.post] and resumes the caller where it was, so none of the state below
 * races the reactor and none of it needs atomics. The recv queue is the exception - its consumer may be on
 * any thread - and so is [isClosed].
 *
 * Reading: [read] waits for data, [tryGetItem] takes each received buffer, [returnBuffer] hands it back.
 * Writing: [write] or [getBuffer] + [advance] stage bytes, [flush] sends them and waits until the kernel has
 * taken them all. The handler's ref is let go when the handler returns (or earlier, with [decRef]); the
 * reactor's when the peer is gone; the connection is recycled once both are.
 */
class TcpConnection internal constructor(
    private val tcp: TcpTransport,
    fd: Int,
    writeSlabSize: Int,
    recvQueueEntries: Int,
) {
    /** The reactor this connection belongs to; its handler runs on that reactor's thread. */
    val reactor: Reactor get() = tcp.reactor

    /** The accepted socket. The reactor owns it and closes it at recycle. */
    var clientFd: Int = fd
        private set

    /** The listener port this connection was accepted on. */
    var listenerPort: Int = 0
        internal set

    // Bumped by clear(); the low 16 bits ride in every user_data, so a CQE from a previous life is told apart.
    internal var generation = 0
        private set

    internal fun setFd(fd: Int): TcpConnection {
        clientFd = fd
        return this
    }

    // ---- Read side --------------------------------------------------------------------------------------

    private val recv = RecvQueue(recvQueueEntries)
    private val snapshot = RecvSnapshot()
    private var readCont: Continuation<RecvSnapshot>? = null

    // A completion that found no read waiting: the next read returns at once, even with nothing queued.
    private var pending = false

    @Volatile private var closed = false
    @Volatile private var overflowed = false

    /**
     * Whether the connection has been torn down. A writer needs this: once it is true nothing will ever send
     * what it stages, so buffering more is not backpressure, it is a leak.
     */
    val isClosed: Boolean get() = closed

    /**
     * Whether a recv-queue overflow closed the connection ([TcpOptions.recvQueueEntries]): the delivery that
     * did not fit was dropped, so the closed snapshot that follows is not the peer's clean end.
     */
    val recvOverflowed: Boolean get() = overflowed

    /**
     * Waits for received data. Returns at once when something is already queued or the connection is closed;
     * otherwise suspends until the next recv completion, or the close.
     *
     * Take the items with [tryGetItem]; each one with a buffer must be handed back with [returnBuffer]. One
     * read at a time. The snapshot is the connection's own, valid until the next read.
     */
    suspend fun read(): RecvSnapshot {
        if (!tcp.reactor.onReactorThread) return readOffReactor()
        return suspendCoroutineUninterceptedOrReturn { readOrPark(it) }
    }

    // Reactor thread. The parked continuation is resumed inline by the next recv completion. The pipe reader
    // parks its own continuation here, chaining onto the read instead of suspending through it.
    internal fun readOrPark(cont: Continuation<RecvSnapshot>): Any {
        if (pending || !recv.isEmpty()) {
            pending = false
            return snapshotNow()
        }

        if (closed) return snapshot.set(0, true)

        readParkedMs = tcp.reactor.nowMs   // the read clock, see TcpTransport.sweep
        check(readCont == null) { "read() is already waiting." }
        readCont = cont
        return COROUTINE_SUSPENDED
    }

    private suspend fun readOffReactor(): RecvSnapshot = suspendCoroutine { cont ->
        tcp.reactor.post {
            val result = readOrPark(cont)
            if (result !== COROUTINE_SUSPENDED) cont.resume(result as RecvSnapshot)
        }
    }

    /**
     * Takes the next item of [snapshot]. This is a dequeue and it transfers ownership: every item with a
     * buffer must be handed back with [returnBuffer], exactly once - the connection no longer tracks it, and
     * a buffer never returned is gone from the group every connection of the reactor draws from.
     */
    fun tryGetItem(snapshot: RecvSnapshot, item: RecvItem): Boolean = recv.tryDequeueUntil(snapshot.tail, item)

    /** Items [snapshot] holds that have not been taken yet. */
    fun itemCount(snapshot: RecvSnapshot): Int = recv.countUntil(snapshot.tail)

    /** Hands [item]'s buffer back to the reactor, which offers it to the kernel again. */
    fun returnBuffer(item: RecvItem) {
        if (item.hasBuffer) tcp.returnBuffer(item.bufferId)
    }

    internal fun returnBuffer(bufferId: Int) = tcp.returnBuffer(bufferId)

    private fun snapshotNow(): RecvSnapshot = snapshot.set(recv.snapshotTail(), closed)

    // The reactor's recv path. False on recv-queue overflow; the reactor then tears the connection down.
    internal fun complete(length: Int, bufferId: Int, address: Long): Boolean {
        if (!recv.tryEnqueue(address, length, bufferId, generation)) {
            System.err.println("[conn] recv queue overflow; closing connection.")
            overflowed = true
            if (bufferId >= 0) tcp.returnBufferDirect(bufferId)
            return false
        }
        signalRead()
        return true
    }

    private fun signalRead() {
        val cont = readCont
        if (cont != null) {
            readCont = null
            cont.resume(snapshotNow())
        } else {
            pending = true
        }
    }

    // Wakes a parked read with whatever is queued, possibly nothing; the next read returns at once when none
    // is parked. Reactor thread.
    internal fun wakeRead() = signalRead()

    // Wakes a parked read with closed = true. Reactor thread.
    internal fun markClosed() {
        closed = true
        signalRead()
        releaseParkedFlush()
    }

    // Recycle: hands back the buffers still queued.
    internal fun drainRecv(scratch: RecvItem) {
        while (recv.tryDequeue(scratch)) {
            if (scratch.hasBuffer) tcp.returnBufferDirect(scratch.bufferId)
        }
    }

    /**
     * The adapter holding buffers taken out of the queue, if any: recycle asks it to give them back, so a
     * buffer stranded by a handler that returned early does not depend on the handler remembering.
     */
    internal var bufferHolder: RecvBufferHolder? = null

    internal fun releaseHeldRecvBuffers() {
        val holder = bufferHolder ?: return
        bufferHolder = null
        holder.releaseHeldBuffers()
    }

    // ---- Write side -------------------------------------------------------------------------------------

    private val baseSlabSize = writeSlabSize
    private var slabSize = writeSlabSize
    internal var writeBuffer: Long = Native.alignedAlloc(64, writeSlabSize.toLong())
    internal var writeHead = 0
    internal var writeTail = 0
    internal var writeInFlight = 0

    // FLUSH_IDLE, FLUSH_ARMED (handed to the reactor) or FLUSH_SUBMITTED (with the kernel, which reads the
    // slab until the send's final completion - so only that completion may end a submitted flush).
    private var flushArmed = FLUSH_IDLE
    private var flushInProgress = false
    private var flushCont: Continuation<Unit>? = null

    // The reactor's clock when the flush was handed over; never cleared, as that would put a store on the
    // send path's hottest point.
    internal var flushArmedMs = 0L

    internal val flushSubmitted: Boolean get() = flushArmed == FLUSH_SUBMITTED

    // Whether a flush is outstanding: the sweep's sign that this connection is sending, not waiting on its peer.
    internal val flushOutstanding: Boolean get() = flushInProgress

    /** Bytes staged and not yet flushed. */
    val writtenBytes: Int get() = writeTail

    /** Bytes [getBuffer]'s address can take before the slab has to grow. */
    val writableBytes: Int get() = slabSize - writeTail

    /** Copies [length] bytes of [source] from [offset] into the write slab. */
    fun write(source: ByteArray, offset: Int = 0, length: Int = source.size - offset) {
        checkWritable()
        Objects.checkFromIndexSize(offset, length, source.size)
        ensureWritable(length)
        copyFromArray(source, offset, writeBuffer + writeTail, length)
        writeTail += length
    }

    /** Copies [source] into the write slab. */
    fun write(source: MemorySegment) {
        checkWritable()
        val length = Math.toIntExact(source.byteSize())
        ensureWritable(length)
        MemorySegment.copy(source, 0, MEM, writeBuffer + writeTail, length.toLong())
        writeTail += length
    }

    /**
     * The address of at least [sizeHint] writable bytes at the write position (see [MEM]), growing the slab
     * if it has to; [advance] commits what was written there. Valid until the next write call or flush.
     */
    fun getBuffer(sizeHint: Int = 1): Long {
        checkWritable()
        ensureWritable(maxOf(sizeHint, 1))
        return writeBuffer + writeTail
    }

    /** [getBuffer] as a segment over everything writable without growing again. */
    fun getSegment(sizeHint: Int = 1): MemorySegment {
        val address = getBuffer(sizeHint)
        return MEM.asSlice(address, (slabSize - writeTail).toLong())
    }

    /** Commits [count] bytes written at [getBuffer]'s address. */
    fun advance(count: Int) {
        checkWritable()
        require(count >= 0 && count <= slabSize - writeTail) { "advance($count) past the writable ${slabSize - writeTail} bytes" }
        writeTail += count
    }

    private fun checkWritable() = check(!flushInProgress) { "Cannot write while flush is in progress." }

    private fun ensureWritable(need: Int) {
        if (need > slabSize - writeTail) growWriteSlab(writeTail.toLong() + need)
    }

    // Doubles the slab and copies what is staged. Never during a flush, so the slab is not the kernel's.
    private fun growWriteSlab(required: Long) {
        var newSize = slabSize
        do {
            // Doubled past Int.MAX_VALUE the size wraps, to 0 at worst, and this loop would spin forever.
            if (newSize > Int.MAX_VALUE / 2) {
                throw OutOfMemoryError("The write slab cannot grow past $newSize bytes to hold $required; flush before writing more.")
            }
            newSize *= 2
        } while (newSize < required)

        val newBuffer = Native.alignedAlloc(64, newSize.toLong())
        if (writeTail > 0) copyMemory(writeBuffer, newBuffer, writeTail.toLong())
        Native.free(writeBuffer)
        writeBuffer = newBuffer
        slabSize = newSize
    }

    /**
     * Sends everything staged and waits until the kernel has taken all of it (MSG_WAITALL, partial sends
     * resubmitted) - not for the peer's ACK. One flush at a time, and no writes while it is out.
     *
     * A connection already closed drops what is staged and returns; one that fails while sending also returns
     * normally, so check [isClosed] (or the next read's snapshot) to learn of it.
     */
    suspend fun flush() {
        if (!tcp.reactor.onReactorThread) return flushOffReactor()
        return suspendCoroutineUninterceptedOrReturn { flushOrPark(it) }
    }

    // Reactor thread; the pipe writer chains onto it the way the pipe reader chains onto readOrPark.
    internal fun flushOrPark(cont: Continuation<Unit>): Any {
        if (closed) {
            if (flushArmed != FLUSH_SUBMITTED) dropStaged()
            return Unit
        }

        check(!flushInProgress) { "flush() is already in progress." }
        val target = writeTail
        if (target == 0) return Unit

        flushInProgress = true
        flushArmed = FLUSH_ARMED
        writeInFlight = target
        flushArmedMs = tcp.reactor.nowMs
        flushCont = cont
        tcp.submitFlush(this)
        return COROUTINE_SUSPENDED
    }

    private suspend fun flushOffReactor(): Unit = suspendCoroutine { cont ->
        tcp.reactor.post {
            if (flushOrPark(cont) !== COROUTINE_SUSPENDED) cont.resume(Unit)
        }
    }

    // The connection is torn down, so nothing will ever send the staged bytes; keeping them would make a writer
    // against a vanished peer grow the slab without end.
    private fun dropStaged() {
        writeTail = 0
    }

    // The reactor takes the flush to the kernel. False if it was released first.
    internal fun claimFlush(): Boolean {
        if (flushArmed != FLUSH_ARMED) return false
        flushArmed = FLUSH_SUBMITTED
        return true
    }

    // Frees a caller parked on a flush the kernel does not have. One it has completes with the send.
    private fun releaseParkedFlush() {
        if (flushArmed == FLUSH_ARMED) {
            flushArmed = FLUSH_IDLE
            flushInProgress = false
            resumeFlush()
        }
    }

    // The send path, once the kernel is done with the slab.
    internal fun completeFlush() {
        writeHead = 0
        writeTail = 0
        writeInFlight = 0
        flushInProgress = false
        if (flushArmed != FLUSH_IDLE) {
            flushArmed = FLUSH_IDLE
            resumeFlush()
        }
    }

    private fun resumeFlush() {
        val cont = flushCont ?: return
        flushCont = null
        cont.resume(Unit)
    }

    // ---- Lifetime ---------------------------------------------------------------------------------------

    // Two owners, the reactor (recv side) and the handler: 2 at accept, recycled at 0, so a connection is
    // never recycled under a live handler.
    private var refs = 0
    private var handlerRefReleased = false

    // Reactor thread: torn down while the kernel had a send; the reactor lets go when that send completes.
    internal var closeAfterSend = false

    // The flags this connection's sends carry, set at accept: kTLS TX refuses MSG_WAITALL, so its handoff
    // clears them.
    internal var sendFlags = 0

    internal var readParkedMs = 0L

    // The last sweep that found a flush in flight: when the server was last seen sending.
    internal var flushSeenMs = 0L

    // Set once the sweep has shut the connection down, so it is not shut down again every tick.
    internal var sweepClosed = false

    private var readTimeoutDisabled = false
    private var finSentMs = 0L
    private var finSent = FIN_NONE

    internal fun initRefs() {
        refs = 2
    }

    /**
     * The handler's release, once per life - the reactor makes it when the handler returns, so calling it is
     * only for letting go earlier. A peer still connected gets a FIN; the read side stays open until the peer
     * closes, bounded by [TcpOptions.readTimeoutMs].
     */
    fun decRef() {
        if (!tcp.reactor.onReactorThread) {
            tcp.reactor.post { decRef() }
            return
        }

        // Once per life: a release made twice would recycle the connection under the reactor's ref.
        if (handlerRefReleased) return
        handlerRefReleased = true

        // A FIN now would cut a flush in flight short, so the sweep sends that one once it completes.
        if (refs == 2 && !flushInProgress) sendFin()
        releaseRef()
    }

    internal fun releaseReactorRef() = releaseRef()

    private fun releaseRef() {
        if (--refs == 0) tcp.recycle(this)
    }

    // The reactor tore the connection down, so no FIN; before markClosed, whose woken handler lets go inline.
    internal fun suppressFin() {
        finSent = FIN_SENT
    }

    // Only meaningful while the connection is in the reactor's table, i.e. the reactor's ref is held.
    internal val handlerReleased: Boolean get() = refs == 1

    internal fun sendFin() {
        if (finSent != FIN_SENT) {
            finSent = FIN_SENT
            finSentMs = tcp.reactor.nowMs   // the peer's time to close starts now
            Native.shutdown(clientFd, Sockets.SHUT_WR)
        }
    }

    internal val finWasSent: Boolean get() = finSent == FIN_SENT
    internal val finWanted: Boolean get() = finSent == FIN_WANTED

    /**
     * Half-close: the peer gets a FIN once what has been flushed is out, and the read side stays open. For a
     * protocol that is done sending (HTTP's `Connection: close`). Nothing may be written after it.
     */
    fun shutdownWrite() {
        if (!tcp.reactor.onReactorThread) {
            tcp.reactor.post { shutdownWrite() }
            return
        }
        if (!flushInProgress) sendFin() else if (finSent == FIN_NONE) finSent = FIN_WANTED
    }

    /** Takes this connection off the read timeout for the rest of its life. */
    fun disableReadTimeout() {
        readTimeoutDisabled = true
    }

    // When the peer started owing the next move, or -1 when it does not: a read is parked on a connection
    // still on the read timeout, or the handler let go and its FIN is out.
    internal fun waitingOnPeerSince(): Long {
        if (handlerReleased) return if (finSentMs != 0L) finSentMs else -1
        if (readCont == null || readTimeoutDisabled) return -1
        return maxOf(readParkedMs, maxOf(flushArmedMs, flushSeenMs))
    }

    // The handler's coroutine ended, returning or throwing. Generation-guarded, and checked on the reactor
    // thread: a handler that let go early and finished after this connection was recycled must not release
    // the ref of its next life.
    internal fun releaseHandlerRef(lifeGeneration: Int) {
        if (!tcp.reactor.onReactorThread) {
            tcp.reactor.post { releaseHandlerRef(lifeGeneration) }
            return
        }
        if (generation == lifeGeneration) decRef()
    }

    // Recycle: every flag and counter back to a fresh connection's.
    internal fun clear() {
        generation++   // first, so CQEs and continuations from this life resolve as stale

        readCont = null
        pending = false
        closed = false
        overflowed = false
        flushArmed = FLUSH_IDLE
        flushInProgress = false
        flushCont = null
        flushArmedMs = 0
        readParkedMs = 0
        flushSeenMs = 0
        readTimeoutDisabled = false
        finSentMs = 0
        finSent = FIN_NONE
        sweepClosed = false
        closeAfterSend = false

        writeHead = 0
        writeTail = 0
        writeInFlight = 0

        // An overgrown slab goes back to its base size, so the pool does not keep large buffers.
        if (slabSize != baseSlabSize) {
            Native.free(writeBuffer)
            writeBuffer = Native.alignedAlloc(64, baseSlabSize.toLong())
            slabSize = baseSlabSize
        }

        recv.reset()
        bufferHolder = null
        handlerRefReleased = false
        listenerPort = 0
    }

    // Pool overflow and reactor teardown: frees the native memory.
    internal fun dispose() {
        if (writeBuffer != 0L) {
            Native.free(writeBuffer)
            writeBuffer = 0L
        }
    }

    private companion object {
        const val FLUSH_IDLE = 0
        const val FLUSH_ARMED = 1
        const val FLUSH_SUBMITTED = 2

        const val FIN_NONE = 0
        const val FIN_SENT = 1     // or suppressed
        const val FIN_WANTED = 2   // asked for behind a flush; the sweep sends it
    }
}

/**
 * An adapter that takes buffers out of a connection's queue and holds them past one read (a pipe reader):
 * recycle asks it to hand them back.
 */
internal interface RecvBufferHolder {
    fun releaseHeldBuffers()
}
