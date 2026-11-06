package ioxide

import java.io.IOException
import java.lang.foreign.MemorySegment
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/** A connection as a [PipeReader] and a [PipeWriter], the Kotlin twin of TcpConnectionDualPipe. */
class TcpDuplexPipe(val connection: TcpConnection) {
    val input: TcpPipeReader = TcpPipeReader(connection)
    val output: TcpPipeWriter = TcpPipeWriter(connection)
}

/**
 * [PipeReader] over a connection's recv queue, allocation-free once warm: received buffers are held in
 * place as slices (no copy), a parked read chains onto the connection's own read through a continuation this
 * reader owns (no state machine per call), and consumption trims the chain's front, handing each emptied
 * buffer back to the reactor.
 *
 * Holds buffers out of the shared group for as long as they are unconsumed, so a parser should consume what
 * it is done with. The connection's recycle takes back whatever a reader still holds.
 */
class TcpPipeReader(private val connection: TcpConnection) : PipeReader, RecvBufferHolder {
    private val chain = SliceChain()
    private val buffer = ReadBuffer(chain)
    private val result = ReadResult(buffer)
    private val item = RecvItem()

    private var heldBytes = 0L      // unconsumed bytes across the chain
    private var examinedBytes = 0L  // of those, how many the caller already examined

    private var completed = false
    private var cancelRequested = false
    private var connectionClosed = false

    // The caller parked in read; resumed when a recv brings new bytes.
    private var waiter: Continuation<ReadResult>? = null

    // What this reader parks on the connection's read: resumed inline by the reactor's recv completion.
    private val recvReady = object : Continuation<RecvSnapshot> {
        override val context: CoroutineContext get() = EmptyCoroutineContext

        override fun resumeWith(result: Result<RecvSnapshot>) = onRecvReady(result.getOrThrow())
    }

    // Closed by a recv-queue overflow, which dropped data: an error, never the clean end a peer's close is.
    private val lostToOverflow: Boolean get() = connectionClosed && connection.recvOverflowed

    init {
        // So the reactor can reclaim at recycle what this reader dequeued and never gave back.
        connection.bufferHolder = this
    }

    override suspend fun read(): ReadResult {
        if (!connection.reactor.onReactorThread) return readOffReactor()
        return suspendCoroutineUninterceptedOrReturn { readOrPark(it) }
    }

    private fun readOrPark(cont: Continuation<ReadResult>): Any {
        check(!completed) { "Reading is not allowed after the reader was completed." }

        if (cancelRequested) {
            cancelRequested = false
            return build(canceled = true)
        }

        // Unexamined bytes, or a closed connection, complete at once.
        if (heldBytes > examinedBytes || connectionClosed) return syncResult()

        // Everything held was examined: wait for new bytes.
        while (true) {
            val r = connection.readOrPark(recvReady)
            if (r === COROUTINE_SUSPENDED) {
                waiter = cont
                return COROUTINE_SUSPENDED
            }
            if (ingest(r as RecvSnapshot) || connectionClosed || cancelRequested) return syncResult()
            // A wake with nothing new: arm again.
        }
    }

    private fun syncResult(): ReadResult {
        if (lostToOverflow) throw overflowError()
        val canceled = cancelRequested
        cancelRequested = false
        return build(canceled)
    }

    private suspend fun readOffReactor(): ReadResult = suspendCoroutine { cont ->
        connection.reactor.post {
            try {
                val r = readOrPark(cont)
                if (r !== COROUTINE_SUSPENDED) cont.resume(r as ReadResult)
            } catch (e: Throwable) {
                cont.resumeWithException(e)
            }
        }
    }

    // The connection's read completed while a caller was parked - inline on the reactor.
    private fun onRecvReady(snapshot: RecvSnapshot) {
        if (!ingest(snapshot) && !connectionClosed && !cancelRequested) {
            // Nothing new: re-arm without completing the caller.
            while (true) {
                val r = connection.readOrPark(recvReady)
                if (r === COROUTINE_SUSPENDED) return
                if (ingest(r as RecvSnapshot) || connectionClosed || cancelRequested) break
            }
        }

        val cont = waiter ?: return   // completed while parked: the held bytes go back at recycle
        waiter = null

        if (lostToOverflow) {
            cont.resumeWithException(overflowError())
            return
        }
        val canceled = cancelRequested
        cancelRequested = false
        cont.resume(build(canceled))
    }

    // Drains a snapshot into the chain. True if any bytes were added.
    private fun ingest(snapshot: RecvSnapshot): Boolean {
        var any = false
        while (connection.tryGetItem(snapshot, item)) {
            if (!item.hasBuffer) continue
            chain.add(item.address, item.length, item.bufferId)
            heldBytes += item.length
            any = true
        }
        if (snapshot.isClosed) connectionClosed = true
        return any
    }

    private fun build(canceled: Boolean): ReadResult {
        buffer.capture(heldBytes)
        return result.set(connectionClosed, canceled)
    }

    override fun tryRead(): ReadResult? {
        check(!completed) { "Reading is not allowed after the reader was completed." }
        if (cancelRequested) {
            cancelRequested = false
            return build(canceled = true)
        }
        if (heldBytes > examinedBytes || connectionClosed) return syncResult()
        return null
    }

    override fun advanceTo(consumed: Long, examined: Long) {
        require(consumed in 0..heldBytes) { "consumed ($consumed) outside the buffer (0..$heldBytes)" }
        val examinedAtLeast = maxOf(examined, consumed)

        // Fully consumed slices come off the front; their buffers go back to the reactor.
        var remaining = consumed
        while (remaining > 0 && chain.count > 0) {
            val available = chain.length(chain.head) - chain.headConsumed
            if (remaining >= available) {
                connection.returnBuffer(chain.removeHead())
                remaining -= available
            } else {
                chain.headConsumed += remaining.toInt()
                remaining = 0
            }
        }

        heldBytes -= consumed
        examinedBytes = minOf(examinedAtLeast - consumed, heldBytes)
        buffer.clear()
    }

    /** Sets the flag only: a parked read sees it when it next wakes. */
    override fun cancelPendingRead() {
        cancelRequested = true
    }

    override fun complete() {
        if (completed) return
        completed = true
        releaseHeldBuffers()
    }

    /**
     * Hands every held buffer back and forgets the chain. Called by [complete], and by the reactor at recycle
     * for a reader its handler never completed. Idempotent: once the chain is empty it does nothing, so
     * complete-then-recycle returns each buffer once. Terminal, so a reader kept past its handler fails instead
     * of reading the recycled connection's next tenant.
     */
    override fun releaseHeldBuffers() {
        completed = true
        connectionClosed = true
        while (chain.count > 0) connection.returnBuffer(chain.removeHead())
        heldBytes = 0
        examinedBytes = 0
        buffer.clear()
    }

    private companion object {
        fun overflowError() = IOException(
            "The connection's receive queue overflowed (TcpOptions.recvQueueEntries): data was dropped and the connection closed.",
        )
    }
}

/**
 * [PipeWriter] over a connection's write slab: writes go straight into it, and a parked flush chains onto
 * the connection's own flush, so the writer allocates nothing at steady state.
 */
class TcpPipeWriter(private val connection: TcpConnection) : PipeWriter {
    private var completed = false
    private var cancelRequested = false
    private var waiter: Continuation<FlushResult>? = null

    private val flushDone = object : Continuation<Unit> {
        override val context: CoroutineContext get() = EmptyCoroutineContext

        override fun resumeWith(result: Result<Unit>) = onFlushDone()
    }

    override var unflushedBytes: Long = 0
        private set

    override fun getBuffer(sizeHint: Int): Long = connection.getBuffer(sizeHint)

    override fun getSegment(sizeHint: Int): MemorySegment = connection.getSegment(sizeHint)

    override fun advance(count: Int) {
        connection.advance(count)
        unflushedBytes += count
    }

    override fun write(source: ByteArray, offset: Int, length: Int) {
        connection.write(source, offset, length)
        unflushedBytes += length
    }

    override suspend fun flush(): FlushResult {
        if (!connection.reactor.onReactorThread) return flushOffReactor()
        return suspendCoroutineUninterceptedOrReturn { flushOrPark(it) }
    }

    private fun flushOrPark(cont: Continuation<FlushResult>): Any {
        if (cancelRequested) {
            cancelRequested = false
            return FlushResult.of(canceled = true, completed = completed || connection.isClosed)
        }

        unflushedBytes = 0
        if (connection.flushOrPark(flushDone) === COROUTINE_SUSPENDED) {
            waiter = cont
            return COROUTINE_SUSPENDED
        }
        return FlushResult.of(canceled = false, completed = completed || connection.isClosed)
    }

    private suspend fun flushOffReactor(): FlushResult = suspendCoroutine { cont ->
        connection.reactor.post {
            try {
                val r = flushOrPark(cont)
                if (r !== COROUTINE_SUSPENDED) cont.resume(r as FlushResult)
            } catch (e: Throwable) {
                cont.resumeWithException(e)
            }
        }
    }

    // The connection's flush completed - inline on the reactor. A closed connection reads as completed, as on
    // the synchronous paths, so a write-until-completed loop stops against a peer that has gone.
    private fun onFlushDone() {
        val cont = waiter ?: return
        waiter = null
        val canceled = cancelRequested
        cancelRequested = false
        cont.resume(FlushResult.of(canceled, completed || connection.isClosed))
    }

    override fun cancelPendingFlush() {
        cancelRequested = true
    }

    override fun complete() {
        completed = true
    }
}
