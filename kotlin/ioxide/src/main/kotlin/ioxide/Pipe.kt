package ioxide

import java.lang.foreign.MemorySegment

/**
 * The reading half of a pipe, after System.IO.Pipelines' PipeReader: [read] returns everything received and
 * not yet consumed, and [advanceTo] says how much of it was consumed and how much merely looked at - so a
 * parser that needs more bytes consumes nothing, examines everything, and its next read waits for new data
 * instead of returning the same bytes again.
 */
interface PipeReader {
    /**
     * Everything held and unconsumed; suspends when all of it was examined, until more arrives or the peer is
     * gone. The result and its buffer belong to the reader and are valid until the next [advanceTo].
     */
    suspend fun read(): ReadResult

    /** As [read] without waiting: null when everything held was examined. */
    fun tryRead(): ReadResult?

    /**
     * [consumed] bytes from the start of the last result's buffer are done with, and [examined] were looked
     * at (at least [consumed]). Consumed buffers go back to the reactor.
     */
    fun advanceTo(consumed: Long, examined: Long = consumed)

    /** The next [read] (or the parked one, once it wakes) returns with [ReadResult.isCanceled] set. */
    fun cancelPendingRead()

    /** Done reading: every held buffer goes back. Terminal. */
    fun complete()
}

/**
 * The writing half, after PipeWriter: bytes are staged with [write] or [getBuffer] + [advance] and sent by
 * [flush].
 */
interface PipeWriter {
    /** The address of at least [sizeHint] writable bytes (see [MEM]); commit them with [advance]. */
    fun getBuffer(sizeHint: Int = 1): Long

    /** [getBuffer] as a segment over everything writable. */
    fun getSegment(sizeHint: Int = 1): MemorySegment

    fun advance(count: Int)

    fun write(source: ByteArray, offset: Int = 0, length: Int = source.size - offset)

    /** Bytes staged since the last flush. */
    val unflushedBytes: Long

    /** Sends what is staged and waits until the kernel has taken it. */
    suspend fun flush(): FlushResult

    fun cancelPendingFlush()

    /** Done writing. Sends nothing by itself: flush first. */
    fun complete()
}

/** A [PipeReader.read]'s outcome: the buffer, and whether the peer is gone. Reused by its reader. */
class ReadResult internal constructor(val buffer: ReadBuffer) {
    /** Nothing more will arrive: [buffer] holds the last of it, possibly nothing. */
    var isCompleted: Boolean = false
        internal set

    var isCanceled: Boolean = false
        internal set

    internal fun set(completed: Boolean, canceled: Boolean): ReadResult {
        isCompleted = completed
        isCanceled = canceled
        return this
    }
}

/** A [PipeWriter.flush]'s outcome; one of four shared instances, so a flush allocates nothing. */
class FlushResult private constructor(val isCanceled: Boolean, val isCompleted: Boolean) {
    companion object {
        private val cache = arrayOf(
            FlushResult(isCanceled = false, isCompleted = false),
            FlushResult(isCanceled = false, isCompleted = true),
            FlushResult(isCanceled = true, isCompleted = false),
            FlushResult(isCanceled = true, isCompleted = true),
        )

        internal fun of(canceled: Boolean, completed: Boolean): FlushResult =
            cache[(if (canceled) 2 else 0) + (if (completed) 1 else 0)]
    }
}
