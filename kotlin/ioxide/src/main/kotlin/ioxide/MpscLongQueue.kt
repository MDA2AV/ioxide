package ioxide

import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray

/**
 * Bounded multi-producer, single-consumer queue of non-negative longs (Vyukov): other threads hand the
 * reactor packed values - buffer ids - without allocating per item.
 */
internal class MpscLongQueue(capacity: Int) {
    init {
        require(capacity > 0 && capacity and (capacity - 1) == 0) { "capacity must be a power of two" }
    }

    private val mask = (capacity - 1).toLong()
    private val sequence = AtomicLongArray(capacity)
    private val values = LongArray(capacity)
    private val enqueuePos = AtomicLong()
    private var dequeuePos = 0L

    init {
        for (i in 0 until capacity) sequence.set(i, i.toLong())
    }

    /** False when the queue is full. */
    fun offer(value: Long): Boolean {
        var pos = enqueuePos.get()
        while (true) {
            val index = (pos and mask).toInt()
            val diff = sequence.getAcquire(index) - pos
            if (diff == 0L) {
                if (enqueuePos.compareAndSet(pos, pos + 1)) {
                    values[index] = value
                    sequence.setRelease(index, pos + 1)
                    return true
                }
                pos = enqueuePos.get()
            } else if (diff < 0L) {
                return false
            } else {
                pos = enqueuePos.get()
            }
        }
    }

    /** The next value, or -1 when the queue is empty. The consumer's thread only. */
    fun poll(): Long {
        val pos = dequeuePos
        val index = (pos and mask).toInt()
        if (sequence.getAcquire(index) - (pos + 1) < 0L) return -1
        val value = values[index]
        sequence.setRelease(index, pos + mask + 1)
        dequeuePos = pos + 1
        return value
    }
}
