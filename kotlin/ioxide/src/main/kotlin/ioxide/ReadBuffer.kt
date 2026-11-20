package ioxide

import java.lang.foreign.MemorySegment
import java.util.Objects

/**
 * The recv slices a pipe reader holds, oldest first, in growable circular primitive arrays - address, length
 * and buffer id per slice - so holding one costs no object. [headConsumed] bytes of the oldest slice are
 * already consumed: consumption moves the start, it never copies or compacts.
 */
internal class SliceChain {
    private var mask = 15
    private var addresses = LongArray(16)
    private var lengths = IntArray(16)
    private var bufferIds = IntArray(16)

    var head = 0
        private set
    var count = 0
        private set
    var headConsumed = 0

    fun slot(i: Int): Int = (head + i) and mask

    fun address(slot: Int): Long = addresses[slot]

    fun length(slot: Int): Int = lengths[slot]

    fun add(address: Long, length: Int, bufferId: Int) {
        if (count == addresses.size) grow()
        val s = (head + count) and mask
        addresses[s] = address
        lengths[s] = length
        bufferIds[s] = bufferId
        count++
    }

    /** Drops the oldest slice and returns its buffer id. */
    fun removeHead(): Int {
        val id = bufferIds[head]
        head = (head + 1) and mask
        count--
        headConsumed = 0
        return id
    }

    private fun grow() {
        val size = addresses.size * 2
        val a = LongArray(size)
        val l = IntArray(size)
        val b = IntArray(size)
        for (i in 0 until count) {
            val s = slot(i)
            a[i] = addresses[s]
            l[i] = lengths[s]
            b[i] = bufferIds[s]
        }
        addresses = a
        lengths = l
        bufferIds = b
        mask = size - 1
        head = 0
    }
}

/**
 * The bytes a [ReadResult] holds: one or more native segments read in place - the provided buffers the
 * kernel received into, not a copy. Positions are offsets from the start of this buffer. Valid until the
 * reader's next [PipeReader.advanceTo].
 *
 * Most reads are one segment ([isSingleSegment]); [segment] hands it out as a [MemorySegment]. The scans
 * ([indexOf]) work across segment boundaries.
 */
class ReadBuffer internal constructor(private val chain: SliceChain) {
    /** Total bytes. */
    var length: Long = 0
        private set

    /** Segments, in order. */
    var segmentCount: Int = 0
        private set

    private var startOffset = 0

    // The view as of the result being built: later ingests extend the chain, not this buffer.
    internal fun capture(heldBytes: Long) {
        length = heldBytes
        segmentCount = chain.count
        startOffset = chain.headConsumed
    }

    internal fun clear() {
        length = 0
        segmentCount = 0
        startOffset = 0
    }

    val isEmpty: Boolean get() = length == 0L

    val isSingleSegment: Boolean get() = segmentCount <= 1

    /** Where segment [i]'s bytes start, see [MEM]. */
    fun segmentAddress(i: Int): Long {
        Objects.checkIndex(i, segmentCount)
        val s = chain.slot(i)
        return chain.address(s) + if (i == 0) startOffset else 0
    }

    fun segmentLength(i: Int): Int {
        Objects.checkIndex(i, segmentCount)
        val s = chain.slot(i)
        return chain.length(s) - if (i == 0) startOffset else 0
    }

    /** Segment [i] as a bounds-checked view. */
    fun segment(i: Int = 0): MemorySegment = MEM.asSlice(segmentAddress(i), segmentLength(i).toLong())

    operator fun get(index: Long): Byte {
        Objects.checkIndex(index, length)
        var remaining = index
        for (i in 0 until segmentCount) {
            val len = segmentLength(i)
            if (remaining < len) return getByte(segmentAddress(i) + remaining)
            remaining -= len
        }
        throw IndexOutOfBoundsException(index.toString())
    }

    /** The first [value] at or after [from], or -1. */
    fun indexOf(value: Byte, from: Long = 0): Long {
        if (from >= length) return -1
        var base = 0L
        for (i in 0 until segmentCount) {
            val len = segmentLength(i)
            if (from < base + len) {
                val skip = if (from > base) (from - base).toInt() else 0
                val found = scan(segmentAddress(i) + skip, len - skip, value)
                if (found >= 0) return base + skip + found
            }
            base += len
        }
        return -1
    }

    /** The first occurrence of [pattern] at or after [from], or -1; it may span segments. */
    fun indexOf(pattern: ByteArray, from: Long = 0): Long {
        if (pattern.isEmpty()) return from.coerceAtMost(length)
        var at = from
        while (true) {
            val first = indexOf(pattern[0], at)
            if (first < 0 || first + pattern.size > length) return -1
            if (matches(first, pattern)) return first
            at = first + 1
        }
    }

    /** Whether [pattern] occurs at [index]. */
    fun matches(index: Long, pattern: ByteArray): Boolean {
        if (index < 0 || index + pattern.size > length) return false
        for (k in pattern.indices) if (this[index + k] != pattern[k]) return false
        return true
    }

    /** Copies [count] bytes from [from] into [destination] at [destinationOffset]. */
    fun copyTo(destination: ByteArray, destinationOffset: Int = 0, from: Long = 0, count: Int = (length - from).toInt()) {
        Objects.checkFromIndexSize(from, count.toLong(), length)
        Objects.checkFromIndexSize(destinationOffset, count, destination.size)
        var skip = from
        var written = 0
        for (i in 0 until segmentCount) {
            if (written == count) return
            val len = segmentLength(i)
            if (skip >= len) {
                skip -= len
                continue
            }
            val n = minOf(len - skip.toInt(), count - written)
            copyToArray(segmentAddress(i) + skip, destination, destinationOffset + written, n)
            written += n
            skip = 0
        }
    }

    fun toByteArray(from: Long = 0, count: Int = (length - from).toInt()): ByteArray {
        val bytes = ByteArray(count)
        copyTo(bytes, 0, from, count)
        return bytes
    }

    private companion object {
        const val ONES = 0x0101010101010101L
        const val HIGHS = -0x7F7F7F7F7F7F7F80L   // 0x8080808080808080

        // Eight bytes a step: a byte of (word ^ pattern) is zero where the value is; the classic has-zero test
        // marks the first such byte lowest, and the CPU is little-endian, so its index is the trailing zeros / 8.
        fun scan(address: Long, length: Int, value: Byte): Int {
            val pattern = (value.toLong() and 0xFF) * ONES
            var i = 0
            while (i + 8 <= length) {
                val word = getLong(address + i) xor pattern
                val found = (word - ONES) and word.inv() and HIGHS
                if (found != 0L) return i + (java.lang.Long.numberOfTrailingZeros(found) ushr 3)
                i += 8
            }
            while (i < length) {
                if (getByte(address + i) == value) return i
                i++
            }
            return -1
        }
    }
}
