package ioxide

import java.lang.foreign.MemorySegment
import java.lang.invoke.MethodHandles
import java.lang.invoke.VarHandle
import java.util.Objects

/**
 * What [TcpConnection.read] returns: how far the connection's recv queue reached when the read completed,
 * and whether the connection was closed by then. One per connection, reused by every read - valid until the
 * next one.
 */
class RecvSnapshot internal constructor() {
    var tail: Long = 0
        private set

    /** The connection is gone: nothing more will be queued, and a write is dropped. */
    var isClosed: Boolean = false
        private set

    internal fun set(tail: Long, closed: Boolean): RecvSnapshot {
        this.tail = tail
        this.isClosed = closed
        return this
    }
}

/**
 * One recv completion taken out of a connection's queue by [TcpConnection.tryGetItem]: [length] bytes at
 * [address], inside provided buffer [bufferId]. The bytes are the kernel's write, not a copy, and stay valid
 * until the buffer is handed back with [TcpConnection.returnBuffer] - after that the reactor may give the
 * buffer to any connection's next recv.
 *
 * A handler keeps one and reuses it for every item, so taking an item allocates nothing.
 */
class RecvItem {
    /** Where the received bytes start, see [MEM]. */
    var address: Long = 0
        internal set

    var length: Int = 0
        internal set

    /** The provided buffer holding the bytes, or -1 for an item without one. */
    var bufferId: Int = -1
        internal set

    val hasBuffer: Boolean get() = bufferId >= 0

    // The connection's generation when the recv was queued.
    internal var generation: Int = 0

    /** The bytes as a bounds-checked segment (a view: no copy, valid as long as the item is). */
    fun segment(): MemorySegment = MEM.asSlice(address, length.toLong())

    operator fun get(index: Int): Byte {
        Objects.checkIndex(index, length)
        return getByte(address + index)
    }

    /** Copies [count] bytes from [offset] into [destination] at [destinationOffset]. */
    fun copyTo(destination: ByteArray, destinationOffset: Int = 0, offset: Int = 0, count: Int = length - offset) {
        Objects.checkFromIndexSize(offset, count, length)
        Objects.checkFromIndexSize(destinationOffset, count, destination.size)
        copyToArray(address + offset, destination, destinationOffset, count)
    }

    internal fun set(address: Long, length: Int, bufferId: Int, generation: Int) {
        this.address = address
        this.length = length
        this.bufferId = bufferId
        this.generation = generation
    }
}

/**
 * A connection's queue of recv completions: one producer, the reactor, and one consumer, the handler, on
 * whichever thread it runs - so the indexes are published with release stores and read with acquire loads.
 * Items live in parallel primitive arrays, so a queued completion costs no object.
 */
internal class RecvQueue(capacity: Int) {
    init {
        require(capacity > 0 && capacity and (capacity - 1) == 0) { "capacity must be a power of two" }
    }

    private val mask = (capacity - 1).toLong()
    private val addresses = LongArray(capacity)
    private val lengths = IntArray(capacity)
    private val bufferIds = IntArray(capacity)
    private val generations = IntArray(capacity)

    @JvmField internal var head = 0L
    @JvmField internal var tail = 0L

    fun tryEnqueue(address: Long, length: Int, bufferId: Int, generation: Int): Boolean {
        val h = HEAD.getAcquire(this) as Long
        val t = tail
        if (t - h >= addresses.size) return false

        val i = (t and mask).toInt()
        addresses[i] = address
        lengths[i] = length
        bufferIds[i] = bufferId
        generations[i] = generation
        TAIL.setRelease(this, t + 1)
        return true
    }

    /** Takes the next item if it lies before [tailSnapshot]. */
    fun tryDequeueUntil(tailSnapshot: Long, item: RecvItem): Boolean {
        val h = head
        if (h >= tailSnapshot) return false
        take(h, item)
        return true
    }

    fun tryDequeue(item: RecvItem): Boolean {
        val h = head
        if (h >= TAIL.getAcquire(this) as Long) return false
        take(h, item)
        return true
    }

    private fun take(h: Long, item: RecvItem) {
        val i = (h and mask).toInt()
        item.set(addresses[i], lengths[i], bufferIds[i], generations[i])
        HEAD.setRelease(this, h + 1)
    }

    fun snapshotTail(): Long = TAIL.getAcquire(this) as Long

    fun isEmpty(): Boolean = (HEAD.getAcquire(this) as Long) >= (TAIL.getAcquire(this) as Long)

    /** Items between the head and [tailSnapshot]. */
    fun countUntil(tailSnapshot: Long): Int = maxOf(0L, tailSnapshot - head).toInt()

    // Reactor thread, at recycle, when no handler is consuming.
    fun reset() {
        head = 0
        tail = 0
    }

    private companion object {
        val HEAD: VarHandle = MethodHandles.lookup().findVarHandle(RecvQueue::class.java, "head", Long::class.java)
        val TAIL: VarHandle = MethodHandles.lookup().findVarHandle(RecvQueue::class.java, "tail", Long::class.java)
    }
}
