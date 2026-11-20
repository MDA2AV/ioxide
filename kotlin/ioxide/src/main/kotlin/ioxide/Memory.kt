package ioxide

import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.lang.invoke.VarHandle

/**
 * Native memory by address. One segment spans the whole address space, so a `Long` works as a pointer the
 * way `byte*` does in the C# core: the kernel-shared rings, provided buffers and write slabs are all read
 * and written through it. Its scope is global (no liveness check), and the unaligned layouts skip the
 * alignment check, leaving a bounds check against Long.MAX_VALUE.
 */
@JvmField
internal val MEM: MemorySegment = MemorySegment.NULL.reinterpret(Long.MAX_VALUE)

private val I8: ValueLayout.OfByte = ValueLayout.JAVA_BYTE
private val I16: ValueLayout.OfShort = ValueLayout.JAVA_SHORT_UNALIGNED
private val I32: ValueLayout.OfInt = ValueLayout.JAVA_INT_UNALIGNED
private val I64: ValueLayout.OfLong = ValueLayout.JAVA_LONG_UNALIGNED

internal fun getByte(addr: Long): Byte = MEM.get(I8, addr)
internal fun putByte(addr: Long, v: Byte) = MEM.set(I8, addr, v)
internal fun getShort(addr: Long): Short = MEM.get(I16, addr)
internal fun putShort(addr: Long, v: Short) = MEM.set(I16, addr, v)
internal fun getInt(addr: Long): Int = MEM.get(I32, addr)
internal fun putInt(addr: Long, v: Int) = MEM.set(I32, addr, v)
internal fun getLong(addr: Long): Long = MEM.get(I64, addr)
internal fun putLong(addr: Long, v: Long) = MEM.set(I64, addr, v)

// The kernel's side of each ring index is smp_load_acquire / smp_store_release, so ours pairs with it:
// a plain access fenced the same way. On x86 both fences only stop the compiler from reordering.
internal fun getIntAcquire(addr: Long): Int {
    val v = MEM.get(I32, addr)
    VarHandle.acquireFence()
    return v
}

internal fun putIntRelease(addr: Long, v: Int) {
    VarHandle.releaseFence()
    MEM.set(I32, addr, v)
}

internal fun putShortRelease(addr: Long, v: Short) {
    VarHandle.releaseFence()
    MEM.set(I16, addr, v)
}

/** Copies [length] bytes between native addresses. */
internal fun copyMemory(src: Long, dst: Long, length: Long) = MemorySegment.copy(MEM, src, MEM, dst, length)

/** Copies from a heap array into native memory. */
internal fun copyFromArray(src: ByteArray, srcOffset: Int, dst: Long, length: Int) =
    MemorySegment.copy(src, srcOffset, MEM, I8, dst, length)

/** Copies from native memory into a heap array. */
internal fun copyToArray(src: Long, dst: ByteArray, dstOffset: Int, length: Int) =
    MemorySegment.copy(MEM, I8, src, dst, dstOffset, length)

internal fun zeroMemory(addr: Long, length: Long) {
    MEM.asSlice(addr, length).fill(0)
}

/**
 * Native memory by address, for the raw seam: what [RecvItem.address], [ReadBuffer.segmentAddress] and
 * [TcpConnection.getBuffer] point into. Nothing is checked beyond the address being in the address space, so
 * stay inside what the item, segment or buffer covers - [RecvItem.segment] and [TcpConnection.getSegment] are
 * the bounds-checked alternative.
 */
object Memory {
    fun getByte(address: Long): Byte = ioxide.getByte(address)
    fun putByte(address: Long, value: Byte) = ioxide.putByte(address, value)
    fun getShort(address: Long): Short = ioxide.getShort(address)
    fun putShort(address: Long, value: Short) = ioxide.putShort(address, value)
    fun getInt(address: Long): Int = ioxide.getInt(address)
    fun putInt(address: Long, value: Int) = ioxide.putInt(address, value)
    fun getLong(address: Long): Long = ioxide.getLong(address)
    fun putLong(address: Long, value: Long) = ioxide.putLong(address, value)

    /** Copies [length] bytes of [source] from [sourceOffset] to [destination]. */
    fun copy(source: ByteArray, sourceOffset: Int, destination: Long, length: Int) =
        copyFromArray(source, sourceOffset, destination, length)

    /** Copies [length] bytes from [source] into [destination] at [destinationOffset]. */
    fun copy(source: Long, destination: ByteArray, destinationOffset: Int, length: Int) =
        copyToArray(source, destination, destinationOffset, length)

    /** Copies [length] bytes between native addresses. */
    fun copy(source: Long, destination: Long, length: Long) = copyMemory(source, destination, length)
}
