package ioxide

/**
 * A provided-buffer ring (IORING_REGISTER_PBUF_RING): [entries] buffers of [bufferSize] bytes in one slab,
 * offered to the kernel under buffer group [bgid]. A recv with IOSQE_BUFFER_SELECT picks the next one and
 * names it in its CQE (`flags >> 16`); the buffer is ours until [add] offers it again.
 *
 * Offers are staged locally and made visible with one release store of the tail in [publish], so a batch
 * of returns costs one store, not one per buffer.
 */
internal class BufferRing(
    private val ring: Ring,
    val bgid: Int,
    val entries: Int,
    val bufferSize: Int,
    incremental: Boolean = false,
) : AutoCloseable {
    init {
        require(entries > 0 && entries and (entries - 1) == 0 && entries <= 32768) {
            "buffer ring entries must be a power of two up to 32768, not $entries"
        }
    }

    private val mask = entries - 1

    /** The ring the kernel reads offers from: page aligned, as registration requires. */
    private val ringAddr: Long = Native.alignedAlloc(PAGE, entries.toLong() * IoUring.BUF_SIZE)

    /** Buffer `bid` lives at `slab + bid * bufferSize`. */
    val slab: Long = Native.alignedAlloc(PAGE, entries.toLong() * bufferSize)

    private var tail = 0
    private var registered = false

    init {
        zeroMemory(ringAddr, entries.toLong() * IoUring.BUF_SIZE)

        val reg = Native.malloc(IoUring.BUF_REG_SIZE)
        try {
            zeroMemory(reg, IoUring.BUF_REG_SIZE)
            putLong(reg, ringAddr)
            putInt(reg + 8, entries)
            putShort(reg + 12, bgid.toShort())
            putShort(reg + 14, (if (incremental) IoUring.IOU_PBUF_RING_INC else 0).toShort())
            val rc = Native.ioUringRegister(ring.fd, IoUring.REGISTER_PBUF_RING, reg, 1)
            if (rc < 0) {
                Native.free(ringAddr)
                Native.free(slab)
                throw IllegalStateException("IORING_REGISTER_PBUF_RING failed with errno ${-rc} (bgid $bgid, $entries entries)")
            }
            registered = true
        } finally {
            Native.free(reg)
        }

        for (bid in 0 until entries) add(bid)
        publish()
    }

    fun bufferAddr(bid: Int): Long = slab + bid.toLong() * bufferSize

    /** Stages buffer [bid] for the kernel; visible after the next [publish]. */
    fun add(bid: Int) {
        val e = ringAddr + (tail and mask).toLong() * IoUring.BUF_SIZE
        putLong(e, bufferAddr(bid))
        putInt(e + 8, bufferSize)
        // bid only: the u16 after it in bufs[0] is the ring's tail.
        putShort(e + 12, bid.toShort())
        tail++
    }

    /** Makes every staged buffer visible to the kernel. */
    fun publish() = putShortRelease(ringAddr + IoUring.BUF_RING_TAIL, tail.toShort())

    /**
     * Unregisters the group; it must run before the memory goes, and before the ring's descriptor is closed:
     * unregistering is synchronous, closing is not (io_uring_release defers to a workqueue).
     */
    fun unregister() {
        if (!registered) return
        registered = false
        val reg = Native.malloc(IoUring.BUF_REG_SIZE)
        zeroMemory(reg, IoUring.BUF_REG_SIZE)
        putShort(reg + 12, bgid.toShort())
        Native.ioUringRegister(ring.fd, IoUring.UNREGISTER_PBUF_RING, reg, 1)
        Native.free(reg)
    }

    /** Frees the memory; [unregister] first, while the ring is still open. */
    override fun close() {
        unregister()
        Native.free(ringAddr)
        Native.free(slab)
    }

    private companion object {
        const val PAGE = 4096L
    }
}
