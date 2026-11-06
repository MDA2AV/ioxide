package ioxide

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RingTest {
    // One NOP submitted and waited for: 1, or the enter's negative errno.
    private fun nop(ring: Ring, userData: Long = 1): Int {
        val sqe = ring.getSqe()
        IoUring.prep(sqe, IoUring.OP_NOP, -1, 0L, 0, 0L, userData)
        val rc = ring.submitAndWait(1)
        if (rc == 1) ring.cqAdvance(ring.cqReady())
        return rc
    }

    @Test
    fun `a NOP goes in and its completion comes back`() {
        Ring.create(16).use { ring ->
            val sqe = ring.getSqe()
            assertNotEquals(0L, sqe)
            IoUring.prep(sqe, IoUring.OP_NOP, -1, 0L, 0, 0L, userData = 0x1234_5678_9ABCL)

            assertEquals(1, ring.submitAndWait(1))
            assertEquals(1, ring.cqReady())
            val cqe = ring.cqeAt(0)
            assertEquals(0x1234_5678_9ABCL, getLong(cqe))
            assertEquals(0, getInt(cqe + 8))
            ring.cqAdvance(1)
            assertEquals(0, ring.cqReady())
        }
    }

    @Test
    fun `the SQ hands out no more SQEs than it has, until an enter consumes them`() {
        Ring.create(8).use { ring ->
            repeat(ring.sqEntries) { assertNotEquals(0L, ring.getSqe()) }
            assertEquals(0L, ring.getSqe())
        }
    }

    @Test
    fun `a timed wait with nothing in flight runs out with ETIME`() {
        Ring.create(8).use { ring ->
            assertEquals(-Native.ETIME, ring.submitAndWait(1, timeoutMs = 5))
        }
    }

    @Test
    fun `the CQ wraps past its size`() {
        Ring.create(4).use { ring ->
            repeat(ring.cqEntries * 3) { assertEquals(1, nop(ring, it.toLong())) }
        }
    }

    @Test
    fun `enters go through the registered slot, not the descriptor`() {
        Ring.create(16).use { ring ->
            assertTrue(ring.enterFd != ring.fd, "the ring should have taken a registered slot")
            assertEquals(1, nop(ring))

            // Emptied behind the ring's back: an enter by descriptor would not notice, one by slot must.
            val update = Native.malloc(IoUring.RSRC_UPDATE_SIZE)
            zeroMemory(update, IoUring.RSRC_UPDATE_SIZE)
            putInt(update, ring.enterFd)
            Native.ioUringRegister(ring.fd, IoUring.UNREGISTER_RING_FDS, update, 1)
            Native.free(update)
            assertEquals(-Native.EBADF, nop(ring))
        }
    }

    @Test
    fun `a ring created with every slot taken still works, through its descriptor`() {
        val rings = ArrayList<Ring>()
        try {
            repeat(17) { rings.add(Ring.create(16)) }
            val last = rings.last()
            assertEquals(last.fd, last.enterFd)
            assertEquals(1, nop(last))
        } finally {
            rings.forEach { it.close() }
        }
    }

    @Test
    fun `setup failures name their likely cause`() {
        assertTrue(Ring.describeSetupFailure(Native.EINVAL, 16, "5.15.0-1-generic").contains("6.1 or later"))
        assertTrue(Ring.describeSetupFailure(Native.EPERM, 16, "6.14.0").contains("io_uring_disabled"))
        assertTrue(Ring.kernelOlderThan("5.15.167.4-microsoft-standard-WSL2", 6, 1))
        assertTrue(!Ring.kernelOlderThan("6.14.0-37-generic", 6, 1))
    }
}
