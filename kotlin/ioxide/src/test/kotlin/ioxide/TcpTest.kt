package ioxide

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicIntegerArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TcpTest {
    // Connection A is recycled with its multishot recv still armed: its send fails after its own FIN, which wakes
    // nothing on the read side, so the recv's cancel is only queued when its fd is closed. The reactor is held
    // until B has connected, so the next enter accepts B onto that fd ahead of A's -ECANCELED. Returns what B got
    // back for its "BBBB", and the fds A and B were accepted on.
    private fun nextConnectionOnTheSameFd(poolMax: Int): Triple<String, Int, Int> {
        val aStalled = CountDownLatch(1)
        val bConnected = CountDownLatch(1)
        val fds = AtomicIntegerArray(intArrayOf(-1, -1))
        val ready = CountDownLatch(1)
        val config = ServerConfig(reactorCount = 1, tcp = TcpOptions(port = 0, poolMax = poolMax))
        val server = IoxideServer(config, onStart = { ready.countDown() }) handler@{ conn ->
            val isB = aStalled.count == 0L
            if (isB) fds.set(1, conn.clientFd)

            val item = RecvItem()
            val first = conn.read()
            val head = StringBuilder()
            while (conn.tryGetItem(first, item)) {
                if (item.hasBuffer) for (i in 0 until item.length) head.append(item[i].toInt().toChar())
                conn.returnBuffer(item)
            }

            if (!isB && head.startsWith("AAAA")) {
                fds.set(0, conn.clientFd)
                conn.shutdownWrite()
                conn.write(ByteArray(16))
                conn.flush()   // EPIPE: the reactor tears A down, its recv still armed

                // Resumed inline by the failed send, so this holds the reactor thread on purpose.
                aStalled.countDown()
                bConnected.await(5, TimeUnit.SECONDS)
                Thread.sleep(50)   // B's handshake reaches the listener
                return@handler
            }

            conn.write(head.toString().toByteArray())
            conn.flush()
        }.start()
        try {
            assertTrue(ready.await(10, TimeUnit.SECONDS), "the reactor never started")
            val port = server.reactors[0].listenPorts[0]
            Socket().use { a ->
                a.connect(InetSocketAddress("127.0.0.1", port))
                a.getOutputStream().write("AAAA".toByteArray())
                assertTrue(aStalled.await(5, TimeUnit.SECONDS), "A's failed flush never returned")
                Socket().use { b ->
                    try {
                        b.soTimeout = 5_000
                        b.connect(InetSocketAddress("127.0.0.1", port))
                    } finally {
                        bConnected.countDown()
                    }
                    b.getOutputStream().write("BBBB".toByteArray())
                    val got = StringBuilder()
                    try {
                        while (got.length < 4) {
                            val c = b.getInputStream().read()
                            if (c < 0) {
                                got.append("<EOF>")
                                break
                            }
                            got.append(c.toChar())
                        }
                    } catch (e: IOException) {
                        got.append("<${e.message}>")
                    }
                    return Triple(got.toString(), fds.get(0), fds.get(1))
                }
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun `a recycled connection's stale recv completion does not close the next connection on its fd (#416)`() {
        // poolMax 0: every connection is a new object, so both lives start from the same generation.
        val (got, a, b) = nextConnectionOnTheSameFd(poolMax = 0)
        assertEquals(a, b, "precondition: B was accepted on $b, not on A's $a")
        assertEquals("BBBB", got, "B, accepted on the fd A gave back, was closed before it was served")
    }

    @Test
    fun `control - the same stale completion misses a connection taken from the pool`() {
        // B reuses A's object, whose generation its recycle moved.
        val (got, a, b) = nextConnectionOnTheSameFd(poolMax = 1024)
        assertEquals(a, b, "precondition: B was accepted on $b, not on A's $a")
        assertEquals("BBBB", got, "B was closed before it was served")
    }
}
