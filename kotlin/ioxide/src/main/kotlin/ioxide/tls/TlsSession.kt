package ioxide.tls

import ioxide.Native
import ioxide.Sockets
import ioxide.TcpConnection
import ioxide.copyMemory
import ioxide.getByte
import ioxide.getLong
import java.io.IOException

/**
 * One connection's TLS once the handshake is done: BoringSSL decrypts inbound records and encrypts outbound ones,
 * except for whichever direction was handed to the kernel ([TlsOptions.kernelTx], [TlsOptions.kernelRx]). One
 * session per connection, reactor thread only; [close] it when the connection's handler is done with it.
 */
class TlsSession internal constructor(
    private val ssl: Long,
    private val rbio: Long,
    private val wbio: Long,
) : AutoCloseable {
    // Decryption never expands, so a decrypt is bounded by the ciphertext fed; the cap guards a pathological
    // stream, not the everyday size.
    private var plain = Native.malloc(INITIAL_PLAINTEXT.toLong())
    private var plainCapacity = INITIAL_PLAINTEXT
    private var plainLength = 0
    private var disposed = false

    private var conn: TcpConnection? = null
    private var fd = -1
    private var lifeGeneration = 0
    private var txEnabled = false

    /** The TLS 1.3 traffic secrets, captured by the keylog callback for the kTLS handoff only. */
    internal var serverSecret: ByteArray? = null
    internal var clientSecret: ByteArray? = null

    /** Where the last [decrypt] or [drainPlaintext] left its plaintext, valid until the next one. */
    var plaintext: Long = plain
        private set

    /** True once the kernel decrypts inbound records: reads arrive as plaintext and [decrypt] hands them back. */
    var kernelRx: Boolean = false
        private set

    /** True when the kernel encrypts outbound records. [write] is right either way; this only reports the path. */
    val kernelTx: Boolean get() = txEnabled

    private var closeNotified = false
    private var alertPeeked = false

    /**
     * True once the peer sent close_notify. Under kTLS RX the kernel holds the peer's alerts and a recv stops at
     * one with EIO, ending the read side; asked after that, this reads it, once.
     */
    val closed: Boolean get() = closeNotified || (kernelRx && peekKernelCloseNotify())

    private fun peekKernelCloseNotify(): Boolean {
        val c = conn
        if (alertPeeked || c == null || !c.isClosed || c.generation != lifeGeneration) return false
        alertPeeked = true
        closeNotified = Ktls.peekCloseNotify(fd)
        return closeNotified
    }

    /** The protocol ALPN settled on, or null when the client offered none this port serves. */
    var negotiatedAlpn: String? = null
        private set

    /** BoringSSL's wire value for the version settled on: 0x0303 is TLS 1.2, 0x0304 TLS 1.3. */
    val negotiatedProtocolVersion: Int get() = BoringSsl.version(ssl)

    /** The IANA id of the ciphersuite settled on, 0 before the handshake completes. */
    val negotiatedCipherSuiteId: Int get() = BoringSsl.currentCipherId(ssl)

    internal fun captureAlpn() {
        negotiatedAlpn = BoringSsl.alpnSelected(ssl)
    }

    internal fun attachConnection(connection: TcpConnection) {
        conn = connection
        fd = connection.clientFd
        lifeGeneration = connection.generation
    }

    internal fun markTxEnabled() {
        txEnabled = true
    }

    internal fun markKernelRx() {
        kernelRx = true
    }

    /**
     * Feeds [length] bytes of ciphertext at [ciphertext] and decrypts what completes, returning the plaintext's
     * length; the bytes are at [plaintext] until the next call. 0 is normal, a partial record - check [closed].
     * Under kTLS RX the bytes already are plaintext, and are handed back where they lie.
     */
    fun decrypt(ciphertext: Long, length: Int): Int {
        if (kernelRx) {
            plaintext = ciphertext
            return length
        }
        plainLength = 0
        BoringSsl.bioWrite(rbio, ciphertext, length)
        drainPending()
        plaintext = plain
        return plainLength
    }

    /** What the handshake's final flight carried in ahead of the first read, at [plaintext]. */
    fun drainPlaintext(): Int {
        plaintext = plain
        return plainLength
    }

    // Everything the read BIO holds that decrypts, appended at plainLength.
    internal fun drainPending() {
        while (true) {
            if (plainCapacity - plainLength < 4 * 1024) growPlaintext()
            val n = BoringSsl.read(ssl, plain + plainLength, plainCapacity - plainLength)
            if (n > 0) {
                plainLength += n
                continue
            }
            when (-n) {
                BoringSsl.SSL_ERROR_WANT_READ, BoringSsl.SSL_ERROR_WANT_WRITE -> return   // the record is not all here
                BoringSsl.SSL_ERROR_ZERO_RETURN -> {
                    closeNotified = true
                    return
                }
                // A bad MAC or a malformed record is not "more bytes needed": waiting on it would wait forever.
                else -> throw IOException("TLS decrypt failed (error ${-n}): ${BoringSsl.lastError()}")
            }
        }
    }

    private fun growPlaintext() {
        if (plainCapacity >= MAX_PLAINTEXT) throw IOException("TLS plaintext exceeds $MAX_PLAINTEXT bytes in one decrypt")
        val capacity = minOf(plainCapacity * 2, MAX_PLAINTEXT)
        val grown = Native.malloc(capacity.toLong())
        copyMemory(plain, grown, plainLength.toLong())
        Native.free(plain)
        plain = grown
        plainCapacity = capacity
    }

    /**
     * Stages plaintext into [connection]'s write slab, right for whichever backend this session has: under kTLS
     * TX it goes in as it is and the kernel makes the records; otherwise BoringSSL encrypts and the records go
     * in. A plain [TcpConnection.write] on a BoringSSL session would put cleartext on the wire.
     */
    fun write(connection: TcpConnection, source: ByteArray, offset: Int = 0, length: Int = source.size - offset) {
        if (length == 0) return   // zero-length is an error to SSL_write, not a no-op
        if (txEnabled) {
            connection.write(source, offset, length)
            return
        }
        checkReactorThread(connection)
        if (BoringSsl.write(ssl, source, offset, length) <= 0) throw IOException("TLS encrypt failed: ${BoringSsl.lastError()}")
        stageRecords(connection)
    }

    /** As the other [write], from [length] native bytes at [source]. */
    fun write(connection: TcpConnection, source: Long, length: Int) {
        if (length == 0) return
        if (txEnabled) {
            copyMemory(source, connection.getBuffer(length), length.toLong())
            connection.advance(length)
            return
        }
        checkReactorThread(connection)
        if (BoringSsl.write(ssl, source, length) <= 0) throw IOException("TLS encrypt failed: ${BoringSsl.lastError()}")
        stageRecords(connection)
    }

    // A BoringSSL session is not thread-safe, and the reactor decrypts with this one.
    private fun checkReactorThread(connection: TcpConnection) {
        check(connection.reactor.onReactorThread) {
            "TlsSession.write encrypts with BoringSSL, which the reactor uses for this session: call it on the reactor thread."
        }
    }

    // The records SSL_write left in the write BIO, moved into the slab: the second pass over the bytes that kTLS
    // TX avoids.
    private fun stageRecords(connection: TcpConnection) {
        while (true) {
            val pending = BoringSsl.bioPending(wbio).toInt()
            if (pending <= 0) return
            val n = BoringSsl.bioRead(wbio, connection.getBuffer(pending), pending)
            if (n <= 0) return
            connection.advance(n)
        }
    }

    // How many complete records the read BIO holds, and in pendingMissing how many bytes the record after them
    // still lacks (0 when nothing is left over). Read in place through BIO_CTRL_INFO, not consumed: the kTLS RX
    // handoff starts the kernel's sequence after these, and cannot start it inside a record.
    internal var pendingMissing = 0

    internal fun countPendingRecords(): Int {
        pendingMissing = 0
        val out = Native.malloc(8)
        try {
            val available = BoringSsl.bioCtrl(rbio, BoringSsl.BIO_CTRL_INFO, 0, out)
            val buffer = getLong(out)
            if (available <= 0 || buffer == 0L) return 0

            var records = 0
            var offset = 0L
            while (offset + 5 <= available) {
                // TLSCiphertext: type(1) legacy_version(2) length(2), then length encrypted bytes.
                val length = ((getByte(buffer + offset + 3).toInt() and 0xFF) shl 8) or (getByte(buffer + offset + 4).toInt() and 0xFF)
                if (offset + 5 + length > available) {
                    pendingMissing = (offset + 5 + length - available).toInt()
                    return records
                }
                records++
                offset += 5 + length
            }
            pendingMissing = if (offset < available) (offset + 5 - available).toInt() else 0   // the header is cut
            return records
        } finally {
            Native.free(out)
        }
    }

    internal fun zeroSecrets() {
        serverSecret?.fill(0)
        serverSecret = null
        clientSecret?.fill(0)
        clientSecret = null
    }

    /**
     * Sends close_notify where it can go out cleanly - not into a send the ring still holds, nor past the FIN -
     * and frees the session. Also after the peer closed first, as RFC 8446 6.1 asks of both sides.
     */
    override fun close() {
        if (disposed) return
        disposed = true

        val c = conn
        if (fd >= 0 && (c == null || (c.generation == lifeGeneration && !c.flushOutstanding && !c.finWasSent))) {
            if (txEnabled) Ktls.sendCloseNotify(fd) else sendCloseNotifyBoringSsl()
        }

        zeroSecrets()
        BoringSsl.sslFree(ssl)   // frees both BIOs
        Native.free(plain)
        plain = 0L
        plaintext = 0L
    }

    // SSL_shutdown makes the record into the write BIO and a plain send puts it on the wire. MSG_DONTWAIT,
    // because accepted sockets are blocking and a peer that stopped reading must not park the reactor here.
    private fun sendCloseNotifyBoringSsl() {
        // A handshake that never completed has no session to end; SSL_shutdown would only queue an error.
        if (BoringSsl.inInit(ssl)) return
        if (BoringSsl.shutdown(ssl) < 0) {
            BoringSsl.clearError()
            return
        }

        // Drained rather than sized: a TLS 1.2 CBC close_notify is 69 or 85 bytes, not the 1.3 record's 24.
        val record = Native.malloc(512)
        try {
            while (true) {
                val n = BoringSsl.bioRead(wbio, record, 512)
                if (n <= 0) break
                if (Native.send(fd, record, n.toLong(), Sockets.MSG_NOSIGNAL or Sockets.MSG_DONTWAIT) != n.toLong()) break
            }
        } finally {
            Native.free(record)
        }
    }

    private companion object {
        const val INITIAL_PLAINTEXT = 16 * 1024
        const val MAX_PLAINTEXT = 8 * 1024 * 1024
    }
}
