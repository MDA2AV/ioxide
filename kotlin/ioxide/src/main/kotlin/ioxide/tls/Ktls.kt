package ioxide.tls

import ioxide.Native
import ioxide.Sockets
import ioxide.getByte
import ioxide.getInt
import ioxide.putByte
import ioxide.putInt
import ioxide.putLong
import ioxide.putShort
import ioxide.zeroMemory
import java.io.IOException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Kernel TLS: derive the TLS 1.3 record keys from a traffic secret (HKDF-Expand-Label) and program them into one
 * direction of the socket. After TX, the ring's ordinary sends carry plaintext and the kernel makes the records;
 * after RX, an ordinary recv returns plaintext.
 */
internal object Ktls {
    private const val SOL_TCP = 6
    private const val TCP_ULP = 31
    private const val SOL_TLS = 282
    private const val TLS_TX = 1
    private const val TLS_RX = 2
    private const val TLS_SET_RECORD_TYPE = 1
    private const val TLS_GET_RECORD_TYPE = 2
    private const val TLS_1_3_VERSION: Short = 0x0304
    private const val TLS_CIPHER_AES_GCM_128: Short = 51
    private const val TLS_RECORD_TYPE_ALERT: Byte = 21

    // tls12_crypto_info_aes_gcm_128: version(2) cipher_type(2) iv(8) key(16) salt(4) rec_seq(8).
    private const val CRYPTO_INFO_SIZE = 40

    // A msghdr (56) with one iovec (16), CMSG_SPACE(1) of control (24) and the 2-byte alert, in one block.
    private const val MSG_BLOCK = 104

    /**
     * Enables TX with keys from the TLS 1.3 server traffic secret. Runs first: it installs the TCP_ULP that RX
     * rides on. Record sequence 0, as tickets are off under kTLS and no record went out under the key before.
     */
    fun enableTx(fd: Int, serverTrafficSecret: ByteArray) =
        program(fd, TLS_TX, "TLS_TX", serverTrafficSecret, 0L, installUlp = true)

    /**
     * Enables RX with keys from the TLS 1.3 client traffic secret. [recordSequence] counts the application-data
     * records the handshake already took off the socket: the sequence is part of the AEAD nonce, so starting the
     * kernel at the wrong one fails every record.
     */
    fun enableRx(fd: Int, clientTrafficSecret: ByteArray, recordSequence: Long) =
        program(fd, TLS_RX, "TLS_RX", clientTrafficSecret, recordSequence, installUlp = false)

    private fun program(fd: Int, optname: Int, what: String, trafficSecret: ByteArray, recordSequence: Long, installUlp: Boolean) {
        val key = expandLabel(trafficSecret, "key", 16)
        val nonce = expandLabel(trafficSecret, "iv", 12)
        val info = Native.malloc(CRYPTO_INFO_SIZE.toLong())
        try {
            putShort(info, TLS_1_3_VERSION)
            putShort(info + 2, TLS_CIPHER_AES_GCM_128)
            for (i in 0 until 8) putByte(info + 4 + i, nonce[4 + i])     // iv: nonce[4..12]
            for (i in 0 until 16) putByte(info + 12 + i, key[i])
            for (i in 0 until 4) putByte(info + 28 + i, nonce[i])        // salt: nonce[0..4]
            for (i in 0 until 8) putByte(info + 32 + i, (recordSequence ushr ((7 - i) * 8)).toByte())   // big-endian

            if (installUlp) {
                val ulp = Native.malloc(3)
                try {
                    putByte(ulp, 't'.code.toByte())
                    putByte(ulp + 1, 'l'.code.toByte())
                    putByte(ulp + 2, 's'.code.toByte())
                    val rc = Native.setsockopt(fd, SOL_TCP, TCP_ULP, ulp, 3)
                    if (rc < 0) throw IOException("kTLS: TCP_ULP failed (errno ${-rc}); is the 'tls' kernel module available?")
                } finally {
                    Native.free(ulp)
                }
            }

            val rc = Native.setsockopt(fd, SOL_TLS, optname, info, CRYPTO_INFO_SIZE)
            if (rc < 0) throw IOException("kTLS: $what failed (errno ${-rc})")
        } finally {
            // The keys are in the kernel now; no copy stays behind.
            key.fill(0)
            nonce.fill(0)
            trafficSecret.fill(0)
            zeroMemory(info, CRYPTO_INFO_SIZE.toLong())
            Native.free(info)
        }
    }

    /**
     * Best-effort close_notify on a kTLS TX socket: a {warning, close_notify} alert sent with a
     * TLS_SET_RECORD_TYPE control message. The peer may already be gone.
     */
    fun sendCloseNotify(fd: Int) {
        val msg = Native.malloc(MSG_BLOCK.toLong())
        try {
            zeroMemory(msg, MSG_BLOCK.toLong())
            val iov = msg + 56
            val control = msg + 72
            val alert = msg + 96
            putByte(alert, 1)       // level: warning
            putByte(alert + 1, 0)   // description: close_notify
            putLong(control, 17)    // cmsg_len: CMSG_LEN(1)
            putInt(control + 8, SOL_TLS)
            putInt(control + 12, TLS_SET_RECORD_TYPE)
            putByte(control + 16, TLS_RECORD_TYPE_ALERT)
            putLong(iov, alert)
            putLong(iov + 8, 2)
            putLong(msg + 16, iov)
            putLong(msg + 24, 1)
            putLong(msg + 32, control)
            putLong(msg + 40, 24)
            Native.sendmsg(fd, msg, Sockets.MSG_NOSIGNAL or Sockets.MSG_DONTWAIT)
        } finally {
            Native.free(msg)
        }
    }

    /**
     * Whether the record a kTLS RX socket holds next is the peer's close_notify. A plain recv stops at a
     * non-data record with EIO and leaves it queued; this peeks it with the control message carrying its type.
     */
    fun peekCloseNotify(fd: Int): Boolean {
        val msg = Native.malloc(MSG_BLOCK.toLong())
        try {
            zeroMemory(msg, MSG_BLOCK.toLong())
            val iov = msg + 56
            val control = msg + 72
            val alert = msg + 96
            putLong(iov, alert)
            putLong(iov + 8, 2)
            putLong(msg + 16, iov)
            putLong(msg + 24, 1)
            putLong(msg + 32, control)
            putLong(msg + 40, 24)
            if (Native.recvmsg(fd, msg, Sockets.MSG_PEEK or Sockets.MSG_DONTWAIT) != 2L) return false
            return getInt(control + 8) == SOL_TLS &&
                getInt(control + 12) == TLS_GET_RECORD_TYPE &&
                getByte(control + 16) == TLS_RECORD_TYPE_ALERT &&
                getByte(alert + 1).toInt() == 0
        } finally {
            Native.free(msg)
        }
    }

    // RFC 8446 HKDF-Expand-Label with an empty context. Every length asked for fits one SHA-256 block, T(1).
    private fun expandLabel(secret: ByteArray, label: String, length: Int): ByteArray {
        val full = "tls13 $label".toByteArray(Charsets.US_ASCII)
        val info = ByteArray(2 + 1 + full.size + 1 + 1)
        info[0] = (length ushr 8).toByte()
        info[1] = length.toByte()
        info[2] = full.size.toByte()
        full.copyInto(info, 3)
        info[3 + full.size] = 0          // empty context
        info[info.size - 1] = 1          // HKDF-Expand's block counter
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        val block = mac.doFinal(info)
        return block.copyOf(length).also { block.fill(0) }
    }
}
