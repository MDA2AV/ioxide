package ioxide.tls

import ioxide.getByte
import ioxide.getShort
import ioxide.putByte
import ioxide.putLong
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.lang.invoke.MethodHandles
import java.lang.invoke.MethodType
import java.util.HexFormat

/**
 * The three functions BoringSSL calls back into, as upcall stubs made once per process. An exception escaping
 * one would cross BoringSSL's C frame and end the process, so each body is guarded.
 */
internal object TlsCallbacks {
    /**
     * The session whose handshake step is running on this thread. The keylog callback only fires inside
     * SSL_accept, which the handshake makes on the reactor thread with this set around it.
     */
    val handshaking = ThreadLocal<TlsSession?>()

    /** `void (*)(const SSL *, const char *line)`: the traffic secrets, for the kTLS handoff. */
    val keylog: Long

    /** `int (*)(SSL *, const uint8_t **out, uint8_t *out_len, const uint8_t *in, unsigned in_len, void *arg)`. */
    val alpnSelect: Long

    /** `int (*)(char *buf, int size, int rwflag, void *userdata)`: there is never a passphrase. */
    val noPassphrase: Long

    init {
        val linker = Linker.nativeLinker()
        val lookup = MethodHandles.lookup()
        val long = Long::class.javaPrimitiveType
        val int = Int::class.javaPrimitiveType

        keylog = linker.upcallStub(
            lookup.findStatic(TlsCallbacks::class.java, "onKeylog", MethodType.methodType(Void.TYPE, long, long)),
            FunctionDescriptor.ofVoid(JAVA_LONG, JAVA_LONG), Arena.global(),
        ).address()

        alpnSelect = linker.upcallStub(
            lookup.findStatic(
                TlsCallbacks::class.java, "onAlpnSelect",
                MethodType.methodType(int, long, long, long, long, int, long),
            ),
            FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_INT, JAVA_LONG), Arena.global(),
        ).address()

        noPassphrase = linker.upcallStub(
            lookup.findStatic(TlsCallbacks::class.java, "onPassphrase", MethodType.methodType(int, long, int, int, long)),
            FunctionDescriptor.of(JAVA_INT, JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_LONG), Arena.global(),
        ).address()
    }

    // "<SIDE>_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>"; every other line is ignored.
    @JvmStatic
    private fun onKeylog(ssl: Long, line: Long) {
        try {
            val session = handshaking.get() ?: return
            val text = BoringSsl.cString(line)
            val server = text.startsWith("SERVER_TRAFFIC_SECRET_0 ")
            if (!server && !text.startsWith("CLIENT_TRAFFIC_SECRET_0 ")) return
            val lastSpace = text.lastIndexOf(' ')
            if (lastSpace <= 0) return
            val secret = HexFormat.of().parseHex(text.substring(lastSpace + 1).trimEnd())
            if (server) session.serverSecret = secret else session.clientSecret = secret
        } catch (e: Throwable) {
            System.err.println("[tls] keylog callback faulted: $e")
        }
    }

    // Server preference: our list is walked in order and the first protocol the client also offered wins.
    // *out points into the client's buffer, which outlives the callback. arg is the wire list: u16 length, then
    // each protocol as a length byte and its ASCII name.
    @JvmStatic
    private fun onAlpnSelect(ssl: Long, out: Long, outLength: Long, offered: Long, offeredLength: Int, arg: Long): Int {
        try {
            if (arg == 0L) return BoringSsl.SSL_TLSEXT_ERR_NOACK
            val wireLength = getShort(arg).toInt() and 0xFFFF
            val wire = arg + 2

            var ours = 0
            while (ours < wireLength) {
                val wantLength = getByte(wire + ours).toInt() and 0xFF
                var theirs = 0
                while (theirs < offeredLength) {
                    val haveLength = getByte(offered + theirs).toInt() and 0xFF
                    if (theirs + 1 + haveLength > offeredLength) break   // malformed offer: stop, do not read past it
                    if (haveLength == wantLength && same(offered + theirs + 1, wire + ours + 1, haveLength)) {
                        putLong(out, offered + theirs + 1)
                        putByte(outLength, haveLength.toByte())
                        return BoringSsl.SSL_TLSEXT_ERR_OK
                    }
                    theirs += 1 + haveLength
                }
                ours += 1 + wantLength
            }
            // Nothing in common: continue without ALPN, as the client may still speak HTTP/1.1.
            return BoringSsl.SSL_TLSEXT_ERR_NOACK
        } catch (e: Throwable) {
            System.err.println("[tls] alpn callback faulted: $e")
            return BoringSsl.SSL_TLSEXT_ERR_NOACK
        }
    }

    private fun same(a: Long, b: Long, length: Int): Boolean {
        for (i in 0 until length) if (getByte(a + i) != getByte(b + i)) return false
        return true
    }

    // Zero bytes written fails an encrypted key's load with the ordinary error.
    @JvmStatic
    @Suppress("UNUSED_PARAMETER")
    private fun onPassphrase(buffer: Long, size: Int, rwflag: Int, userdata: Long): Int = 0
}
