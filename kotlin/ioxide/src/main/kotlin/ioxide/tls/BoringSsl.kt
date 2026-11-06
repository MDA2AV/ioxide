package ioxide.tls

import ioxide.MEM
import ioxide.Native
import ioxide.getByte
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.lang.foreign.ValueLayout.JAVA_SHORT
import java.lang.invoke.MethodHandle
import java.nio.file.Path

/**
 * The BoringSSL surface TLS needs, through FFM: libssl and libcrypto in one object, libioxide_boringssl.so - the
 * library the C# ioxide package ships, built by scripts/build-boringssl-native.sh. It is found through the
 * `ioxide.boringssl` system property or the IOXIDE_BORINGSSL variable, each a path, and otherwise by name on the
 * loader's search path. Loaded on first use, so a server without TLS never maps it. Pointers are `Long`
 * addresses, as everywhere in this port.
 */
internal object BoringSsl {
    const val SSL_FILETYPE_PEM = 1
    const val SSL_ERROR_WANT_READ = 2
    const val SSL_ERROR_WANT_WRITE = 3
    const val SSL_ERROR_ZERO_RETURN = 6
    const val TLS1_2_VERSION: Short = 0x0303
    const val TLS1_3_VERSION: Short = 0x0304

    /** The RFC 8446 id of the one suite kTLS is programmed for. */
    const val TLS_AES_128_GCM_SHA256: Short = 0x1301
    const val SSL_TLSEXT_ERR_OK = 0
    const val SSL_TLSEXT_ERR_NOACK = 3
    const val SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000

    /** On a memory BIO: a pointer to its buffer, without consuming it. */
    const val BIO_CTRL_INFO = 3

    private const val ERR_LIB_PEM = 9
    private const val PEM_R_NO_START_LINE = 110
    private const val ERR_LIB_X509 = 11
    private const val X509_R_KEY_TYPE_MISMATCH = 115
    private const val X509_R_KEY_VALUES_MISMATCH = 116

    private val linker = Linker.nativeLinker()

    private val library: SymbolLookup = run {
        val path = System.getProperty("ioxide.boringssl") ?: System.getenv("IOXIDE_BORINGSSL")
        try {
            if (path != null) SymbolLookup.libraryLookup(Path.of(path), Arena.global())
            else SymbolLookup.libraryLookup("libioxide_boringssl.so", Arena.global())
        } catch (e: IllegalArgumentException) {
            throw UnsatisfiedLinkError(
                "libioxide_boringssl.so not loaded (${path ?: "searched by name"}): point -Dioxide.boringssl or " +
                    "IOXIDE_BORINGSSL at it - ${e.message}",
            )
        }
    }

    private fun bind(name: String, descriptor: FunctionDescriptor, vararg options: Linker.Option): MethodHandle =
        linker.downcallHandle(
            library.find(name).orElseThrow { UnsatisfiedLinkError("$name is not in libioxide_boringssl.so") },
            descriptor, *options,
        )

    private val L = JAVA_LONG
    private val I = JAVA_INT
    private val S = JAVA_SHORT

    // Calls that only touch memory BoringSSL owns and never call back skip the native-state transition.
    private val leaf = Linker.Option.critical(false)

    private val TLS_SERVER_METHOD = bind("TLS_server_method", FunctionDescriptor.of(L))
    private val SSL_CTX_NEW = bind("SSL_CTX_new", FunctionDescriptor.of(L, L))
    private val SSL_CTX_FREE = bind("SSL_CTX_free", FunctionDescriptor.ofVoid(L))
    private val SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = bind("SSL_CTX_use_certificate_chain_file", FunctionDescriptor.of(I, L, L))
    private val SSL_CTX_USE_PRIVATEKEY_FILE = bind("SSL_CTX_use_PrivateKey_file", FunctionDescriptor.of(I, L, L, I))
    private val SSL_CTX_CHECK_PRIVATE_KEY = bind("SSL_CTX_check_private_key", FunctionDescriptor.of(I, L))
    private val SSL_CTX_USE_CERTIFICATE = bind("SSL_CTX_use_certificate", FunctionDescriptor.of(I, L, L))
    private val SSL_CTX_USE_PRIVATEKEY = bind("SSL_CTX_use_PrivateKey", FunctionDescriptor.of(I, L, L))
    private val SSL_CTX_ADD_EXTRA_CHAIN_CERT = bind("SSL_CTX_add_extra_chain_cert", FunctionDescriptor.of(I, L, L))
    private val SSL_CTX_SET_MIN_PROTO_VERSION = bind("SSL_CTX_set_min_proto_version", FunctionDescriptor.of(I, L, S))
    private val SSL_CTX_SET_MAX_PROTO_VERSION = bind("SSL_CTX_set_max_proto_version", FunctionDescriptor.of(I, L, S))
    private val SSL_CTX_SET1_TLS13_CIPHERS = bind("SSL_CTX_set1_tls13_ciphers", FunctionDescriptor.of(I, L, L, L, L))
    private val SSL_GET_CIPHER_BY_VALUE = bind("SSL_get_cipher_by_value", FunctionDescriptor.of(L, S))
    private val SSL_CIPHER_STANDARD_NAME = bind("SSL_CIPHER_standard_name", FunctionDescriptor.of(L, L))
    private val SSL_CTX_SET_CIPHER_LIST = bind("SSL_CTX_set_cipher_list", FunctionDescriptor.of(I, L, L))
    private val SSL_CTX_SET_NUM_TICKETS = bind("SSL_CTX_set_num_tickets", FunctionDescriptor.of(I, L, L))
    private val SSL_CTX_SET_OPTIONS = bind("SSL_CTX_set_options", FunctionDescriptor.of(I, L, I))
    private val SSL_CTX_SET_KEYLOG_CALLBACK = bind("SSL_CTX_set_keylog_callback", FunctionDescriptor.ofVoid(L, L))
    private val SSL_CTX_SET_ALPN_SELECT_CB = bind("SSL_CTX_set_alpn_select_cb", FunctionDescriptor.ofVoid(L, L, L))
    private val SSL_CTX_SET_DEFAULT_PASSWD_CB = bind("SSL_CTX_set_default_passwd_cb", FunctionDescriptor.ofVoid(L, L))
    private val SSL_CTX_SET_SESSION_ID_CONTEXT = bind("SSL_CTX_set_session_id_context", FunctionDescriptor.of(I, L, L, L))

    private val SSL_NEW = bind("SSL_new", FunctionDescriptor.of(L, L))
    private val SSL_FREE = bind("SSL_free", FunctionDescriptor.ofVoid(L))
    private val SSL_SET_ACCEPT_STATE = bind("SSL_set_accept_state", FunctionDescriptor.ofVoid(L))
    private val SSL_SET_BIO = bind("SSL_set_bio", FunctionDescriptor.ofVoid(L, L, L))
    private val SSL_ACCEPT = bind("SSL_accept", FunctionDescriptor.of(I, L))   // calls back: keylog, ALPN
    private val SSL_READ = bind("SSL_read", FunctionDescriptor.of(I, L, L, I))
    private val SSL_WRITE = bind("SSL_write", FunctionDescriptor.of(I, L, L, I))
    private val SSL_WRITE_HEAP = bind("SSL_write", FunctionDescriptor.of(I, L, ADDRESS, I), Linker.Option.critical(true))
    private val SSL_SHUTDOWN = bind("SSL_shutdown", FunctionDescriptor.of(I, L))
    private val SSL_IN_INIT = bind("SSL_in_init", FunctionDescriptor.of(I, L))
    private val SSL_GET_ERROR = bind("SSL_get_error", FunctionDescriptor.of(I, L, I), leaf)
    private val SSL_GET0_ALPN_SELECTED = bind("SSL_get0_alpn_selected", FunctionDescriptor.ofVoid(L, L, L))
    private val SSL_VERSION = bind("SSL_version", FunctionDescriptor.of(I, L))
    private val SSL_GET_CURRENT_CIPHER = bind("SSL_get_current_cipher", FunctionDescriptor.of(L, L))
    private val SSL_CIPHER_GET_PROTOCOL_ID = bind("SSL_CIPHER_get_protocol_id", FunctionDescriptor.of(S, L))

    private val BIO_NEW = bind("BIO_new", FunctionDescriptor.of(L, L))
    private val BIO_S_MEM = bind("BIO_s_mem", FunctionDescriptor.of(L))
    private val BIO_NEW_MEM_BUF = bind("BIO_new_mem_buf", FunctionDescriptor.of(L, L, L))
    private val BIO_FREE = bind("BIO_free", FunctionDescriptor.of(I, L))
    private val BIO_WRITE = bind("BIO_write", FunctionDescriptor.of(I, L, L, I), leaf)
    private val BIO_READ = bind("BIO_read", FunctionDescriptor.of(I, L, L, I), leaf)
    private val BIO_CTRL_PENDING = bind("BIO_ctrl_pending", FunctionDescriptor.of(L, L), leaf)
    private val BIO_CTRL = bind("BIO_ctrl", FunctionDescriptor.of(L, L, I, L, L))

    private val PEM_READ_BIO_X509 = bind("PEM_read_bio_X509", FunctionDescriptor.of(L, L, L, L, L))
    private val PEM_READ_BIO_PRIVATEKEY = bind("PEM_read_bio_PrivateKey", FunctionDescriptor.of(L, L, L, L, L))
    private val X509_FREE = bind("X509_free", FunctionDescriptor.ofVoid(L))
    private val EVP_PKEY_FREE = bind("EVP_PKEY_free", FunctionDescriptor.ofVoid(L))

    private val ERR_CLEAR_ERROR = bind("ERR_clear_error", FunctionDescriptor.ofVoid(), leaf)
    private val ERR_GET_ERROR = bind("ERR_get_error", FunctionDescriptor.of(I))
    private val ERR_PEEK_ERROR = bind("ERR_peek_error", FunctionDescriptor.of(I))
    private val ERR_ERROR_STRING_N = bind("ERR_error_string_n", FunctionDescriptor.ofVoid(I, L, L))

    fun serverMethod(): Long = TLS_SERVER_METHOD.invokeExact() as Long
    fun ctxNew(method: Long): Long = SSL_CTX_NEW.invokeExact(method) as Long
    fun ctxFree(ctx: Long) {
        SSL_CTX_FREE.invokeExact(ctx)
    }
    fun useCertificateChainFile(ctx: Long, path: String): Int = withCString(path) { SSL_CTX_USE_CERTIFICATE_CHAIN_FILE.invokeExact(ctx, it) as Int }
    fun usePrivateKeyFile(ctx: Long, path: String): Int = withCString(path) { SSL_CTX_USE_PRIVATEKEY_FILE.invokeExact(ctx, it, SSL_FILETYPE_PEM) as Int }
    fun checkPrivateKey(ctx: Long): Int = SSL_CTX_CHECK_PRIVATE_KEY.invokeExact(ctx) as Int
    fun useCertificate(ctx: Long, x509: Long): Int = SSL_CTX_USE_CERTIFICATE.invokeExact(ctx, x509) as Int
    fun usePrivateKey(ctx: Long, pkey: Long): Int = SSL_CTX_USE_PRIVATEKEY.invokeExact(ctx, pkey) as Int

    /** Takes ownership of [x509] on success. */
    fun addExtraChainCert(ctx: Long, x509: Long): Int = SSL_CTX_ADD_EXTRA_CHAIN_CERT.invokeExact(ctx, x509) as Int
    fun setMinProtoVersion(ctx: Long, version: Short): Int = SSL_CTX_SET_MIN_PROTO_VERSION.invokeExact(ctx, version) as Int
    fun setMaxProtoVersion(ctx: Long, version: Short): Int = SSL_CTX_SET_MAX_PROTO_VERSION.invokeExact(ctx, version) as Int

    /** TLS 1.3 suites by protocol id, in server preference order; an empty list means BoringSSL's own order. */
    fun setTls13Ciphers(ctx: Long, ids: ShortArray): Int = Arena.ofConfined().use { arena ->
        val p = arena.allocate(2L * ids.size.coerceAtLeast(1))
        for (i in ids.indices) p.setAtIndex(S, i.toLong(), ids[i])
        SSL_CTX_SET1_TLS13_CIPHERS.invokeExact(ctx, p.address(), 0L, ids.size.toLong()) as Int
    }

    /**
     * The id of the TLS 1.3 suite called [name] (its RFC 8446 name), or null when this BoringSSL does not
     * implement it - asked of the library, which knows the ids 0x1301-0x1305 it offers.
     */
    fun tls13SuiteId(name: String): Short? {
        for (id in 0x1301..0x1305) {
            val cipher = SSL_GET_CIPHER_BY_VALUE.invokeExact(id.toShort()) as Long
            if (cipher != 0L && cString(SSL_CIPHER_STANDARD_NAME.invokeExact(cipher) as Long) == name) return id.toShort()
        }
        return null
    }

    fun setCipherList(ctx: Long, list: String): Int = withCString(list) { SSL_CTX_SET_CIPHER_LIST.invokeExact(ctx, it) as Int }
    fun setNumTickets(ctx: Long, count: Long): Int = SSL_CTX_SET_NUM_TICKETS.invokeExact(ctx, count) as Int
    fun setOptions(ctx: Long, options: Int): Int = SSL_CTX_SET_OPTIONS.invokeExact(ctx, options) as Int
    fun setKeylogCallback(ctx: Long, callback: Long) {
        SSL_CTX_SET_KEYLOG_CALLBACK.invokeExact(ctx, callback)
    }
    fun setAlpnSelectCallback(ctx: Long, callback: Long, arg: Long) {
        SSL_CTX_SET_ALPN_SELECT_CB.invokeExact(ctx, callback, arg)
    }
    fun setDefaultPasswordCallback(ctx: Long, callback: Long) {
        SSL_CTX_SET_DEFAULT_PASSWD_CB.invokeExact(ctx, callback)
    }
    fun setSessionIdContext(ctx: Long, id: Long, length: Long): Int = SSL_CTX_SET_SESSION_ID_CONTEXT.invokeExact(ctx, id, length) as Int

    fun sslNew(ctx: Long): Long = SSL_NEW.invokeExact(ctx) as Long

    /** Frees both BIOs as well. */
    fun sslFree(ssl: Long) {
        SSL_FREE.invokeExact(ssl)
    }
    fun setAcceptState(ssl: Long) {
        SSL_SET_ACCEPT_STATE.invokeExact(ssl)
    }

    /** [ssl] owns both BIOs from here. */
    fun setBio(ssl: Long, rbio: Long, wbio: Long) {
        SSL_SET_BIO.invokeExact(ssl, rbio, wbio)
    }
    fun shutdown(ssl: Long): Int = SSL_SHUTDOWN.invokeExact(ssl) as Int

    /** Whether the handshake is still running: SSL_shutdown on one that is only queues an error. */
    fun inInit(ssl: Long): Boolean = (SSL_IN_INIT.invokeExact(ssl) as Int) != 0
    fun version(ssl: Long): Int = SSL_VERSION.invokeExact(ssl) as Int

    fun currentCipherId(ssl: Long): Int {
        val cipher = SSL_GET_CURRENT_CIPHER.invokeExact(ssl) as Long
        return if (cipher == 0L) 0 else (SSL_CIPHER_GET_PROTOCOL_ID.invokeExact(cipher) as Short).toInt() and 0xFFFF
    }

    /** What ALPN settled on, or null when the client offered nothing this port serves. */
    fun alpnSelected(ssl: Long): String? = Arena.ofConfined().use { arena ->
        val out = arena.allocate(16)
        SSL_GET0_ALPN_SELECTED.invokeExact(ssl, out.address(), out.address() + 8)
        val data = out.get(L, 0)
        val length = out.get(I, 8)
        if (data == 0L || length == 0) null else String(ByteArray(length) { getByte(data + it) }, Charsets.US_ASCII)
    }

    // The three operations whose result has to be classified, each run from a clean error queue and returning
    // the classification. The queue belongs to the thread, which here is a reactor shared by every connection:
    // SSL_get_error reads it before asking whether the SSL merely wants more data, so a residue another
    // connection left would read as this one's fatal error. The raw entry points stay private for that reason.

    /** SSL_accept: 0 once the handshake is done, otherwise SSL_get_error's code. */
    fun accept(ssl: Long): Int {
        ERR_CLEAR_ERROR.invokeExact()
        val ret = SSL_ACCEPT.invokeExact(ssl) as Int
        return if (ret == 1) 0 else SSL_GET_ERROR.invokeExact(ssl, ret) as Int
    }

    /** SSL_read: the bytes read, or minus SSL_get_error's code. */
    fun read(ssl: Long, buffer: Long, length: Int): Int {
        ERR_CLEAR_ERROR.invokeExact()
        val n = SSL_READ.invokeExact(ssl, buffer, length) as Int
        return if (n > 0) n else -(SSL_GET_ERROR.invokeExact(ssl, n) as Int)
    }

    /** SSL_write of native bytes: the bytes taken, or minus SSL_get_error's code. */
    fun write(ssl: Long, buffer: Long, length: Int): Int {
        ERR_CLEAR_ERROR.invokeExact()
        val n = SSL_WRITE.invokeExact(ssl, buffer, length) as Int
        return if (n > 0) n else -(SSL_GET_ERROR.invokeExact(ssl, n) as Int)
    }

    /** SSL_write straight from a heap array, which a critical call may hand over without a copy. */
    fun write(ssl: Long, source: ByteArray, offset: Int, length: Int): Int {
        ERR_CLEAR_ERROR.invokeExact()
        val segment = MemorySegment.ofArray(source).asSlice(offset.toLong(), length.toLong())
        val n = SSL_WRITE_HEAP.invokeExact(ssl, segment, length) as Int
        return if (n > 0) n else -(SSL_GET_ERROR.invokeExact(ssl, n) as Int)
    }

    fun memoryBio(): Long = BIO_NEW.invokeExact(BIO_S_MEM.invokeExact() as Long) as Long

    /** A read-only BIO over [length] bytes at [address], which must outlive it. */
    fun memoryBuffer(address: Long, length: Long): Long = BIO_NEW_MEM_BUF.invokeExact(address, length) as Long
    fun bioFree(bio: Long): Int = BIO_FREE.invokeExact(bio) as Int
    fun bioWrite(bio: Long, data: Long, length: Int): Int = BIO_WRITE.invokeExact(bio, data, length) as Int
    fun bioRead(bio: Long, data: Long, length: Int): Int = BIO_READ.invokeExact(bio, data, length) as Int
    fun bioPending(bio: Long): Long = BIO_CTRL_PENDING.invokeExact(bio) as Long
    fun bioCtrl(bio: Long, cmd: Int, larg: Long, parg: Long): Long = BIO_CTRL.invokeExact(bio, cmd, larg, parg) as Long

    fun readX509(bio: Long): Long = PEM_READ_BIO_X509.invokeExact(bio, 0L, 0L, 0L) as Long
    fun readPrivateKey(bio: Long): Long = PEM_READ_BIO_PRIVATEKEY.invokeExact(bio, 0L, 0L, 0L) as Long
    fun x509Free(x509: Long) {
        X509_FREE.invokeExact(x509)
    }
    fun pkeyFree(pkey: Long) {
        EVP_PKEY_FREE.invokeExact(pkey)
    }

    fun clearError() {
        ERR_CLEAR_ERROR.invokeExact()
    }

    /** Whether the queued error says a key does not belong to the certificate loaded. */
    fun errorIsKeyMismatch(): Boolean {
        val code = ERR_PEEK_ERROR.invokeExact() as Int
        val reason = code and 0xFFF
        return (code ushr 24) == ERR_LIB_X509 && (reason == X509_R_KEY_TYPE_MISMATCH || reason == X509_R_KEY_VALUES_MISMATCH)
    }

    /**
     * Drains the queue and reports whether it held only "no start line", PEM's way of saying the BIO is
     * exhausted. Anything else means a read stopped on a malformed block - the difference between the last
     * certificate of a bundle and the rest of it silently dropped.
     */
    fun errorIsEndOfPem(): Boolean {
        var sawEnd = false
        var sawOther = false
        while (true) {
            val code = ERR_GET_ERROR.invokeExact() as Int
            if (code == 0) break
            if ((code ushr 24) == ERR_LIB_PEM && (code and 0xFFF) == PEM_R_NO_START_LINE) sawEnd = true else sawOther = true
        }
        return sawEnd && !sawOther
    }

    /** The oldest queued error as text, and the queue drained so the next caller does not read it again. */
    fun lastError(): String {
        val code = ERR_GET_ERROR.invokeExact() as Int
        if (code == 0) return "no BoringSSL error"
        val buffer = Native.malloc(256)
        val message = try {
            ERR_ERROR_STRING_N.invokeExact(code, buffer, 256L)
            cString(buffer)
        } finally {
            Native.free(buffer)
        }
        while ((ERR_GET_ERROR.invokeExact() as Int) != 0) { /* drain */ }
        return message
    }

    fun cString(address: Long): String = MEM.getString(address)

    private inline fun <T> withCString(text: String, body: (Long) -> T): T =
        Arena.ofConfined().use { arena -> body(arena.allocateFrom(text).address()) }
}
