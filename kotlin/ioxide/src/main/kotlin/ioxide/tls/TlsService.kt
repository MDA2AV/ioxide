package ioxide.tls

import ioxide.Native
import ioxide.Reactor
import ioxide.RecvItem
import ioxide.RecvSnapshot
import ioxide.Sockets
import ioxide.TcpConnection
import ioxide.copyFromArray
import ioxide.putByte
import ioxide.putShort
import java.io.IOException
import java.lang.foreign.Arena
import java.nio.file.Files
import java.nio.file.Path

/**
 * One reactor's TLS termination. [accept] runs the handshake through BoringSSL memory BIOs, its bytes riding
 * the connection's ordinary ring recv and send, and hands back the [TlsSession] that carries the connection from
 * there. BoringSSL owns both directions by default; kernel TLS is opt-in per direction ([TlsOptions.kernelTx],
 * [TlsOptions.kernelRx]) and the handoff happens here, right after the handshake.
 *
 * Start one per reactor from [Reactor.onStart], so the context and its ticket keys belong to the thread that
 * uses them; a ticket resumes on the reactor that issued it.
 */
class TlsService private constructor(
    private val reactor: Reactor,
    private val options: TlsOptions,
    private val context: Long,
) {
    // Handshakes still running, oldest first. Every entry has the same timeout, so insertion order is deadline
    // order and the sweep stops at the first that has not expired.
    private val handshakes = ArrayDeque<PendingHandshake>()

    private class PendingHandshake(var conn: TcpConnection?, val deadlineMs: Long)

    private val item = RecvItem()
    private var waiting = 0L   // the kTLS RX handoff's direct-recv buffer, made on first use

    // Closes connections that have been handshaking too long. The shutdown is what the peer sees and what ends
    // the reactor's recv, so the connection is released; markClosed wakes the handshake now, not a round trip later.
    private fun sweepHandshakes() {
        val now = reactor.nowMs
        while (true) {
            val head = handshakes.firstOrNull() ?: return
            val conn = head.conn
            if (conn == null) {
                handshakes.removeFirst()
                continue
            }
            if (now < head.deadlineMs) return
            handshakes.removeFirst()
            Native.shutdown(conn.clientFd, Sockets.SHUT_RDWR)
            conn.markClosed()
        }
    }

    /**
     * Runs the server handshake on [conn], resuming inline on the reactor like every other wait, and returns the
     * session. Application data that rode in with the client's final flight is in [TlsSession.drainPlaintext].
     * Throws [IOException] when the handshake fails or the peer goes away during it.
     */
    suspend fun accept(conn: TcpConnection): TlsSession {
        val ssl = BoringSsl.sslNew(context)
        if (ssl == 0L) throw IOException("SSL_new: ${BoringSsl.lastError()}")
        val rbio = BoringSsl.memoryBio()
        val wbio = BoringSsl.memoryBio()
        BoringSsl.setBio(ssl, rbio, wbio)
        BoringSsl.setAcceptState(ssl)

        val session = TlsSession(ssl, rbio, wbio)
        session.attachConnection(conn)   // the teardown close_notify goes out on it

        val pending = if (options.handshakeTimeoutMs > 0) {
            PendingHandshake(conn, reactor.nowMs + options.handshakeTimeoutMs).also { handshakes.addLast(it) }
        } else {
            null
        }

        try {
            while (true) {
                val error = handshakeStep(ssl, session)

                // Read before the alert's flush, during which other connections' calls clear this thread's queue.
                val failure = if (error != 0 && error != BoringSsl.SSL_ERROR_WANT_READ) BoringSsl.lastError() else null

                flushOutbound(conn, wbio)
                if (error == 0) break
                if (failure != null) throw IOException("TLS handshake failed: $failure")

                val snapshot = conn.read()
                val fed = feedInbound(conn, rbio, snapshot)
                if (snapshot.isClosed && !fed) throw IOException("connection closed during TLS handshake")
            }

            session.captureAlpn()

            // kTLS RX takes over at a record boundary: the records the handshake already pulled off the socket are
            // invisible to the kernel, so BoringSSL decrypts them and the kernel's sequence starts after. -1 keeps
            // the connection on BoringSSL.
            val handedRecords =
                if (options.kernelTx && options.kernelRx && session.clientSecret != null) handoffBoundary(conn, rbio, session) else -1

            // Application data that rode in with the client's Finished, decrypted now.
            session.drainPending()

            if (options.kernelTx) {
                // The secret exists only on TLS 1.3, which kernelTx pins, so its absence is a real failure here.
                val secret = session.serverSecret
                    ?: throw IOException("TLS handshake completed but no server traffic secret was captured")
                session.serverSecret = null
                Ktls.enableTx(conn.clientFd, secret)   // zeroes the secret once programmed
                conn.sendFlags = 0                     // kTLS refuses MSG_WAITALL; the reactor still loops on short sends
                session.markTxEnabled()
            } else {
                session.zeroSecrets()
            }

            val clientSecret = session.clientSecret
            session.clientSecret = null
            if (handedRecords >= 0 && clientSecret != null) {
                Ktls.enableRx(conn.clientFd, clientSecret, handedRecords.toLong())
                session.markKernelRx()
            } else {
                clientSecret?.fill(0)
            }
            return session
        } catch (e: Throwable) {
            session.close()
            throw e
        } finally {
            // Emptied rather than removed: the sweep drops empty entries when they reach the front.
            pending?.conn = null
        }
    }

    private fun handshakeStep(ssl: Long, session: TlsSession): Int {
        TlsCallbacks.handshaking.set(session)
        try {
            return BoringSsl.accept(ssl)
        } finally {
            TlsCallbacks.handshaking.set(null)
        }
    }

    // The server's flights, staged whole and sent with one flush.
    private suspend fun flushOutbound(conn: TcpConnection, wbio: Long) {
        var staged = false
        while (true) {
            val pending = BoringSsl.bioPending(wbio).toInt()
            if (pending <= 0) break
            val n = BoringSsl.bioRead(wbio, conn.getBuffer(pending), pending)
            if (n <= 0) break
            conn.advance(n)
            staged = true
        }
        if (staged) conn.flush()
    }

    private fun feedInbound(conn: TcpConnection, rbio: Long, snapshot: RecvSnapshot): Boolean {
        var any = false
        while (conn.tryGetItem(snapshot, item)) {
            if (item.hasBuffer) {
                BoringSsl.bioWrite(rbio, item.address, item.length)
                conn.returnBuffer(item)
                any = true
            }
        }
        return any
    }

    // Finds the record boundary the kTLS RX handoff programs the kernel at, or -1 to stay on BoringSSL. With
    // DEFER_TASKRUN nothing more leaves the socket before the reactor's next enter, and nothing below waits
    // between the count and the handoff, so the count holds - unless the kernel is holding completions the CQ
    // had no room for.
    private suspend fun handoffBoundary(conn: TcpConnection, rbio: Long, session: TlsSession): Int {
        val turn = HandoffTurn(conn)
        var closed = false
        while (true) {
            // The rest of the batch that finished the handshake may hold further records: fed as they come, so
            // the recv queue never fills, until the end of the batch wakes this.
            turn.schedule()
            do {
                val snapshot = conn.read()
                feedInbound(conn, rbio, snapshot)
                closed = closed || snapshot.isClosed
            } while (!turn.ended && !closed)

            if (conn.reactor.ring.cqOverflowed) return -1

            // Counted before draining: a cut record's rest is often in the socket already, and nothing else reads
            // the socket before the next enter. Exactly the rest is taken.
            var records = session.countPendingRecords()
            while (session.pendingMissing > 0 && !closed && takeWaiting(conn.clientFd, rbio, session.pendingMissing) > 0) {
                records = session.countPendingRecords()
            }
            if (session.pendingMissing == 0) return records

            if (closed) throw IOException("connection closed inside a TLS record")
            if (BoringSsl.bioPending(rbio) > MAX_HANDOFF_BYTES) return -1   // its records keep arriving cut

            // The rest has not arrived: wait for more, then for the end of its batch.
            val more = conn.read()
            feedInbound(conn, rbio, more)
            closed = closed || more.isClosed
        }
    }

    // Takes up to count bytes already waiting in the socket into the read BIO, without blocking.
    private fun takeWaiting(fd: Int, rbio: Long, count: Int): Int {
        if (waiting == 0L) waiting = Native.malloc(WAITING_BYTES.toLong())
        val n = Native.recv(fd, waiting, minOf(count, WAITING_BYTES).toLong(), Sockets.MSG_DONTWAIT)
        if (n <= 0) return 0
        BoringSsl.bioWrite(rbio, waiting, n.toInt())
        return n.toInt()
    }

    // Wakes the handoff's read at the end of the reactor's turn: a post from the reactor thread runs once every
    // completion of the batch is dispatched, before the next enter.
    private class HandoffTurn(private val conn: TcpConnection) {
        var ended = false
            private set
        private var generation = 0

        fun schedule() {
            ended = false
            generation = conn.generation
            conn.reactor.post {
                // A handshake that ended mid-turn may have let go of the connection, which may live again.
                if (conn.generation == generation) {
                    ended = true
                    conn.wakeRead()
                }
            }
        }
    }

    companion object {
        private const val KERNEL_TLS_SUITE = "TLS_AES_128_GCM_SHA256"
        private const val MAX_HANDOFF_BYTES = 1L shl 20
        private const val WAITING_BYTES = 16 * 1024

        // Scopes sessions to this server, so a ticket another server issued is not resumed here.
        private val sessionIdContext: Long = Arena.global().allocateFrom("ioxide").address()
        private const val SESSION_ID_CONTEXT_LENGTH = 6L

        /** Builds [reactor]'s TLS context from [options] and starts its handshake sweep. Call from [Reactor.onStart]. */
        fun start(reactor: Reactor, options: TlsOptions): TlsService {
            validate(options)
            val alpnWire = alpnWire(options.alpn)
            val context = newContext(options, alpnWire)
            val service = TlsService(reactor, options, context)
            if (options.handshakeTimeoutMs > 0) reactor.addTicker { service.sweepHandshakes() }
            return service
        }

        // The combinations that cannot hold are named here rather than resolved by whichever setting runs last.
        private fun validate(options: TlsOptions) {
            require(options.handshakeTimeoutMs >= 0) {
                "handshakeTimeoutMs is ${options.handshakeTimeoutMs}; 0 disables the handshake sweep, a negative value would too."
            }
            require(!options.kernelRx || options.kernelTx) {
                "kernelRx requires kernelTx: kTLS RX is programmed at the same handoff and rides the ULP TX installs."
            }
            require(!options.kernelTx || options.minProtocolVersion != TlsProtocolVersion.TLS12) {
                "kernelTx negotiates TLS 1.3 only, so minProtocolVersion = TLS12 cannot hold. Drop one of the two."
            }
            require(!options.kernelTx || options.cipherSuites == null || options.cipherSuites.trim() == KERNEL_TLS_SUITE) {
                "kernelTx requires exactly $KERNEL_TLS_SUITE to derive kernel keys; set cipherSuites to it, or drop one of the two."
            }
            require((options.certificatePath == null) != (options.certificatePem == null)) {
                "Exactly one certificate source: set certificatePath or certificatePem."
            }
            require((options.keyPath == null) != (options.keyPem == null)) {
                "Exactly one key source: set keyPath or keyPem."
            }
        }

        // The protocols as the select callback walks them, in our preference order: a u16 total, then each one as a
        // length byte and its ASCII name. Lives as long as the process, as the contexts reading it do.
        private fun alpnWire(protocols: List<String>): Long {
            require(protocols.isNotEmpty()) { "At least one ALPN protocol is required." }
            var total = 0
            for (protocol in protocols) {
                require(protocol.length in 1..255) { "ALPN protocol '$protocol' must be 1..255 bytes." }
                require(protocol.all { it.code < 128 }) { "ALPN protocol '$protocol' must be ASCII." }
                total += 1 + protocol.length
            }
            val wire = Arena.global().allocate(2L + total).address()
            putShort(wire, total.toShort())
            var cursor = wire + 2
            for (protocol in protocols) {
                putByte(cursor++, protocol.length.toByte())
                for (c in protocol) putByte(cursor++, c.code.toByte())
            }
            return wire
        }

        private fun newContext(options: TlsOptions, alpnWire: Long): Long {
            val ctx = BoringSsl.ctxNew(BoringSsl.serverMethod())
            if (ctx == 0L) throw IOException("SSL_CTX_new: ${BoringSsl.lastError()}")
            try {
                configure(ctx, options, alpnWire)
            } catch (e: Throwable) {
                BoringSsl.ctxFree(ctx)   // never published, so nothing holds it
                throw e
            }
            return ctx
        }

        private fun configure(ctx: Long, options: TlsOptions, alpnWire: Long) {
            // Before any key is read: an encrypted key fails at load, whatever a default callback would try.
            BoringSsl.setDefaultPasswordCallback(ctx, TlsCallbacks.noPassphrase)

            if (options.minProtocolVersion != TlsProtocolVersion.DEFAULT) {
                val floor = if (options.minProtocolVersion == TlsProtocolVersion.TLS13) BoringSsl.TLS1_3_VERSION else BoringSsl.TLS1_2_VERSION
                if (BoringSsl.setMinProtoVersion(ctx, floor) != 1) throw IOException("set_min_proto_version: ${BoringSsl.lastError()}")
            }

            options.cipherSuites?.let { suites ->
                // Empty is refused: BoringSSL reads an empty list as its built-in order, which null already means.
                val names = suites.split(':').map { it.trim() }.filter { it.isNotEmpty() }
                if (names.isEmpty()) throw IOException("cipherSuites is empty, which disables every TLS 1.3 suite. Leave it null for the default.")
                val ids = ShortArray(names.size) { i ->
                    BoringSsl.tls13SuiteId(names[i])
                        ?: throw IOException("cipherSuites: '${names[i]}' is not a TLS 1.3 suite BoringSSL implements; TLS 1.2 ciphers go in cipherList.")
                }
                if (BoringSsl.setTls13Ciphers(ctx, ids) != 1) throw IOException("set1_tls13_ciphers: ${BoringSsl.lastError()}")
            }

            options.cipherList?.let {
                if (BoringSsl.setCipherList(ctx, it) != 1) throw IOException("set_cipher_list: ${BoringSsl.lastError()}")
            }

            // A stated list is in preference order; for TLS 1.2 the client's order wins without this.
            if (options.cipherSuites != null || options.cipherList != null) {
                BoringSsl.setOptions(ctx, BoringSsl.SSL_OP_CIPHER_SERVER_PREFERENCE)
            }

            if (options.kernelTx) {
                // TLS 1.3 only, one suite: kTLS is programmed with AES-128-GCM keys in a known layout.
                if (BoringSsl.setMinProtoVersion(ctx, BoringSsl.TLS1_3_VERSION) != 1 ||
                    BoringSsl.setMaxProtoVersion(ctx, BoringSsl.TLS1_3_VERSION) != 1 ||
                    BoringSsl.setTls13Ciphers(ctx, shortArrayOf(BoringSsl.TLS_AES_128_GCM_SHA256)) != 1
                ) {
                    throw IOException("kTLS posture: ${BoringSsl.lastError()}")
                }
                // No tickets: one would consume a record sequence number after the handshake and desynchronise
                // the handoff.
                BoringSsl.setNumTickets(ctx, 0)
            }

            loadCertificate(ctx, options)

            if (BoringSsl.setSessionIdContext(ctx, sessionIdContext, SESSION_ID_CONTEXT_LENGTH) != 1) {
                throw IOException("could not set the session id context: ${BoringSsl.lastError()}")
            }

            // Only the kernel path consumes the secrets, so the callback that materialises them is set only there.
            if (options.kernelTx) BoringSsl.setKeylogCallback(ctx, TlsCallbacks.keylog)
            BoringSsl.setAlpnSelectCallback(ctx, TlsCallbacks.alpnSelect, alpnWire)
        }

        // BoringSSL's file loaders, except for a file starting with a UTF-8 BOM, which its PEM reader does not skip:
        // that one goes through the in-memory route with the mark removed.
        private fun loadCertificate(ctx: Long, options: TlsOptions) {
            val certificatePath = options.certificatePath
            if (certificatePath != null) {
                val text = readAfterBom(certificatePath)
                if (text != null) {
                    loadCertificatePem(ctx, text, "certificate '$certificatePath'")
                } else if (BoringSsl.useCertificateChainFile(ctx, certificatePath) != 1) {
                    throw IOException("certificate '$certificatePath': ${BoringSsl.lastError()}")
                }
            } else {
                loadCertificatePem(ctx, options.certificatePem!!.toByteArray(Charsets.US_ASCII), "certificatePem")
            }

            val keyPath = options.keyPath
            if (keyPath != null) {
                val text = readAfterBom(keyPath)
                if (text != null) {
                    try {
                        loadKeyPem(ctx, text, "private key '$keyPath'")
                    } finally {
                        text.fill(0)
                    }
                } else if (BoringSsl.usePrivateKeyFile(ctx, keyPath) != 1) {
                    throw if (BoringSsl.errorIsKeyMismatch()) pairMismatch() else IOException("private key '$keyPath': ${BoringSsl.lastError()}")
                }
            } else {
                val text = options.keyPem!!.toByteArray(Charsets.US_ASCII)
                try {
                    loadKeyPem(ctx, text, "keyPem")
                } finally {
                    text.fill(0)
                }
            }

            // Checked explicitly: whether the key load notices a mismatch depends on the key types.
            if (BoringSsl.checkPrivateKey(ctx) != 1) throw pairMismatch()
        }

        private fun pairMismatch(): IOException {
            BoringSsl.clearError()
            return IOException("the certificate and private key do not go together - the key is not the one the certificate was issued for.")
        }

        // The file's bytes after a leading UTF-8 BOM, or null when it has none or cannot be read, so that
        // BoringSSL's own loader reports the file as it reports every other unusable one.
        private fun readAfterBom(path: String): ByteArray? = try {
            val bytes = Files.readAllBytes(Path.of(path))
            if (bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte()) {
                bytes.copyOfRange(3, bytes.size).also { bytes.fill(0) }
            } else {
                bytes.fill(0)
                null
            }
        } catch (e: java.io.IOException) {
            null
        } catch (e: SecurityException) {
            null
        }

        private fun loadCertificatePem(ctx: Long, pem: ByteArray, source: String) = withMemoryBio(pem) { bio ->
            // The first block is the leaf; use_certificate takes its own reference.
            val leaf = BoringSsl.readX509(bio)
            if (leaf == 0L) throw IOException("$source carries no certificate: ${BoringSsl.lastError()}")
            val ok = BoringSsl.useCertificate(ctx, leaf)
            BoringSsl.x509Free(leaf)
            if (ok != 1) throw IOException("$source: ${BoringSsl.lastError()}")

            // Any further blocks are the chain, closest to the leaf first. A malformed block is refused rather than
            // read as the end: the leaf would be served with its chain cut at the tear.
            while (true) {
                val extra = BoringSsl.readX509(bio)
                if (extra == 0L) {
                    if (!BoringSsl.errorIsEndOfPem()) {
                        throw IOException("$source is malformed after the leaf; the rest of the chain would have been ignored.")
                    }
                    BoringSsl.clearError()
                    break
                }
                if (BoringSsl.addExtraChainCert(ctx, extra) != 1) {
                    BoringSsl.x509Free(extra)
                    throw IOException("$source chain: ${BoringSsl.lastError()}")
                }
            }
        }

        private fun loadKeyPem(ctx: Long, pem: ByteArray, source: String) = withMemoryBio(pem) { bio ->
            val key = BoringSsl.readPrivateKey(bio)
            if (key == 0L) throw IOException("$source carries no private key: ${BoringSsl.lastError()}")
            val ok = BoringSsl.usePrivateKey(ctx, key)
            BoringSsl.pkeyFree(key)
            if (ok != 1 && BoringSsl.errorIsKeyMismatch()) throw pairMismatch()
            if (ok != 1) throw IOException("$source: ${BoringSsl.lastError()}")
        }

        // A read-only memory BIO over a native copy of pem, which is zeroed and freed with it.
        private inline fun withMemoryBio(pem: ByteArray, body: (Long) -> Unit) {
            val buffer = Native.malloc(pem.size.coerceAtLeast(1).toLong())
            try {
                copyFromArray(pem, 0, buffer, pem.size)
                val bio = BoringSsl.memoryBuffer(buffer, pem.size.toLong())
                if (bio == 0L) throw IOException("BIO_new_mem_buf: ${BoringSsl.lastError()}")
                try {
                    body(bio)
                } finally {
                    BoringSsl.bioFree(bio)
                }
            } finally {
                ioxide.zeroMemory(buffer, pem.size.toLong())
                Native.free(buffer)
            }
        }
    }
}
