package ioxide

import ioxide.tls.TlsOptions
import ioxide.tls.TlsProtocolVersion
import ioxide.tls.TlsService
import ioxide.tls.TlsSession
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.IOException
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * TLS end to end: a one-reactor echo server behind [TlsService], and the JDK's own TLS client, which validates the
 * test certificate (CN and SAN localhost) rather than trusting anything.
 */
class TlsTest {
    private val certPath = TestCertificate.certificate.toString()
    private val keyPath = TestCertificate.key.toString()

    // What the server saw of the session, for the test thread.
    private class Observed {
        @Volatile var kernelTx = false
        @Volatile var kernelRx = false
        @Volatile var alpn: String? = null
        @Volatile var version = 0
        @Volatile var failure: String? = null
    }

    private fun withEchoServer(options: TlsOptions, body: (port: Int, observed: Observed) -> Unit) {
        val observed = Observed()
        val services = arrayOfNulls<TlsService>(1)
        val ready = CountDownLatch(1)
        val item = RecvItem()

        suspend fun echo(conn: TcpConnection) {
            var tls: TlsSession? = null
            try {
                val session = services[0]!!.accept(conn)
                tls = session
                observed.kernelTx = session.kernelTx
                observed.kernelRx = session.kernelRx
                observed.alpn = session.negotiatedAlpn
                observed.version = session.negotiatedProtocolVersion

                val early = session.drainPlaintext()
                if (early > 0) {
                    session.write(conn, session.plaintext, early)
                    conn.flush()
                }
                while (true) {
                    val snapshot = conn.read()
                    var wrote = false
                    while (conn.tryGetItem(snapshot, item)) {
                        if (!item.hasBuffer) continue
                        val n = session.decrypt(item.address, item.length)
                        if (n > 0) {
                            session.write(conn, session.plaintext, n)
                            wrote = true
                        }
                        conn.returnBuffer(item)
                    }
                    if (wrote) conn.flush()
                    if (snapshot.isClosed || session.closed) return
                }
            } catch (e: IOException) {
                observed.failure = e.message
            } finally {
                tls?.close()
            }
        }

        val config = ServerConfig(reactorCount = 1, tcp = TcpOptions(port = 0))
        val server = IoxideServer(config, onStart = { r ->
            services[0] = TlsService.start(r, options)
            ready.countDown()
        }, handler = ::echo).start()
        try {
            assertTrue(ready.await(10, TimeUnit.SECONDS), "the reactor never started")
            body(server.reactors[0].listenPorts[0], observed)
        } finally {
            server.close()
        }
    }

    private fun clientContext(): SSLContext {
        val certificate = Files.newInputStream(Path.of(certPath)).use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("server", certificate)
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        return SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
    }

    private fun connect(port: Int, protocols: Array<String> = arrayOf("TLSv1.3"), alpn: Array<String> = arrayOf("http/1.1")): SSLSocket {
        val socket = clientContext().socketFactory.createSocket("localhost", port) as SSLSocket
        socket.soTimeout = 10_000
        socket.sslParameters = socket.sslParameters.apply {
            this.protocols = protocols
            applicationProtocols = alpn
            endpointIdentificationAlgorithm = "HTTPS"
        }
        socket.startHandshake()
        return socket
    }

    // Writes size random bytes from another thread while this one reads them back, so a large echo cannot fill
    // both directions and stall.
    private fun echo(socket: SSLSocket, size: Int) {
        val data = Random(size).nextBytes(size)
        val writer = Thread {
            socket.outputStream.write(data)
            socket.outputStream.flush()
        }
        writer.start()
        val got = ByteArray(size)
        var read = 0
        while (read < size) {
            val n = socket.inputStream.read(got, read, size - read)
            if (n < 0) break
            read += n
        }
        writer.join()
        assertEquals(size, read)
        assertContentEquals(data, got)
    }

    private fun kernelTlsAvailable(): Boolean =
        runCatching { Files.readString(Path.of("/proc/sys/net/ipv4/tcp_available_ulp")).split(' ', '\n').contains("tls") }.getOrDefault(false)

    @Test
    fun `BoringSSL carries data both ways`() = withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath)) { port, observed ->
        connect(port).use { socket ->
            echo(socket, 5)
            echo(socket, 256 * 1024)
        }
        assertFalse(observed.kernelTx)
        assertFalse(observed.kernelRx)
        assertEquals("http/1.1", observed.alpn)
        assertEquals(0x0304, observed.version)
    }

    @Test
    fun `kernel TX encrypts what the handler writes as plaintext`() {
        assumeTrue(kernelTlsAvailable(), "the tls kernel module is not loaded")
        withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath, kernelTx = true)) { port, observed ->
            connect(port).use { socket ->
                echo(socket, 5)
                echo(socket, 1024 * 1024)
            }
            assertTrue(observed.kernelTx)
            assertFalse(observed.kernelRx)
        }
    }

    @Test
    fun `kernel TX and RX carry data both ways`() {
        assumeTrue(kernelTlsAvailable(), "the tls kernel module is not loaded")
        withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath, kernelTx = true, kernelRx = true)) { port, observed ->
            connect(port).use { socket ->
                echo(socket, 5)
                echo(socket, 1024 * 1024)
            }
            assertTrue(observed.kernelTx)
            assertTrue(observed.kernelRx)
        }
    }

    @Test
    fun `TLS 1_2 is served on BoringSSL and refused under kernel TX`() {
        withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath)) { port, observed ->
            connect(port, protocols = arrayOf("TLSv1.2")).use { echo(it, 100) }
            assertEquals(0x0303, observed.version)
        }
        assumeTrue(kernelTlsAvailable(), "the tls kernel module is not loaded")
        withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath, kernelTx = true)) { port, _ ->
            assertFailsWith<IOException> { connect(port, protocols = arrayOf("TLSv1.2")).close() }
        }
    }

    @Test
    fun `a client offering no protocol this port serves continues without ALPN`() =
        withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath)) { port, observed ->
            connect(port, alpn = arrayOf("h2")).use { socket ->
                assertEquals("", socket.applicationProtocol)
                echo(socket, 10)
            }
            assertNull(observed.alpn)
        }

    @Test
    fun `a handshake that never starts is closed by the sweep`() =
        withEchoServer(TlsOptions(certificatePath = certPath, keyPath = keyPath, handshakeTimeoutMs = 300)) { port, observed ->
            Socket("127.0.0.1", port).use { raw ->
                raw.soTimeout = 5_000
                val started = System.nanoTime()
                assertEquals(-1, raw.getInputStream().read())   // the server shut it down
                val ms = (System.nanoTime() - started) / 1_000_000
                assertTrue(ms in 250..3_000, "closed after $ms ms")
            }
            Thread.sleep(100)
            assertEquals("connection closed during TLS handshake", observed.failure)
        }

    @Test
    fun `a certificate and key with a byte-order mark load`() {
        val dir = Files.createTempDirectory("ioxide-tls")
        try {
            val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())
            val cert = dir.resolve("server.crt").also { Files.write(it, bom + Files.readAllBytes(Path.of(certPath))) }
            val key = dir.resolve("server.key").also { Files.write(it, bom + Files.readAllBytes(Path.of(keyPath))) }
            withEchoServer(TlsOptions(certificatePath = cert.toString(), keyPath = key.toString())) { port, _ ->
                connect(port).use { echo(it, 10) }
            }
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `settings that cannot hold are refused at start`() {
        val reactor = Reactor(0, ServerConfig())
        fun refused(options: TlsOptions) = assertFailsWith<IllegalArgumentException> { TlsService.start(reactor, options) }

        refused(TlsOptions(certificatePath = certPath, keyPath = keyPath, kernelRx = true))
        refused(TlsOptions(certificatePath = certPath, keyPath = keyPath, kernelTx = true, minProtocolVersion = TlsProtocolVersion.TLS12))
        refused(TlsOptions(certificatePath = certPath, keyPath = keyPath, kernelTx = true, cipherSuites = "TLS_AES_256_GCM_SHA384"))
        refused(TlsOptions(certificatePath = certPath, certificatePem = "x", keyPath = keyPath))
        refused(TlsOptions(keyPath = keyPath))
        refused(TlsOptions(certificatePath = certPath, keyPath = keyPath, handshakeTimeoutMs = -1))

        // A key that is not the certificate's is named at start, not left for every handshake to fail on.
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(other.private.encoded) +
            "\n-----END PRIVATE KEY-----\n"
        val mismatch = assertFailsWith<IOException> { TlsService.start(reactor, TlsOptions(certificatePath = certPath, keyPem = pem)) }
        assertTrue(mismatch.message!!.contains("do not go together"), mismatch.message)
    }
}

/**
 * A self-signed localhost certificate made once per run, so no key lives in the repository: keytool (the test JDK's
 * own) mints it into a PKCS#12 store, and the certificate and its PKCS#8 key are written out as PEM.
 */
private object TestCertificate {
    private val dir: Path = Files.createTempDirectory("ioxide-tls-cert").also { it.toFile().deleteOnExit() }
    val certificate: Path = dir.resolve("server.crt")
    val key: Path = dir.resolve("server.key")

    init {
        val store = dir.resolve("server.p12")
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString()
        val process = ProcessBuilder(
            keytool, "-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "3650",
            "-keystore", store.toString(), "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.readAllBytes().decodeToString()
        check(process.waitFor() == 0) { "keytool failed: $output" }

        val keys = KeyStore.getInstance("PKCS12").apply { Files.newInputStream(store).use { load(it, "changeit".toCharArray()) } }
        Files.writeString(certificate, pem("CERTIFICATE", keys.getCertificate("server").encoded))
        Files.writeString(key, pem("PRIVATE KEY", keys.getKey("server", "changeit".toCharArray()).encoded))
        listOf(certificate, key, store).forEach { it.toFile().deleteOnExit() }
    }

    private fun pem(type: String, der: ByteArray): String =
        "-----BEGIN $type-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END $type-----\n"
}
