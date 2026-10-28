package playground

import ioxide.IoxideServer
import ioxide.RecvItem
import ioxide.ServerConfig
import ioxide.TcpConnection
import ioxide.TcpOptions

/**
 * raw - a complete ioxide server in one file, the Kotlin twin of Playground/Tcp/Raw: one pre-encoded response
 * per read, no parsing, so it is the throughput baseline the other samples are read against.
 *
 *     ./gradlew :playground:installDist && playground/build/install/playground/bin/playground tcp-raw
 *     curl http://127.0.0.1:8080/
 */
object TcpRaw {
    fun run() {
        val port = Env.port(8080)
        val reactors = Env.reactors(12)
        val bodyBytes = Env.body(2)

        // Every knob at its default, so the whole tuning surface is visible in one place.
        val config = ServerConfig(
            reactorCount = reactors,       // io_uring rings/threads - one per core
            ringEntries = 8192,            // SQ depth per ring (the CQ is twice that)
            recvBufferSize = 32 * 1024,    // bytes per shared recv buffer
            recvSlots = 4096,              // shared recv buffer-ring depth
            tcp = TcpOptions(
                port = port,
                listenBacklog = 1024,      // accept-queue depth per SO_REUSEPORT listener
                writeSlabSize = 16 * 1024, // per-connection write buffer; doubles when outgrown
                poolMax = 1024,            // pooled connection objects kept per reactor
                recvQueueEntries = 64,     // per-connection recv completion queue depth
                readTimeoutMs = 60_000,    // close a connection whose read waits this long on a silent peer; 0 = off
                sendTimeoutMs = 60_000,    // close a connection whose flush takes this long to go out; 0 = off
            ),
        )

        // One pre-encoded response, written for every request. PLAYGROUND_BODY sizes the body (2 = "ok").
        val body = if (bodyBytes == 2) "ok".toByteArray() else ByteArray(bodyBytes) { if (it == bodyBytes - 1) '\n'.code.toByte() else 'x'.code.toByte() }
        val response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.size}\r\n\r\n".toByteArray() + body

        // The handler. It runs on the reactor thread and every suspension resumes right back on it.
        suspend fun handle(conn: TcpConnection) {
            val item = RecvItem()
            while (true) {
                // io_uring recv. The continuation resumes inline on this thread - no thread pool.
                val snapshot = conn.read()

                // ioxide hands you raw bytes and stays out of HTTP: this sample returns every buffer unread.
                while (conn.tryGetItem(snapshot, item)) conn.returnBuffer(item)

                // Stage into the connection's write slab, then one io_uring send.
                conn.write(response)
                conn.flush()

                if (snapshot.isClosed) return   // peer went away
            }
        }

        val server = IoxideServer(config, handler = ::handle).start()
        System.err.println("[raw] $reactors reactors on :$port, $bodyBytes-byte body")
        server.join()
    }
}
