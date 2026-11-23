package playground

import ioxide.IoxideServer
import ioxide.Memory
import ioxide.RecvItem
import ioxide.ServerConfig
import ioxide.TcpConnection
import ioxide.TcpOptions

/**
 * count - Tcp/Raw answering once per request instead of once per read: a request is anything ending in
 * "\r\n\r\n", found by a byte state machine that carries across reads, so pipelined and fragmented GETs get one
 * response each. No HTTP parsing - bodies are not framed - so it takes GET-only load (gcannon get.raw,
 * pipelining, churn). Twin of kotlin/bench/cs-count, for comparing the two runtimes under that load.
 */
object TcpCount {
    fun run() {
        val port = Env.port(8080)
        val reactors = Env.reactors(Runtime.getRuntime().availableProcessors())

        val config = ServerConfig(
            reactorCount = reactors,
            ringEntries = 8192,
            recvBufferSize = 32 * 1024,
            recvSlots = 4096,
            tcp = TcpOptions(port = port, listenBacklog = 1024, writeSlabSize = 16 * 1024, poolMax = 1024, recvQueueEntries = 64),
        )

        val response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".toByteArray()

        suspend fun handle(conn: TcpConnection) {
            val item = RecvItem()
            var state = 0   // how much of "\r\n\r\n" the bytes so far end with
            while (true) {
                val snapshot = conn.read()

                var requests = 0
                while (conn.tryGetItem(snapshot, item)) {
                    val p = item.address
                    for (i in 0 until item.length) {
                        when (Memory.getByte(p + i).toInt()) {
                            13 -> state = if (state == 2) 3 else 1
                            10 -> state = when (state) {
                                1 -> 2
                                3 -> { requests++; 0 }
                                else -> 0
                            }
                            else -> state = 0
                        }
                    }
                    conn.returnBuffer(item)
                }

                repeat(requests) { conn.write(response) }
                if (requests > 0) conn.flush()

                if (snapshot.isClosed) return
            }
        }

        val server = IoxideServer(config, handler = ::handle).start()
        System.err.println("[count] $reactors reactors on :$port")
        server.join()
    }
}
