package playground

/** Runs the sample named by the first argument (default `tcp-raw`). */
fun main(args: Array<String>) {
    when (val sample = args.firstOrNull() ?: "tcp-raw") {
        "tcp-raw" -> TcpRaw.run()
        "tcp-pipe" -> TcpPipe.run()
        "tcp-count" -> TcpCount.run()
        "tls-raw" -> TlsRaw.run()
        else -> {
            System.err.println("unknown sample '$sample'; known: tcp-raw, tcp-pipe, tcp-count, tls-raw")
            kotlin.system.exitProcess(2)
        }
    }
}
