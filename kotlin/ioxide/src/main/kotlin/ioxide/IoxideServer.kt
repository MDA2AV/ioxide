package ioxide

/**
 * The host side, for the common case: [ServerConfig.reactorCount] reactors, each on its own platform thread
 * named `reactor-<id>`, all serving [handler]. The core creates no threads itself - this is all a host has to
 * do with [Reactor] directly.
 */
class IoxideServer(
    private val config: ServerConfig,
    private val onStart: ((Reactor) -> Unit)? = null,
    private val handler: suspend (TcpConnection) -> Unit,
) : AutoCloseable {
    val reactors: List<Reactor> = List(config.reactorCount) { id ->
        Reactor(id, config).also {
            it.tcpHandler = handler
            it.onStart = onStart
        }
    }

    private val threads = reactors.map { reactor -> Thread(reactor::run, "reactor-${reactor.id}") }

    fun start(): IoxideServer {
        threads.forEach(Thread::start)
        return this
    }

    /** Waits for every reactor thread to end. */
    fun join() {
        threads.forEach(Thread::join)
    }

    /** Stops every reactor and waits for their teardown. */
    override fun close() {
        reactors.forEach(Reactor::stop)
        join()
    }
}
