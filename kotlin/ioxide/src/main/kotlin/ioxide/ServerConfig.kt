package ioxide

/**
 * One reactor's settings; every reactor of a server takes the same instance.
 *
 * @property reactorCount how many reactors [IoxideServer] starts, one thread and one ring each.
 * @property ringEntries SQ entries per ring; the kernel sizes the CQ at twice that.
 * @property recvBufferSize bytes per provided buffer of the reactor's shared recv group.
 * @property recvSlots buffers in that group, a power of two up to 32768.
 * @property opSlots initial capacity of the table of in-flight timer operations; it grows on demand.
 * @property tcp the TCP transport; null opens no listener at all.
 */
class ServerConfig(
    val reactorCount: Int = 12,
    val ringEntries: Int = 8192,
    val recvBufferSize: Int = 32 * 1024,
    val recvSlots: Int = 4096,
    val opSlots: Int = 4096,
    val tcp: TcpOptions? = null,
)

/**
 * @property port the listening port; 0 lets the kernel pick one (one reactor only - every reactor would get
 *   its own), read back from [Reactor.listenPorts].
 * @property extraPorts more ports, each with its own listener per reactor; [TcpConnection.listenerPort] says
 *   which one a connection came in on.
 * @property writeSlabSize initial bytes of each connection's write slab, which doubles when a response
 *   outgrows it and shrinks back on recycle.
 * @property poolMax connection objects (with their slabs) a reactor keeps for reuse.
 * @property sendWaitAll sends carry MSG_WAITALL, so the kernel completes a send only when every byte is out.
 * @property recvQueueEntries recv completions a connection can hold unread, a power of two; one more closes it.
 * @property readTimeoutMs how long a connection may wait on a silent peer, in ~250 ms steps; 0 disables it.
 * @property sendTimeoutMs how long a flush may wait on a peer that stopped draining; 0 disables it.
 */
class TcpOptions(
    val port: Int = 8080,
    val extraPorts: IntArray = IntArray(0),
    val listenBacklog: Int = 1024,
    val writeSlabSize: Int = 16 * 1024,
    val poolMax: Int = 1024,
    val sendWaitAll: Boolean = true,
    val recvQueueEntries: Int = 64,
    val readTimeoutMs: Long = 60_000,
    val sendTimeoutMs: Long = 60_000,
)
