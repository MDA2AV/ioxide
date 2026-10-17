namespace epoxide;

/// <summary>
/// All server tunables; override via object initializer. Engine-wide knobs live here and the TCP
/// transport's in <see cref="Tcp"/>, the way ioxide groups them - minus what only an io_uring ring
/// needs (ring depth, provided-buffer rings, op slots).
/// </summary>
public sealed record ServerConfig
{
    public int ReactorCount { get; init; } = 12;

    /// <summary>Events one epoll_wait can return: the most a reactor takes in per pass.</summary>
    public int MaxEvents { get; init; } = 1024;

    /// <summary>
    /// Bind listeners as dual-stack IPv6 (AF_INET6 on :: with IPV6_V6ONLY=0) so one socket accepts both
    /// IPv6 and IPv4-mapped clients. When false (default) listeners are IPv4-only (AF_INET on 0.0.0.0).
    /// </summary>
    public bool DualStack { get; init; } = false;

    /// <summary>
    /// Bytes per receive buffer. A recv lands in one buffer from the reactor's pool and the buffer goes
    /// back once its bytes are consumed, so only data a handler has not read yet holds memory - an idle
    /// connection holds none.
    /// </summary>
    public int RecvBufferSize { get; init; } = 32 * 1024;

    /// <summary>
    /// The TCP transport: listeners, connection pool, and the write path. Null (default) opens no
    /// TCP listener, as in ioxide, so a reactor used only for outbound connections binds nothing:
    /// <c>new()</c> listens on <see cref="TcpOptions.Port"/>.
    /// </summary>
    public TcpOptions? Tcp { get; init; }
}

/// <summary>
/// How a connection's write buffer absorbs a response larger than <see cref="TcpOptions.WriteSlabSize"/>.
/// </summary>
public enum WriteOverflowStrategy
{
    /// <summary>Grow the single contiguous slab (realloc + copy); the flush stays one send.</summary>
    Grow,

    /// <summary>Chain pooled slabs and flush them with one vectored sendmsg (no realloc copies).</summary>
    Segmented,
}

/// <summary>The TCP side of <see cref="ServerConfig"/>: listeners, connection pool, and the write path.</summary>
public sealed record TcpOptions
{
    public ushort Port { get; init; } = 8080;

    /// <summary>
    /// Additional listener ports (every reactor binds each one). Connections carry the port they
    /// arrived on in <see cref="TcpConnection.ListenerPort"/>, so one handler can serve several
    /// entry points (e.g. plaintext + TLS).
    /// </summary>
    public ushort[] ExtraPorts { get; init; } = [];

    /// <summary>listen() backlog per SO_REUSEPORT listener - the accept-queue depth for connection bursts.</summary>
    public int ListenBacklog { get; init; } = 1024;

    // Per-connection write slab + connection pool cap.
    public int WriteSlabSize { get; init; } = 16 * 1024;
    public int PoolMax       { get; init; } = 1024;

    // How a response larger than WriteSlabSize is buffered: grow the slab (default) or chain pooled
    // slabs flushed with one vectored sendmsg.
    public WriteOverflowStrategy WriteOverflow { get; init; } = WriteOverflowStrategy.Grow;

    /// <summary>
    /// Received buffers a connection may hold that its reader has not taken yet (a power of two). Reads
    /// are pulled by the reader, so a full queue stops the reading and lets TCP push back on the peer -
    /// it never drops data or closes the connection the way an overflowing io_uring queue has to.
    /// </summary>
    public int RecvQueueEntries { get; init; } = 64;

    /// <summary>
    /// Close a connection whose read has waited this long for the peer. 0 disables. Enforced on the
    /// reactor's ~250 ms ticker, like ioxide's: the clock runs only while a read is parked with nothing
    /// buffered, and bytes in either direction restart it.
    /// </summary>
    public int ReadTimeoutMs { get; init; } = 60_000;

    /// <summary>
    /// Close a connection whose flush has been waiting this long for the socket to take the rest. 0
    /// disables. A peer that stops reading shuts its window and the flush never completes; nothing
    /// else bounds that.
    /// </summary>
    public int SendTimeoutMs { get; init; } = 60_000;
}
