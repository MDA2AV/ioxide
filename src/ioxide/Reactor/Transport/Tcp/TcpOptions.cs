namespace ioxide;

/// <summary>
/// How a connection's write buffer absorbs a response larger than <see cref="TcpOptions.WriteSlabSize"/>.
/// </summary>
public enum WriteOverflowStrategy
{
    /// <summary>Grow the single contiguous slab (realloc + copy); the flush stays one SEND.</summary>
    Grow,

    /// <summary>Chain pooled slabs and flush them with one vectored SENDMSG (no realloc copies).</summary>
    Segmented,
}

/// <summary>The TCP side of <see cref="ServerConfig"/>: listeners, connection pool, and the write path
/// (recv buffering is reactor machinery - see the buffer-ring knobs on <see cref="ServerConfig"/>).</summary>
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
    // slabs flushed with one vectored SENDMSG.
    public WriteOverflowStrategy WriteOverflow { get; init; } = WriteOverflowStrategy.Grow;

    // Inject IORING_OP_SEND_ZC (zero-copy send) for the response path instead of IORING_OP_SEND.
    // Trades the in-kernel payload copy for page-pinning plus a second (F_NOTIF) completion per send,
    // so it only pays off for large responses - leave off for small-payload workloads. The sender is
    // chosen once per connection at accept; kTLS connections always fall back to plain SEND (the
    // kernel re-buffers to encrypt, so zero-copy buys nothing there).
    public bool ZeroCopySend { get; init; } = false;

    // Per-connection SPSC recv queue depth (power of two); overflow closes the connection.
    public int RecvQueueEntries { get; init; } = 64;

    /// <summary>
    /// Close a connection whose read has waited this long for the peer. 0 disables.
    ///
    /// What it defends: a peer that connects and goes quiet holds an fd, a pooled
    /// <see cref="TcpConnection"/> with its native write slab, and a recv queue - and in
    /// incremental mode a registered buffer ring plus a gid, which is capped, so an idle
    /// connection at the cap converts directly into shed accepts.
    ///
    /// Enforced on the reactor's ticker, so the granularity is the tick (~250 ms) and a connection
    /// closes at the first tick after its deadline rather than exactly on it.
    /// </summary>
    /// <remarks>
    /// The clock runs only while a read is parked with nothing buffered, so a handler busy answering
    /// a request is never timed out, and only the peer's bytes restart it: a protocol where only the
    /// server talks has to hear from its client within this (a websocket pong counts), or set 0. It
    /// also bounds how long a peer has to close after its handler returns.
    /// </remarks>
    public int ReadTimeoutMs { get; init; } = 60_000;

    /// <summary>
    /// Close a connection whose flush has been in flight for this long. 0 disables.
    ///
    /// What it defends: a peer that stops reading. Its window shuts, the socket send buffer fills,
    /// and the SEND never completes - so <c>FlushAsync</c> parks forever, holding the connection,
    /// its slab and the handler's state. TCP will not end it either: a zero window is legitimate
    /// and a peer can hold one indefinitely. Nothing else in the stack bounds this.
    /// </summary>
    /// <remarks>
    /// This is the deadline for the WHOLE flush, not for progress within it, because MSG_WAITALL
    /// (the default - see <see cref="TcpConnection.SendOpFlags"/>) coalesces a flush into a single
    /// completion: there is no per-chunk signal to measure progress against. So set it against the
    /// slowest legitimate full response, not against a stall - a large body over a slow link is
    /// the false positive to watch for.
    ///
    /// It is deliberately not folded into <see cref="ReadTimeoutMs"/>: a peer that keeps SENDING
    /// while it has stopped READING restarts the read clock on every inbound completion, so it
    /// never fires while that connection's send is wedged. Duplex protocols - a websocket written
    /// from a background task is the reported case - need this clock and are not covered by the
    /// other one.
    /// </remarks>
    public int SendTimeoutMs { get; init; } = 60_000;
}
