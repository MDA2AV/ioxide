using System.Net;

namespace ioxide;

/// <summary>
/// How a connection's write buffer absorbs a response larger than <see cref="TcpOptions.WriteSlabSize"/>.
/// </summary>
public enum WriteOverflowStrategy
{
    /// <summary>Grow the single contiguous slab (realloc + copy); the flush stays one SEND.</summary>
    Grow,

    /// <summary>Chain the connection's own segments and flush them with one vectored SENDMSG (no realloc copies).</summary>
    Segmented,
}

/// <summary>The TCP side of <see cref="ServerConfig"/>: listeners, connection pool, and the write path
/// (recv buffering is reactor machinery - see the buffer-ring knobs on <see cref="ServerConfig"/>).</summary>
public sealed record TcpOptions
{
    /// <summary>
    /// The port every reactor listens on. Each listener sets SO_REUSEPORT so the reactors can share it, and the kernel
    /// can't tell them from another process: a second server of the same user on this port, or on one of
    /// <see cref="ExtraPorts"/>, starts without an error and takes a share of the new connections. A restart with no
    /// downtime relies on that; a deploy that must not overlap stops the old process first. Another user is refused.
    /// </summary>
    public ushort Port { get; init; } = 8080;

    /// <summary>
    /// Additional listener ports (every reactor binds each one). Connections carry the port they
    /// arrived on in <see cref="TcpConnection.ListenerPort"/>, so one handler can serve several
    /// entry points (e.g. plaintext + TLS).
    /// </summary>
    public ushort[] ExtraPorts { get; init; } = [];

    /// <summary>
    /// The address the listeners bind, for <see cref="Port"/> and <see cref="ExtraPorts"/> alike. Null, the default, is
    /// every interface: 0.0.0.0, or :: under <see cref="ServerConfig.DualStack"/>. An address decides the family itself
    /// and DualStack doesn't apply; :: also takes IPv4-mapped peers.
    /// </summary>
    public IPAddress? Address { get; init; }

    /// <summary>listen() backlog per SO_REUSEPORT listener - the accept-queue depth for connection bursts.</summary>
    public int ListenBacklog { get; init; } = 1024;

    // Per-connection write slab + connection pool cap.
    public int WriteSlabSize { get; init; } = 16 * 1024;
    public int PoolMax       { get; init; } = 1024;

    // How a response larger than WriteSlabSize is buffered: grow the slab (default) or chain the
    // connection's own segments, flushed with one vectored SENDMSG.
    public WriteOverflowStrategy WriteOverflow { get; init; } = WriteOverflowStrategy.Grow;

    // Inject IORING_OP_SEND_ZC (zero-copy send) for the response path instead of IORING_OP_SEND.
    // Trades the in-kernel payload copy for page-pinning plus a second (F_NOTIF) completion per send,
    // so it only pays off for large responses - leave off for small-payload workloads. The sender is
    // chosen once per connection at accept; kTLS connections always fall back to plain SEND (the
    // kernel re-buffers to encrypt, so zero-copy buys nothing there).
    public bool ZeroCopySend { get; init; } = false;

    /// <summary>
    /// Send with MSG_WAITALL (the default): the kernel carries a short send on itself, so a flush
    /// completes as one CQE. Off, a short send completes as it is and the reactor submits the rest,
    /// which costs a completion and a submit per short send. Bound per connection at accept
    /// (<see cref="TcpConnection.SendOpFlags"/>); the kTLS handoff turns it off for its connection
    /// either way, since kTLS rejects the flag.
    /// </summary>
    public bool SendWaitAll { get; init; } = true;

    // Per-connection SPSC recv queue depth (power of two), about 24 bytes a slot. Each queued delivery
    // holds one of the reactor's recv buffers until the handler reads it, so in shared mode one connection
    // can hold this many of RecvSlots. Overflow drops the delivery that did not fit and closes the
    // connection, which its readers report as an error (TcpConnection.RecvOverflowed). The queue is
    // sized up front for every connection, pooled ones included, so the default stays small; raise it
    // for a handler that lets its peer get further ahead.
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
    /// a request is never timed out. Bytes in either direction restart it, and a flush in flight
    /// holds it - <see cref="SendTimeoutMs"/> governs that. A protocol that keeps a read parked
    /// while its handlers work, like HTTP/2's frame loop, is bounded as before: a response slower
    /// than this, to a peer that sends nothing meanwhile, is cut. It also bounds how long a peer
    /// has to close after its handler returns.
    /// </remarks>
    public int ReadTimeoutMs { get; init; } = 60_000;

    /// <summary>
    /// Close a connection whose flush has been in flight for this long, or whose peer has left sent data
    /// unacknowledged, or its window shut, for this long. 0 disables both.
    ///
    /// What it defends: a peer that stops reading. Its window shuts, the socket send buffer fills,
    /// and the SEND never completes - so <c>FlushAsync</c> parks forever, holding the connection,
    /// its slab and the handler's state. TCP will not end it either: a zero window is legitimate
    /// and a peer can hold one indefinitely. Nothing else in the stack bounds this.
    /// </summary>
    /// <remarks>
    /// This is the deadline for the WHOLE flush, not for progress within it, because MSG_WAITALL
    /// (the default - see <see cref="SendWaitAll"/>) coalesces a flush into a single completion:
    /// there is no per-chunk signal to measure progress against. With it off the clock still starts
    /// once per flush, not at each short send. So set it against the slowest legitimate full
    /// response, not against a stall - a large body over a slow link is the false positive to watch
    /// for.
    ///
    /// It is deliberately not folded into <see cref="ReadTimeoutMs"/>: a peer that keeps SENDING
    /// while it has stopped READING restarts the read clock on every inbound completion, so it
    /// never fires while that connection's send is wedged. Duplex protocols - a websocket written
    /// from a background task is the reported case - need this clock and are not covered by the
    /// other one.
    ///
    /// It also bounds a flush still draining when the peer closes: that connection is held, fd and
    /// slab, until its send completes, exactly like a live one - so with 0 nothing bounds that either.
    ///
    /// The listeners also carry this value as TCP_USER_TIMEOUT, which accepted connections inherit: the
    /// kernel aborts a connection whose peer has left sent data unacknowledged, or kept its window shut
    /// with data waiting, for that long. That covers two cases the flush deadline can't see. A stream of
    /// small flushes completes every one of them into the send buffer, so a peer that stopped reading,
    /// or vanished, would hold the connection until that buffer filled, or for TCP's own retries, about
    /// 15 minutes. And with <see cref="ZeroCopySend"/> a send completes only once the kernel lets go of
    /// the slab, which the sweep's shutdown doesn't make it do. The cost: a peer whose network drops for
    /// longer than this while data is in flight is cut, and what was flushed but not yet sent is lost,
    /// as when the flush deadline cuts a connection.
    /// </remarks>
    public int SendTimeoutMs { get; init; } = 60_000;

    /// <summary>
    /// Let a busy reactor give connections to one that is not, among those sharing the <see cref="ServerConfig"/>. Off by
    /// default.
    ///
    /// The kernel spreads connections over the reactors as they connect, before any of them has asked for anything. When
    /// the busy ones happen to be on a few reactors, the others' cores stay unused: with two of four reactors' connections
    /// silent, a server does half of what it could. With this on, the reactors look at their loads together, every
    /// <see cref="RebalanceIntervalMs"/>: each reads how busy it was over the same tick (~250 ms), on a CPU or kept from
    /// waiting for completions. The busiest is then paired with the idlest, the next busiest with the next idlest, and so on,
    /// while the one is busy three quarters or more and the other 30 points less, and each gives its taker connections worth
    /// half the difference, and no more than that share of them. While a look pairs anyone the next follows three ticks
    /// later, and spreading one reactor's load over N takes about log2(N) of those. A connection that alone keeps a reactor
    /// busy stays: it can't be split. Nothing moves between reactors that are all busy, however unevenly.
    /// </summary>
    /// <remarks>
    /// A connection moves as TCP has it, whatever protocol is on it, and the peer notices nothing: while a read of its
    /// handler's waits, everything received has been handed back and nothing is being sent. So what a handler may no longer
    /// do is take it for granted that it resumes on the same reactor after a read, or after a flush that a read waits
    /// beside (and an HTTP/2 request handler, whose connection reads beside it, after any wait on its request or response):
    /// <list type="bullet">
    /// <item>What belongs to a reactor (a pool, a cache, the <c>Reactor</c> the handler was called with, which is the one
    /// the connection was accepted on) is taken from <see cref="Reactor.Current"/> or
    /// <see cref="TcpConnection.Reactor"/> afterwards, not kept across it.</item>
    /// <item>A handler that has to keep it, through a transaction over several reads say, sets
    /// <see cref="TcpConnection.Pinned"/> meanwhile.</item>
    /// <item>A connection that something other than its handler flushes while a read of it waits, as a broadcast to its
    /// websocket does, or a timer of the reactor it was accepted on, has to be pinned, or flushed from the reactor it is on
    /// (<see cref="TcpConnection.Reactor"/>): a flush asked for anywhere else while the connection is between two reactors
    /// can get lost. That flush never completes, the connection can't be written to again, and only its peer or
    /// <see cref="SendTimeoutMs"/> ends it. One that its own handler flushes, between its reads, on whichever thread, is
    /// safe. So are ioxide's HTTP/2 stacks, given the connection or one of ioxide's two pipes over it, and its TLS pipes
    /// where BoringSSL encrypts: they take their flushes to the connection's reactor first. Over a pipe of another kind,
    /// such as an <c>SslStream</c>'s, an HTTP/2 stack stays on the reactor it began on, and its connection has to be
    /// pinned.</item>
    /// </list>
    /// A TLS handshake, and a connection served by Kestrel, stay where they are.
    ///
    /// Incremental mode has one thing more: a connection only moves to a reactor with a group id left
    /// (<see cref="IncrementalOptions.MaxConnections"/>).
    ///
    /// What it can't see: a reactor goes by its own thread, so one whose CPU is shared, and that waits in a queue for it
    /// after a completion has come, reads less busy than it is. A connection is weighed by the time its recv completions
    /// take, so what its handler does after awaiting something else isn't in its weight. One whose handler is at work for
    /// more than 2 s in one go stays.
    /// </remarks>
    public bool Rebalance { get; init; } = false;

    /// <summary>
    /// How often, with <see cref="Rebalance"/>, the reactors look at their loads together, in milliseconds: in whole ticks of
    /// ~250 ms, three at the least. A minute by default, for a server whose load takes far longer than that to go uneven.
    /// Each look reads the two ticks before it; between looks a reactor pays nothing for any of this. A look that pairs
    /// reactors has the next follow it three ticks later, until the loads are even. A benchmark that changes the load every
    /// few seconds wants a short interval: with 750 ms a reactor's load is spread over the others in two seconds or so.
    /// </summary>
    public int RebalanceIntervalMs { get; init; } = 60_000;
}
