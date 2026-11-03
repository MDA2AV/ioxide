namespace ioxide;

/// <summary>The UDP side of <see cref="ServerConfig"/>: raw datagram sockets (QUIC binds its own
/// port through <see cref="ServerConfig.Quic"/> and only shares these tunables).</summary>
public sealed record UdpOptions
{
    /// <summary>
    /// UDP ports to bind (every reactor binds each one via SO_REUSEPORT, like the TCP listeners).
    /// Datagrams are delivered to <see cref="Reactor.OnDatagram"/> on the reactor thread. Empty
    /// (default) means no UDP sockets are opened.
    /// </summary>
    public ushort[] Ports { get; init; } = [];

    /// <summary>
    /// Depth of the shared UDP provided-buffer ring (rounded up to a power of two). One multishot
    /// RECVMSG per socket draws buffers from this ring; each buffer pins ~64 KiB (a full GRO train
    /// plus the packed address/control header) and returns as soon as its datagram is handled, so
    /// the depth bounds how many datagrams can be in flight across all UDP sockets at once.
    /// 1 to 32768, the most buffers a kernel buffer ring holds.
    /// </summary>
    public int RecvSlots { get; init; } = 16;

    /// <summary>
    /// Receive and send buffer requested on every UDP socket, in bytes.
    ///
    /// QUIC bursts overflow the stock ~208 KiB while the reactor drains a batch, so the default
    /// asks for considerably more - roughly what other QUIC servers ask for. It is a REQUEST: the
    /// kernel silently clamps it to <c>net.core.rmem_max</c> / <c>wmem_max</c> rather than failing,
    /// and on a stock Linux box those are 212,992 bytes, so the default is clamped to about a
    /// fortieth of itself and datagrams are dropped under load. ioxide reads the granted size back
    /// and says so once at startup when that happens.
    ///
    /// Raising that ceiling is not automatically an improvement. Measured on the h3 benchmark here,
    /// granting the full 8 MiB cost about 45% of throughput at saturation: the drops stopped and a
    /// deep standing queue replaced them, so peers timed out and retransmitted instead. A shallow
    /// buffer drops early, which is the signal congestion control is built to read. Treat both the
    /// ceiling and this value as things to measure on the deployment rather than to maximise.
    /// </summary>
    public int SocketBufferBytes { get; init; } = 8 * 1024 * 1024;

    /// <summary>
    /// Enable UDP_GRO on receive: the kernel coalesces a burst of equal-size datagrams from one
    /// peer into a single completion, and <see cref="UdpDatagram.GroSegmentSize"/> carries the
    /// segment size for the handler to split on.
    /// </summary>
    public bool Gro { get; init; } = true;
}
