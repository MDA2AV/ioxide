namespace ioxide;

/// <summary>
/// All server tunables; override via object initializer. Engine-wide knobs live here; everything
/// transport-specific is grouped: <see cref="Tcp"/> (listeners, buffer rings, write path),
/// <see cref="Udp"/> (raw datagram sockets), <see cref="Quic"/> (the QUIC transport, which binds
/// its own UDP port).
/// </summary>
public sealed record ServerConfig
{
    public int ReactorCount { get; init; } = 12;

    // io_uring SQ/CQ depth.
    public uint RingEntries { get; init; } = 8192;

    /// <summary>
    /// Slots each reactor's table of in-flight ring operations starts with: every timer, and every
    /// socket or file operation of the pg, redis, HTTP and file clients, holds one until it
    /// completes. The table doubles when it runs out, so this only sets where that first happens.
    /// </summary>
    public int OpSlots { get; init; } = 4096;

    /// <summary>
    /// Bind listeners as dual-stack IPv6 (AF_INET6 on :: with IPV6_V6ONLY=0) so one socket accepts both
    /// IPv6 and IPv4-mapped clients. When false (default) listeners are IPv4-only (AF_INET on 0.0.0.0).
    /// Applies to TCP listeners and UDP sockets alike.
    /// </summary>
    public bool DualStack { get; init; } = false;

    // --- reactor recv machinery: io_uring provided-buffer rings, registered per reactor at
    //     startup (TCP recv draws on them; UDP has its own ring, sized by UdpOptions.RecvSlots). ---

    // Shared buffer ring - the default recv mode, used when Incremental is null.
    public int RecvBufferSize { get; init; } = 32 * 1024;
    public int RecvSlots      { get; init; } = 4096;

    /// <summary>
    /// Per-connection buffer rings (IOU_PBUF_RING_INC, kernel 6.12+): setting this IS enabling
    /// the mode - the reactor runs its incremental loop variant and the shared-ring knobs above
    /// go unused. Null (default) = shared ring.
    /// </summary>
    public IncrementalOptions? Incremental { get; init; }

    /// <summary>
    /// The TCP transport: listeners, connection pool, and the write path. Defaults to an enabled
    /// listener on <see cref="TcpOptions.Port"/>; set it to <c>null</c> to open no TCP listener at
    /// all, which is what a QUIC-only server wants - otherwise the reactor binds 8080 regardless
    /// and inbound connections reach a <see cref="Reactor.TcpHandle"/> that was never set.
    /// </summary>
    public TcpOptions? Tcp { get; init; } = new();

    /// <summary>
    /// Raw UDP sockets (datagrams reach <see cref="Reactor.OnDatagram"/>). Null opens none, which
    /// is what a TCP-only server wants. QUIC binds its own port either way and falls back to the
    /// default <see cref="UdpOptions.RecvSlots"/> / <see cref="UdpOptions.Gro"/> when this is null -
    /// the same values it would get from an unset <see cref="UdpOptions"/>.
    /// </summary>
    public UdpOptions? Udp { get; init; } = new();

    /// <summary>
    /// Enable the QUIC transport (Reactor.Quic.cs). Its port is bound as a UDP socket
    /// automatically (no need to repeat it in <see cref="UdpOptions.Ports"/>); datagrams on that
    /// port are demultiplexed by connection ID instead of reaching <see cref="Reactor.OnDatagram"/>.
    /// </summary>
    public QuicOptions? Quic { get; init; }
}

/// <summary>
/// The incremental recv mode (kernel 6.12+): one small provided-buffer ring per connection, the
/// kernel appending successive recvs into the same buffer until it fills. Reserved native memory
/// ≈ MaxConnections × RecvSlots × RecvBufferSize × ReactorCount.
/// </summary>
public sealed record IncrementalOptions
{
    /// <summary>One buffer-group id per active connection; accepts past this are shed.</summary>
    public int MaxConnections { get; init; } = 4096;

    /// <summary>Buffers per connection ring.</summary>
    public int RecvSlots { get; init; } = 16;

    /// <summary>Bytes per buffer - the kernel appends into it across recvs.</summary>
    public int RecvBufferSize { get; init; } = 4096;
}
