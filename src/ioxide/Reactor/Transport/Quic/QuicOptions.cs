namespace ioxide;

public sealed record QuicOptions
{
    public ushort Port { get; init; } = 443;

    /// <summary>
    /// Length of the CIDs this endpoint mints. Short-header packets carry no CID length on the
    /// wire, so the demux slices exactly this many bytes - every locally-issued CID must use it.
    /// </summary>
    public int LocalCidLength { get; init; } = 8;

    /// <summary>
    /// How a datagram reaches the reactor owning its connection when several share the port.
    /// See <see cref="QuicRouting"/> for the measured trade.
    /// </summary>
    public QuicRouting Routing { get; init; } = QuicRouting.Forward;

    /// <summary>
    /// Under <see cref="QuicRouting.Forward"/>, claim a migrated client's new address so the kernel
    /// delivers to its owner directly and forwarding stops. One descriptor per migrated connection.
    /// </summary>
    public bool PinMigratedPeers { get; init; } = true;

    public QuicConnectionFactory? ConnectionFactory { get; init; }

    /// <summary>
    /// Close a connection whose peer has sent nothing for this long. 0 disables. While a response is
    /// owed, the engine keeps the peer answering (ioxide.ngtcp2 sends keep-alive PINGs), so a slow
    /// handler is not timed out.
    /// </summary>
    public int ReadTimeoutMs { get; init; } = 60_000;

    /// <summary>
    /// Response bytes a connection may hold unacknowledged before a response waits for acks, so
    /// memory per connection stays near this whatever the response size. Floored at 256 KiB.
    /// </summary>
    public long SendRetentionBytes { get; init; } = 16L << 20;

    /// <summary>
    /// Where the connection is closed instead: a producer that keeps sending past the wait and
    /// reaches this is not going to stop. A buffered HTTP/3 response is handed over whole, so the
    /// buffered responses in flight on one connection must fit under it. Never below
    /// <see cref="SendRetentionBytes"/>.
    /// </summary>
    public long SendRetentionCeilingBytes { get; init; } = 32L << 20;
}

/// <summary>
/// Invoked on the reactor thread for a long-header packet whose DCID is unknown - i.e. a new
/// connection attempt. Return the engine-backed connection to adopt it, or null to drop the packet.
/// </summary>
public delegate QuicConnection? QuicConnectionFactory(Reactor reactor, in UdpDatagram datagram, in QuicCid dcid);
