namespace ioxide;

/// <summary>
/// Client-side QUIC: connections this reactor OPENS, as opposed to the ones it accepts.
///
/// They run on the reactor that opened them, which is the whole point - a handler that awaits an
/// outbound request is resumed inline on its own reactor thread, with no synchronization context
/// and no cross-thread handoff.
///
/// Two shapes, one mechanism:
///
///   proxy      - the app already serves QUIC, so outbound connections share the configured QUIC
///                socket and route back through the same DCID demux. Nothing extra is opened.
///   standalone - no <see cref="ServerConfig.Quic"/> at all. The first outbound connect opens a
///                client UDP socket on an EPHEMERAL port (the kernel picks it), arms it on this
///                reactor's ring, and joins the same demux. Being a client requires no listener,
///                no fixed port and no connection factory.
///
/// The one requirement that makes routing work either way: the connection ID the client asks the
/// peer to address it by must be exactly <see cref="QuicLocalCidLength"/> bytes, because
/// short-header packets carry no CID length on the wire and the demux slices that many.
/// </summary>
public sealed unsafe partial class Reactor
{
    // Index into _udpFds of the socket outbound connections use: the configured QUIC socket in the
    // proxy shape, a lazily opened ephemeral one in the standalone shape. -1 = not resolved yet.
    private int _quicClientSocketIndex = -1;

    /// <summary>CID length a client with no QuicOptions mints - 8 bytes, matching the demux slice.</summary>
    private const int QuicClientDefaultCidLength = 8;

    /// <summary>Idle eviction for a client-only reactor, which has no QuicOptions to read it from.</summary>
    private const int QuicClientDefaultIdleMs = 30_000;

    /// <summary>
    /// Make this reactor able to open outbound QUIC connections and return the socket they send
    /// from - a dedicated one on an ephemeral port, opened on first use. Reactor thread only.
    /// Idempotent.
    /// </summary>
    public int QuicEnsureClientTransport()
    {
        if (_quicClientSocketIndex >= 0)
        {
            return _udpFds[_quicClientSocketIndex];
        }

        // Always a dedicated socket, even when this reactor also SERVES QUIC. Sharing the serving
        // socket looks natural - one fd, replies demux by CID like everything else - but the
        // serving port is SO_REUSEPORT across reactors, so an upstream's replies hash by 4-tuple
        // over ALL reactors' sockets and land on ones that have never heard of the connection.
        // With N reactors the handshake then times out (N-1)/N of the time. A per-reactor
        // ephemeral port keeps the reply path deterministic, because only this reactor owns it.
        _quicClientSocketIndex = OpenClientUdpSocket();
        if (_quicOptions is null)
        {
            AddTicker(QuicSweep);   // InitQuic never ran; serving reactors registered it there
        }
        return _udpFds[_quicClientSocketIndex];
    }

    /// <summary>The socket outbound connections send from, or -1 before the first connect.</summary>
    public int QuicSocketFd => _quicClientSocketIndex >= 0 ? _udpFds[_quicClientSocketIndex] : -1;

    /// <summary>The local port outbound connections send from (ephemeral when standalone).</summary>
    public ushort QuicLocalPort => _quicClientSocketIndex >= 0 ? _udpFdPorts[_quicClientSocketIndex] : (ushort)0;

    /// <summary>CID length this reactor's demux slices - a client's own CID must match it.</summary>
    public int QuicLocalCidLength => _quicOptions?.LocalCidLength ?? QuicClientDefaultCidLength;

    // Idle timeout for the sweep, which now runs for client-only reactors too.
    private int QuicIdleTimeoutMs => _quicOptions?.IdleTimeoutMs ?? QuicClientDefaultIdleMs;

    /// <summary>
    /// Adopt an outgoing connection the engine binding just created: route its replies by
    /// <paramref name="localCid"/>, join the timer/eviction sweeps, and take the transport's
    /// reference. Reactor thread only.
    /// </summary>
    /// <param name="connection">The engine-backed connection, already constructed.</param>
    /// <param name="localCid">The CID the peer will address us by; must be QuicLocalCidLength bytes.</param>
    /// <param name="peerAddr">Native sockaddr of the peer, owned by the connection from here on.</param>
    /// <param name="peerAddrLen">Its length.</param>
    public void QuicAdoptClient(QuicConnection connection, ReadOnlySpan<byte> localCid,
        nint peerAddr, int peerAddrLen)
    {
        if (localCid.Length != QuicLocalCidLength)
        {
            throw new ArgumentException(
                $"client CID must be {QuicLocalCidLength} bytes to match this reactor's demux, got {localCid.Length}.",
                nameof(localCid));
        }

        int socketFd = QuicEnsureClientTransport();

        connection.Reactor     = this;
        connection.SocketFd    = socketFd;
        connection.PeerAddr    = peerAddr;
        connection.PeerAddrLen = peerAddrLen;
        connection.LastSeenMs  = Environment.TickCount64;

        var cid = new QuicCid(localCid);
        connection.Cids.Add(cid);
        _quicConns[cid] = connection;
        _quicConnSet.Add(connection);

        // Two owners, like an accepted connection: this transport, and the caller that opened it.
        connection.InitRefs();
        QuicArmTimer(connection);
    }
}
