using System.Runtime.InteropServices;
using ioxide;

namespace ioxide.ngtcp2;

/// <summary>
/// ngtcp2-backed QUIC engine, CLIENT side: holds the picotls client context and mints outgoing
/// connections. One engine per process (or per ALPN); connections it creates are adopted by a
/// reactor and then behave exactly like accepted ones - same <see cref="QuicConnection"/> read
/// surface, same engine callbacks.
///
/// <code>
/// using var engine = new QuicClientEngine("h3");
/// QuicEngineConnection connection = engine.Connect(reactor, "127.0.0.1", 8443, serverName: "localhost");
/// </code>
/// </summary>
public sealed unsafe class QuicClientEngine : IDisposable
{
    private nint _engine;   // iq_client_engine*

    /// <summary>The single ALPN this engine offers (h3 for HTTP/3).</summary>
    public string Alpn { get; }

    public QuicClientEngine(string alpn = "h3")
    {
        Ngtcp2.RequireAbi();

        Alpn = alpn;

        // The same callback table the server engine registers: the shim now routes both directions
        // through the connection's own copy, so client connections get close/ack/handshake events
        // too (without them, send-retention would never be freed).
        var callbacks = new Ngtcp2.Callbacks
        {
            StructSize = (nuint)sizeof(Ngtcp2.Callbacks),
            OnStreamData         = &QuicEngineConnection.CbStreamData,
            OnStreamClose        = &QuicEngineConnection.CbStreamClose,
            OnHandshakeCompleted = &QuicEngineConnection.CbHandshakeCompleted,
            OnNewCid             = null,   // client CIDs are not routed by the reactor
            OnRetireCid          = null,
            OnStreamReset        = &QuicEngineConnection.CbStreamReset,
            OnStreamStopSending  = &QuicEngineConnection.CbStreamStopSending,
            OnAckedStreamData    = &QuicEngineConnection.CbAckedStreamData,
        };

        // No certificate: the two nulls are what "this client presents nothing" looks like.
        _engine = Ngtcp2.iq_client_engine_new_mtls(alpn, null, null, callbacks);
        if (_engine == 0)
        {
            throw new InvalidOperationException("ioxide.ngtcp2: client engine init failed");
        }
    }

    /// <summary>
    /// Open a QUIC connection to <paramref name="ipv4"/>:<paramref name="port"/> and adopt it on
    /// <paramref name="reactor"/>: the handshake rides that reactor's ring, replies route back by
    /// connection ID, and the returned connection's read surface is awaitable straight away.
    /// Reactor thread only. Needs no server: if the app serves QUIC the connection shares that
    /// socket, otherwise the reactor opens one on an ephemeral port for outbound use.
    /// </summary>
    public QuicEngineConnection Connect(Reactor reactor, string ipv4, ushort port, string serverName)
    {
        reactor.QuicEnsureClientTransport();   // QuicLocalPort is 0 until the socket is open

        // Peer sockaddr, owned by the connection for its lifetime (ngtcp2 keeps the pointer).
        nint peerAddr = (nint)NativeMemory.AllocZeroed(128);
        int peerAddrLen = FillSockaddrIn(peerAddr, ipv4, port);

        int cidLength = reactor.QuicLocalCidLength;
        Span<byte> localCid = stackalloc byte[QuicCid.MaxLength];

        var connection = new QuicEngineConnection(this);
        if (!connection.TryConnect(_engine, reactor, reactor.QuicLocalPort,
                peerAddr, peerAddrLen, serverName, Alpn, cidLength, localCid))
        {
            NativeMemory.Free((void*)peerAddr);
            throw new InvalidOperationException("ioxide.ngtcp2: client connect failed");
        }

        reactor.QuicAdoptClient(connection, localCid[..cidLength], peerAddr, peerAddrLen);
        connection.Pump();   // the Initial flight leaves now, not on some later wake
        return connection;
    }

    // "ipv4:port" into a sockaddr_in at a native block; returns its length.
    private static int FillSockaddrIn(nint destination, string ipv4, ushort port)
    {
        if (!System.Net.IPAddress.TryParse(ipv4, out System.Net.IPAddress? address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new ArgumentException($"'{ipv4}' is not an IPv4 literal.", nameof(ipv4));
        }

        var sockaddr = new Span<byte>((void*)destination, 16);
        sockaddr.Clear();
        sockaddr[0] = 2;                     // AF_INET (little-endian: family low byte)
        sockaddr[2] = (byte)(port >> 8);     // sin_port, network byte order
        sockaddr[3] = (byte)(port & 0xff);
        address.TryWriteBytes(sockaddr[4..], out _);
        return 16;
    }

    public void Dispose()
    {
        if (_engine != 0)
        {
            Ngtcp2.iq_client_engine_free(_engine);
            _engine = 0;
        }
    }
}
