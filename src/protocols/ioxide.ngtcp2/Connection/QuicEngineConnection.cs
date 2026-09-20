using System.Diagnostics;
using System.Runtime.InteropServices;
using ioxide;

namespace ioxide.ngtcp2;

/// <summary>
/// A live ngtcp2 server connection, bridging the reactor's QUIC transport to the native engine.
/// Datagrams routed by CID arrive at <see cref="OnDatagram(System.ReadOnlySpan{byte}, byte)"/> and are fed to ngtcp2; the engine's
/// output is flushed back through the transport's <c>Send</c>; loss/idle deadlines ride the reactor
/// ticker via <see cref="GetNextTimeout"/> / <see cref="OnTimer"/>. Everything runs on the owning
/// reactor thread, so the whole connection - transport half and engine half - is single-threaded.
///
/// Application bytes flow through the read surface on <see cref="QuicConnection"/>: each decrypted
/// stream event is copied into the recv queue during iq_conn_read, and the IVTS fires ONCE after
/// the read returns, so the resumed handler (see <see cref="Reactor.QuicHandle"/>) can never
/// re-enter the engine mid-read. Replies go out via <see cref="SendStream"/>.
/// </summary>
public unsafe partial class QuicEngineConnection : QuicConnection
{
    // sockaddr cap the transport uses for its peer-address blocks; large enough for sockaddr_in6.
    private const int PeerAddrCap = 128;

    private readonly QuicEngine? _engine;              // server connections
    private readonly QuicClientEngine? _clientEngine;   // client connections
    private nint _conn;                        // iq_conn*, null once closed

    /// <summary>
    /// The verified client certificate's subject, or null when the peer offered none - which is
    /// possible whenever the engine was built with a client CA but not
    /// <c>requireClientCertificate</c>. Empty until the handshake completes.
    ///
    /// Read it to decide what an authenticated peer may do: a server that can only answer "some
    /// valid certificate" has a gate rather than an identity.
    /// </summary>
    /// <remarks>
    /// For people to read - logs, audit trails, errors. Do not authorize on a substring of it: the
    /// format escapes a literal '/' in an attribute as "\/", which still contains '/', so a client
    /// whose organisation is <c>Acme\/CN=admin.internal</c> satisfies a
    /// <c>Contains("/CN=admin.internal")</c> check while being a different principal.
    /// <see cref="PeerCommonName"/> is the value to compare instead.
    ///
    /// Null also when the DN does not fit the 1024 bytes the shim records, which is a refusal
    /// rather than an omission: a truncated DN is plausible, comparable, and can equal a DIFFERENT
    /// principal's prefix, so no name is reported instead of a partial one. Nothing here ever
    /// hands back a shortened identity.
    /// </remarks>
    public string? PeerSubject
    {
        get
        {
            if (_conn == 0)
            {
                return null;
            }

            Span<byte> buffer = stackalloc byte[1024];
            fixed (byte* p = buffer)
            {
                nuint written = Ngtcp2.iq_conn_peer_subject(_conn, p, (nuint)buffer.Length);
                return written == 0 ? null : System.Text.Encoding.UTF8.GetString(buffer[..(int)written]);
            }
        }
    }

    /// <summary>
    /// The common name of the validated client certificate, read from the DN structurally rather
    /// than parsed back out of <see cref="PeerSubject"/>, so no escaping convention sits between
    /// the certificate and the comparison. This is the value to authorize on - compare it whole,
    /// with <see cref="StringComparison.Ordinal"/>.
    ///
    /// Null when there was no validated certificate, when the subject carries no CN (legitimate:
    /// modern certificates identify by subjectAltName), when the CN is empty or contains an
    /// embedded NUL - a name built to be read differently by different consumers - or when it
    /// exceeds the 256 bytes recorded for it, which is four times RFC 5280's ub-common-name of 64.
    /// Every one of those is a refusal rather than an omission: the accessor never reports a name
    /// it had to shorten, because a prefix can belong to someone else.
    /// </summary>
    public string? PeerCommonName
    {
        get
        {
            if (_conn == 0)
            {
                return null;
            }

            Span<byte> buffer = stackalloc byte[256];
            fixed (byte* p = buffer)
            {
                nuint written = Ngtcp2.iq_conn_peer_cn(_conn, p, (nuint)buffer.Length);
                return written == 0 ? null : System.Text.Encoding.UTF8.GetString(buffer[..(int)written]);
            }
        }
    }
    private GCHandle _self;                    // stable void* user passed to the shim
    private bool _handshakeDone;
    private bool _closed;

    // Held directly (not via the base class) because the engine's get_new_connection_id callback
    // fires during iq_accept - before the transport wires the base Reactor/SocketFd/PeerAddr in.
    private Reactor _reactor = null!;
    private int _socketFd;

    // One reusable send scratch datagram (max QUIC payload); the engine writes at most one per call.
    private readonly byte[] _sendBuf = new byte[1452];

    // Set inside iq_conn_read: arms the once-per-read IVTS fire.
    private bool _recvEnqueued;

    // Why this connection must die, recorded from inside a native engine call - a full recv queue,
    // a callback that threw. It is a note rather than a teardown because freeing the conn from
    // within its own callback is a use-after-free: EndEngineCycle acts on it once ngtcp2's frames
    // have unwound. First reason wins; later ones are consequences of it.
    private string? _deferredFault;

    // Set when the handshake completes, raised after the engine call unwinds (firing it from
    // inside the shim callback would re-enter ngtcp2). Client connections depend on this: nothing
    // else wakes them until the peer sends stream data, and they must open their streams first.
    private bool _handshakeSignalPending;

    /// <summary>
    /// Raised once, on the reactor thread, after the handshake completes AND the engine call has
    /// unwound - so it is safe to open streams and send from here. Client connections use it to
    /// start their protocol setup; server connections are woken by the peer's request instead.
    /// </summary>
    public Action? HandshakeCompleted { get; set; }

    public QuicEngineConnection(QuicEngine engine)
    {
        _engine = engine;
        _maxSendRetention = engine.MaxSendRetentionBytes;
    }

    /// <summary>Client-side connection; <see cref="QuicClientEngine.Connect"/> builds these.</summary>
    public QuicEngineConnection(QuicClientEngine clientEngine)
    {
        _clientEngine = clientEngine;
        // Client request bodies are small; the default high-water is plenty and needs no knob.
    }

    /// <summary>Handshake finished; safe to open server-initiated streams and send.</summary>
    protected virtual void OnHandshakeCompleted() { }

    // ngtcp2 delivered decrypted stream bytes (mid-iq_conn_read; the span dies when it returns).
    // Copy-and-enqueue only - the wake happens once, after the read unwinds.
    private void OnStreamData(long streamId, ReadOnlySpan<byte> data, bool fin)
    {
        if (EnqueueStreamData(streamId, data, fin))
        {
            _recvEnqueued = true;
        }
        else
        {
            _deferredFault ??= "recv queue overflow";
        }
    }

    /// <summary>A stream ended (peer FIN/reset or local close).</summary>
    protected virtual void OnStreamClosed(long streamId, ulong appErrorCode) { }

    // Stream lifecycle -> the shared recv queue, ordered with the data that preceded it. All three
    // fire inside iq_conn_read/handle_expiry, so the once-per-read wake covers them.
    private void EnqueueLifecycle(long streamId, QuicStreamEvent kind, ulong appError)
    {
        if (EnqueueStreamEvent(streamId, kind, appError))
        {
            _recvEnqueued = true;
        }
        else
        {
            _deferredFault ??= "recv queue overflow";
        }
    }

    // The peer refuses our response (STOP_SENDING): stop feeding the stream. Retained chunks are
    // NOT freed here - ngtcp2 may still hold references until the stream closes.
    private void MarkOutStreamDead(long streamId)
    {
        if (_outStreams.TryGetValue(streamId, out OutStream? os))
        {
            os.Dead = true;
        }
    }

    // Monotonic nanosecond clock ngtcp2 wants; Stopwatch is monotonic, unlike wall time.
    private static ulong NowNs() => (ulong)(Stopwatch.GetTimestamp() * (1_000_000_000.0 / Stopwatch.Frequency));

    // struct sockaddr_in for 127.0.0.1:port (16 bytes): family AF_INET(2), port big-endian, addr.
    private static void FillSockaddrInLoopback(Span<byte> sa, ushort port)
    {
        sa.Clear();
        sa[0] = 2;                        // AF_INET (x86 little-endian family low byte)
        sa[2] = (byte)(port >> 8);        // sin_port, network byte order
        sa[3] = (byte)(port & 0xff);
        sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;   // 127.0.0.1
    }

    // --- transport-facing lifecycle (called by the QUIC demux / engine factory) ---------------

    // Adopt the connection: validate the client's first datagram and create the ngtcp2 conn. Runs
    // inside the factory, before the transport records the route; returns false to reject. reactor
    // and socketFd are captured here because engine callbacks can fire during iq_accept.
    //
    // The reactor's shard identity goes across too: it is stamped into the connection id the
    // server mints, which is what lets the kernel steer this connection's later datagrams back to
    // THIS reactor even after the client changes address. See Reactor.Udp.Steering.cs.
    internal bool TryAccept(nint enginePtr, Reactor reactor, in UdpDatagram datagram, Span<byte> scidOut, out int scidLen)
    {
        _reactor  = reactor;
        _socketFd = datagram.SocketFd;
        _self     = GCHandle.Alloc(this);
        scidLen = 0;

        // The server's own sockaddr for the ngtcp2 path. Milestone: IPv4 loopback on the bound
        // port - a real 16-byte sockaddr_in (ngtcp2 asserts addrlen fits its address union).
        Span<byte> local = stackalloc byte[16];
        FillSockaddrInLoopback(local, datagram.LocalPort);

        fixed (byte* pkt = datagram.Payload)
        fixed (byte* scid = scidOut)
        fixed (byte* loc = local)
        {
            _conn = Ngtcp2.iq_accept(
                enginePtr,
                loc, (nuint)local.Length,
                (void*)datagram.PeerAddr, (nuint)datagram.PeerAddrLen,
                pkt, (nuint)datagram.Payload.Length,
                NowNs(), (void*)GCHandle.ToIntPtr(_self),
                (uint)reactor.ShardIndex, (uint)reactor.ShardCount, scid);
        }

        if (_conn == 0)
        {
            _self.Free();
            return false;
        }
        scidLen = (int)_engine!.CidLength;
        return true;
    }

    /// <summary>
    /// Client-side creation: build the ngtcp2 connection toward <paramref name="remoteAddr"/> and
    /// report the connection ID we asked the peer to address us by, so the reactor can route the
    /// replies back here. The handshake itself starts on the first pump (the caller flushes).
    /// </summary>
    internal bool TryConnect(nint clientEnginePtr, Reactor reactor, int socketFd, ushort localPort,
        nint remoteAddr, int remoteAddrLen, string serverName, string alpn, int scidLen, Span<byte> scidOut)
    {
        _reactor  = reactor;
        _socketFd = socketFd;
        _self     = GCHandle.Alloc(this);

        Span<byte> local = stackalloc byte[16];
        FillSockaddrInLoopback(local, localPort);

        fixed (byte* loc = local)
        fixed (byte* scid = scidOut)
        {
            _conn = Ngtcp2.iq_client_connect(
                clientEnginePtr,
                loc, (nuint)local.Length,
                (byte*)remoteAddr, (nuint)remoteAddrLen,
                serverName, alpn,
                (nuint)scidLen, NowNs(), (void*)GCHandle.ToIntPtr(_self), scid);
        }

        if (_conn == 0)
        {
            _self.Free();
            return false;
        }
        return true;
    }

    /// <summary>Open a client-initiated bidirectional stream; the id, or negative when the peer's
    /// allowance is exhausted.</summary>
    public long OpenBidiStream() => _closed ? -1 : Ngtcp2.iq_client_open_bidi(_conn);

    /// <summary>Drive the handshake/egress once - the client calls this after connecting so the
    /// Initial packet goes out without waiting for an inbound datagram.</summary>
    public void Pump()
    {
        if (_closed)
        {
            return;
        }
        _inEngineCycle = true;
        try
        {
            FlushEgress();
        }
        finally
        {
            EndEngineCycle();
        }
    }

    // Single handshake-done funnel (the engine callback and the OnDatagram poll can both detect
    // it): record the negotiated ALPN, then fire the hook.
    private void HandshakeCompletedOnce()
    {
        _handshakeDone = true;
        _handshakeSignalPending = HandshakeCompleted is not null;

        Span<byte> alpn = stackalloc byte[64];
        fixed (byte* p = alpn)
        {
            nuint len = Ngtcp2.iq_conn_get_alpn(_conn, p, (nuint)alpn.Length);
            if (len > 0)
            {
                NegotiatedProtocol = System.Text.Encoding.ASCII.GetString(alpn[..(int)len]);
            }
        }

        OnHandshakeCompleted();
    }

    // The deferred handshake wake, raised after iq_conn_read / handle_expiry has fully unwound so
    // the callback can safely call back into the engine (open streams, send).
    internal void FireHandshakeSignal()
    {
        if (!_handshakeSignalPending)
        {
            return;
        }
        _handshakeSignalPending = false;
        HandshakeCompleted?.Invoke();
    }

    // The once-per-read wake: the engine is idle again, so the handler resuming inline (and
    // immediately calling SendStream) is safe.
    private void FireRecv()
    {
        if (_recvEnqueued)
        {
            _recvEnqueued = false;
            SignalDataArrived();
        }
    }

    // Teardown

    private void CloseFromEngine(int liberr)
    {
        // Draining and idle-close are normal lifecycle (the peer finished, or vanished and the
        // idle timer reaped the connection - every abandoned benchmark client ends this way);
        // only genuine protocol/engine errors are worth a log line.
        if (!IsQuietEnding(liberr))
        {
            Console.Error.WriteLine($"[ioxide.ngtcp2] connection closed: {Ngtcp2.StrError(liberr)}");
        }

        Teardown(WriteTransportFarewell(liberr));
    }

    /// <summary>
    /// Endings the peer must not be answered about: it has already sent its own CONNECTION_CLOSE
    /// (draining), we have already sent ours (closing), or it is simply gone and RFC 9000 wants
    /// the connection discarded silently (idle timeout).
    /// </summary>
    private static bool IsQuietEnding(int liberr)
    {
        // ngtcp2 codes are negative, but they reach here from both `rv` (negative) and constants
        // written positively at some call sites, so normalise before comparing.
        int e = liberr < 0 ? liberr : -liberr;
        return e == Ngtcp2.NGTCP2_ERR_DRAINING
            || e == Ngtcp2.NGTCP2_ERR_CLOSING
            || e == Ngtcp2.NGTCP2_ERR_IDLE_CLOSE;
    }

    /// <summary>
    /// Builds the CONNECTION_CLOSE for an engine-side death into <see cref="_sendBuf"/>, so the
    /// peer learns the connection is over now instead of waiting out its own idle timeout.
    /// Returns the byte count, or 0 when the peer is not to be told.
    /// </summary>
    private int WriteTransportFarewell(int liberr)
    {
        if (_conn == 0 || IsQuietEnding(liberr))
        {
            return 0;
        }

        fixed (byte* dest = _sendBuf)
        {
            nint written = Ngtcp2.iq_conn_close_liberr(_conn, liberr, dest, (nuint)_sendBuf.Length, NowNs());
            return (int)written > 0 ? (int)written : 0;
        }
    }

    /// <summary>
    /// The single way a connection ends. Three things have to happen, in this order and once: the
    /// peer hears why, the transport stops routing datagrams here, and the engine state is freed.
    /// Routing every death through one place is what keeps them from drifting apart.
    /// </summary>
    /// <param name="farewellLength">Bytes of CONNECTION_CLOSE waiting in <see cref="_sendBuf"/>;
    /// 0 to say nothing.</param>
    private void Teardown(int farewellLength)
    {
        // Anything this cycle coalesced goes out FIRST. QuicRemoveConnection below frees PeerAddr
        // and Send is a no-op without it, so a batch still sitting in _gsoBuf when we get there is
        // discarded - and a handler resumed inline by FireRecv runs inside the cycle, so its
        // response is exactly what is sitting there. That silently dropped the last response of a
        // graceful h3 shutdown: the peer saw only the CONNECTION_CLOSE. EndEngineCycle already
        // flushes before its own deferred teardown; this makes every path agree.
        FlushGso();

        if (farewellLength > 0)
        {
            Send(_sendBuf.AsSpan(0, farewellLength));   // last words: direct, unbatched
        }

        // Close the send gate before the transport wakes the handler (QuicRemoveConnection ->
        // MarkClosed resumes it inline): a farewell SendStream must not pump a dead conn.
        _closed = true;
        _reactor.QuicRemoveConnection(this);   // stop routing every CID to us
        Destroy();
    }

    // Idempotent per resource: callers may gate the send path (_closed) before getting here.
    private void Destroy()
    {
        _closed = true;
        foreach (OutStream os in _outStreams.Values)
        {
            while (os.Chunks.Count > 0)
            {
                (nint ptr, int len) = os.Chunks.Dequeue();
                NativeMemory.Free((void*)ptr);
                _outRetained -= len;
            }
        }
        _outStreams.Clear();
        _outPending.Clear();
        if (_conn != 0)
        {
            Ngtcp2.iq_conn_free(_conn);
            _conn = 0;
        }
        if (_self.IsAllocated)
        {
            _self.Free();
        }
    }
}
