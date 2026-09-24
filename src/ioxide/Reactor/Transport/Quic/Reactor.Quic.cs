using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// TryExtractDcid is the demux's packet parse: pure, and the first thing a hostile datagram meets.
// The unit suite exercises it directly rather than through a live connection.
[assembly: InternalsVisibleTo("Ioxide.Tests.Unit")]

namespace ioxide;

/// <summary>
/// QUIC transport: rides the UDP layer (Reactor.Udp.cs) on one dedicated port and demultiplexes
/// datagrams to logical connections by Destination TcpConnection ID (RFC 8999 version-independent
/// parse), since one UDP socket carries every connection - the fd-keyed TCP table cannot model
/// this. Packet protection and the handshake live in the engine subclass of
/// <see cref="QuicConnection"/>, produced by <see cref="QuicOptions.ConnectionFactory"/>; the
/// engine registers the CIDs it mints via <see cref="QuicRegisterCid"/> as the handshake retires
/// the client's initial DCID.
/// </summary>
public sealed unsafe partial class Reactor
{
    private QuicOptions? _quicOptions;
    private readonly Dictionary<QuicCid, QuicConnection> _quicConns = new();
    private readonly HashSet<QuicConnection> _quicConnSet = [];
    private readonly List<QuicConnection> _quicSweepScratch = [];

    private long _quicStaleDatagrams;

    /// <summary>
    /// Short-header datagrams naming a connection id that is addressed to THIS reactor and which it
    /// does not have: retired after a migration (ngtcp2 rotates ids when the path changes, so
    /// packets already in flight still carry the old one), long dead, or hostile.
    ///
    /// Ordinary, and not a routing problem - a migration produces a handful every time. Datagrams
    /// that belong to a DIFFERENT reactor are not counted here; they are forwarded to it, and
    /// counted by <see cref="QuicForwardsSent"/>.
    /// </summary>
    public long QuicStaleDatagrams => Volatile.Read(ref _quicStaleDatagrams);

    // No-op unless ServerConfig.Quic is set (the port itself is bound by OpenUdpSockets).
    private void InitQuic()
    {
        if (_config.Quic is not { } options)
        {
            return;
        }
        _quicOptions = options;
        QuicJoinFleet();   // so a datagram for another reactor's connection can reach it
        AddTicker(QuicSweep);
    }

    /// <summary>
    /// Un-coalesce GRO, then demux by DCID. UDP_GRO packs a burst from one 4-tuple into ONE recv:
    /// <c>Payload</c> is the whole train, <c>GroSegmentSize</c> the wire size of each datagram in
    /// it (0 = none); only the last segment may be shorter - the Math.Min.
    ///
    ///   Payload = 6040, GroSegmentSize = 1452:
    ///   [ 1452 ][ 1452 ][ 1452 ][ 1452 ][ 232 ]
    ///
    /// Split BEFORE CID routing: connections can share a 4-tuple, so adjacent segments can carry
    /// DIFFERENT DCIDs - routing the train by its first DCID feeds the wrong engine, which
    /// silently drops (peers stall). The bottom call is the no-train path (GroSegmentSize 0, or
    /// exactly one datagram - excluded by the strict &lt;).
    /// </summary>
    private void QuicDispatch(in UdpDatagram datagram)
    {
        if (datagram.GroSegmentSize > 0 && datagram.GroSegmentSize < datagram.Payload.Length)
        {
            int stride = datagram.GroSegmentSize;
            for (int off = 0; off < datagram.Payload.Length; off += stride)
            {
                int len = Math.Min(stride, datagram.Payload.Length - off);
                QuicDispatchDatagram(new UdpDatagram(datagram.SocketFd, datagram.LocalPort,
                    datagram.PeerAddr, datagram.PeerAddrLen,
                    datagram.Payload.Slice(off, len), 0, datagram.Tos));
            }
            return;
        }

        QuicDispatchDatagram(in datagram);
    }

    /// <summary>
    /// Route one datagram by DCID. The known-connection hot path runs two independent clocks:
    ///
    /// <c>LastSeenMs</c> is the coarse one - a "peer said something" stamp the 250 ms sweep
    /// compares against ReadTimeoutMs to garbage-collect vanished clients. Nothing else reads it.
    ///
    /// <c>QuicArmTimer</c> is the fine one, and it must run AFTER <c>OnDatagram</c>: that call
    /// (iq_conn_read) just rewrote the engine's deadlines - arriving ACKs cancelled retransmit
    /// timers and freed send-retention below the acked offset, and the handler may have resumed
    /// inline and sent, arming fresh PTO deadlines for THAT data. GetNextTimeout samples the
    /// settled state and folds it into the reactor-wide min that QuicFireDueTimers checks each
    /// loop pass.
    /// </summary>
    private void QuicDispatchDatagram(in UdpDatagram datagram)
    {
        // Reads only the cleartext prefix per RFC 8999
        if (!TryExtractDcid(datagram.Payload, QuicLocalCidLength, out QuicCid dcid, out bool longHeader))
        {
            return;   // not parseable as QUIC - drop
        }

        if (_quicConns.TryGetValue(dcid, out QuicConnection? conn))
        {
            conn.LastSeenMs = Environment.TickCount64;
            conn.OnDatagram(datagram.Payload, datagram.Tos, datagram.PeerAddr, datagram.PeerAddrLen);
            QuicArmTimer(conn);   // reads/handler sends (inline above) moved the engine deadline
            return;
        }

        if (!longHeader)
        {
            // A short header names a connection that must already exist, so reaching here means
            // this reactor cannot serve this datagram, for two very different reasons - told apart
            // only because a server-minted id carries its owner. The id is NOT ours: the datagram
            // reached the WRONG reactor, which is the routing failing, and is recoverable - hand it
            // to the reactor it names rather than dropping a live connection's traffic, see
            // Reactor.Quic.Forward.cs. The id IS ours: routing worked and the id is simply gone,
            // which is what the count below means (see QuicStaleDatagrams).
            if (QuicTryForward(in datagram, in dcid))
            {
                return;
            }

            _quicStaleDatagrams++;
            return;
        }

        // No factory (or no QuicOptions at all, on a client-only reactor): nothing is accepted here.
        QuicConnection? freshQuicConnection = _quicOptions?.ConnectionFactory?.Invoke(this, in datagram, in dcid);
        if (freshQuicConnection == null)
        {
            return;
        }

        freshQuicConnection.Reactor     = this;
        freshQuicConnection.SocketFd    = datagram.SocketFd;
        freshQuicConnection.PeerAddr    = (nint)NativeMemory.Alloc(UdpNameCap);
        freshQuicConnection.PeerAddrLen = datagram.PeerAddrLen;

        Buffer.MemoryCopy(
            (void*)datagram.PeerAddr,
            (void*)freshQuicConnection.PeerAddr,
            UdpNameCap,
            datagram.PeerAddrLen);

        freshQuicConnection.LastSeenMs = Environment.TickCount64;

        freshQuicConnection.Cids.Add(dcid);
        _quicConns[dcid] = freshQuicConnection;
        _quicConnSet.Add(freshQuicConnection);

        // Two owners: this transport (released in QuicRemoveConnection) and the handler. The
        // handler launches before the first datagram is fed - if the engine delivers stream data
        // right away, the sticky pending flag completes the handler's first ReadAsync.
        freshQuicConnection.InitRefs();
        if (QuicHandle is not null)
        {
            _ = RunQuicHandlerAsync(freshQuicConnection);
        }
        else
        {
            freshQuicConnection.DecRef();   // no handler configured: the transport stays the only owner
        }

        freshQuicConnection.OnDatagram(datagram.Payload, datagram.Tos, datagram.PeerAddr, datagram.PeerAddrLen);
        QuicArmTimer(freshQuicConnection);
    }

    // RFC 8999 (version-independent invariants): long header (bit 0x80) carries an explicit DCID
    // length at offset 5; short header carries the DCID bare at offset 1 with its length known
    // only to the endpoint that minted it (shortCidLen).
    internal static bool TryExtractDcid(ReadOnlySpan<byte> packet, int shortCidLen, out QuicCid dcid, out bool longHeader)
    {
        dcid = default;
        longHeader = false;

        if (packet.IsEmpty)
        {
            return false;
        }

        if ((packet[0] & 0x80) != 0)
        {
            longHeader = true;
            if (packet.Length < 6)
            {
                return false;
            }
            int len = packet[5];
            if (len == 0 || len > QuicCid.MaxLength || packet.Length < 6 + len)
            {
                // Both ends of the range are legal on the wire and neither can be one of ours, so
                // neither is routable. Zero matters more than 21 does: QuicEngine enforces a CID
                // length of 1..20, so nothing this server issues is ever empty - but an empty CID
                // is still a perfectly good dictionary key, so accepting it let the FIRST peer to
                // send one install a route that every later empty-CID packet, from any peer, was
                // then delivered into. Initial keys derive from the client's original DCID, so a
                // second peer sending an empty one derives the same keys: not a misdelivery but
                // two peers sharing one connection state, with replies going to whoever arrived
                // first. ngtcp2_accept does not stop it either - it skips its minimum-DCID guard
                // whenever a packet carries a token, and this server issues no tokens and checks
                // none, so one junk byte is enough.
                return false;
            }
            dcid = new QuicCid(packet.Slice(6, len));
            return true;
        }

        if (packet.Length < 1 + shortCidLen)
        {
            return false;
        }
        dcid = new QuicCid(packet.Slice(1, shortCidLen));
        return true;
    }

    /// <summary>
    /// Route future datagrams carrying <paramref name="cid"/> to <paramref name="conn"/>. The
    /// engine calls this for every CID it issues (NEW_CONNECTION_ID, handshake SCID). Reactor
    /// thread only.
    /// </summary>
    public void QuicRegisterCid(QuicConnection conn, in QuicCid cid)
    {
        _quicConns[cid] = conn;
        conn.Cids.Add(cid);
    }

    /// <summary>Stop routing <paramref name="cid"/> (RETIRE_CONNECTION_ID). Reactor thread only.</summary>
    public void QuicUnregisterCid(in QuicCid cid)
    {
        if (_quicConns.Remove(cid, out QuicConnection? conn))
        {
            conn.Cids.Remove(cid);
        }
    }

    /// <summary>
    /// Drop a connection entirely: every CID route, the sweep membership, and the transport-owned
    /// peer-address memory. The engine calls this once its CONNECTION_CLOSE/drain completes.
    /// Reactor thread only.
    /// </summary>
    public void QuicRemoveConnection(QuicConnection conn)
    {
        foreach (QuicCid cid in conn.Cids)
        {
            _quicConns.Remove(cid);
        }
        conn.Cids.Clear();

        // The set membership doubles as the "transport still owns a ref" flag, so a second call
        // (engine close racing the idle sweep) cannot double-release.
        if (_quicConnSet.Remove(conn))
        {
            QuicUnpinPeer(conn);   // give the descriptor back before the address it names is freed

            // Wake the handler with closed=1 first - it resumes inline, sees IsClosed, and releases
            // its own ref - then invalidate any awaiter that could outlive this life.
            conn.MarkClosed();
            conn.BumpGeneration();

            if (conn.PeerAddr != 0)
            {
                NativeMemory.Free((void*)conn.PeerAddr);
                conn.PeerAddr = 0;
            }

            conn.DecRef();
        }
    }

    // Ticker callback (~250 ms): evict quiet connections. Engine deadlines are fired by
    // QuicFireDueTimers at loop-pass granularity; this ticker's loop wake doubles as its floor.
    private void QuicSweep()
    {
        long now = Environment.TickCount64;
        int readMs = QuicReadTimeoutMs;

        _quicSweepScratch.Clear();
        _quicSweepScratch.AddRange(_quicConnSet);

        foreach (QuicConnection conn in _quicSweepScratch)
        {
            if (readMs > 0 && now - conn.LastSeenMs > readMs)
            {
                QuicRemoveConnection(conn);
                conn.OnEvicted(QuicEvictReason.ReadTimeout);
                continue;
            }

            // Claim a moved connection's new address, so its datagrams stop being forwarded.
            QuicPinPeer(conn);
        }
    }

    // Earliest engine deadline across live conns; long.MaxValue = none. Checked at the top of every
    // loop pass, so loss/PTO timers fire at completion-batch granularity (~RTT under load) instead
    // of the 250 ms ticker - a retransmit that waits 250 ms per loss makes storms self-sustaining.
    private long _quicNextTimeoutMs = long.MaxValue;

    private void QuicFireDueTimers()
    {
        if (_quicConnSet.Count == 0 || Environment.TickCount64 < _quicNextTimeoutMs)
        {
            return;
        }

        long now = Environment.TickCount64;
        long next = long.MaxValue;
        _quicSweepScratch.Clear();
        _quicSweepScratch.AddRange(_quicConnSet);
        foreach (QuicConnection conn in _quicSweepScratch)
        {
            // One connection's fault must not take the loop down with it. This runs bare in both
            // loop bodies and nothing above it catches, so an exception out of a protocol engine
            // would kill the reactor thread and every connection on it.
            //
            // The faulted connection is dropped rather than skipped, because its deadline is still
            // in the past: leaving it would re-fire the same fault on every single pass, turning a
            // one-off into a busy loop.
            try
            {
                long deadline = conn.GetNextTimeout(now);
                if (deadline <= now)
                {
                    conn.OnTimer(now);
                    deadline = conn.GetNextTimeout(now);
                }
                if (deadline < next)
                {
                    next = deadline;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[r{_id}] quic timer faulted, dropping the connection: {e}");

                // Paired with OnEvicted, exactly as QuicSweep and TeardownQuic pair them. Removing
                // without evicting looks like it frees the connection and does not: OnEvicted is
                // the only caller of the engine binding's Destroy, which frees the retained send
                // chunks, calls iq_conn_free (ngtcp2_conn_del and the picotls session) and releases
                // the GCHandle. Worse, removal is what makes the leak permanent - the connection is
                // out of _quicConnSet and every CID route, so neither the idle sweep nor teardown
                // can ever reach it again, and the GCHandle keeps the managed object rooted too.
                QuicRemoveConnection(conn);
                conn.OnEvicted(QuicEvictReason.TimerFault);
            }
        }
        _quicNextTimeoutMs = next;
    }

    // Pull the tracked minimum forward after engine activity on a conn (its expiry may now be the
    // earliest). Deadlines that move LATER are caught by the next full scan when the stale minimum
    // fires - one wasted scan, never a missed timer.
    private void QuicArmTimer(QuicConnection conn)
    {
        long deadline = conn.GetNextTimeout(Environment.TickCount64);
        if (deadline < _quicNextTimeoutMs)
        {
            _quicNextTimeoutMs = deadline;
        }
    }

    private void TeardownQuic()
    {
        if (_quicOptions == null && _quicConnSet.Count == 0)
        {
            return;   // no inbound QUIC and no client connections to close
        }
        _quicSweepScratch.Clear();
        _quicSweepScratch.AddRange(_quicConnSet);
        foreach (QuicConnection conn in _quicSweepScratch)
        {
            QuicRemoveConnection(conn);
            conn.OnEvicted(QuicEvictReason.ReactorShutdown);
        }
        _quicConns.Clear();
    }
}
