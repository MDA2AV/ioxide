using System.Runtime.CompilerServices;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// TCP transport: SO_REUSEPORT listeners, multishot accept, and the stream-shaped recv/send
/// submits and completions that drive <see cref="TcpConnection"/>. Peer transports: Reactor.Udp.cs /
/// Reactor.Quic.cs.
/// </summary>
public sealed unsafe partial class Reactor
{
    private void SubmitRecvMultishot(int fd, ushort gen, ushort bgid)
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_RECV;
        sqe->flags     = IOSQE_BUFFER_SELECT;
        sqe->ioprio    = IORING_RECV_MULTISHOT;
        sqe->fd        = fd;
        sqe->buf_index = bgid;
        sqe->user_data = Tag(KindTcpRecv, gen, fd);
    }

    // Dispatch a send to this connection's strategy. A predictable per-connection branch (ZeroCopySend
    // is constant for the run; kTLS pins plain) instead of an indirect call - so SubmitSendImpl stays
    // inlinable on the hot send path.
    private void SubmitSend(TcpConnection conn, int fd, ushort gen, byte* buf, uint len, uint opFlags)
    {
        if (conn.UseZc)
        {
            SubmitSendImpl(this, IORING_OP_SEND_ZC, fd, gen, buf, len, opFlags);
        }
        else
        {
            SubmitSendImpl(this, IORING_OP_SEND, fd, gen, buf, len, opFlags);
        }

        // After the SQE is written, not before: GetSqeOrFlush throws when the SQ will not drain, and
        // a count raised for a request that never existed can never be cleared - the connection
        // would sit in _sendDraining for the life of the process. Safe here because nothing is
        // submitted until the loop's next io_uring_enter, so no CQE can arrive in between.
        conn.SendsInFlight++;   // cleared by the terminal CQE; gates recycle (#221)
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SubmitSendImpl(Reactor r, byte opcode, int fd, ushort gen, byte* buf, uint len, uint opFlags)
    {
        IoUringSqe* sqe = r.GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = opcode;
        sqe->fd        = fd;
        sqe->addr      = (ulong)buf;
        sqe->len       = len;
        sqe->op_flags  = opFlags;   // MSG_WAITALL by default; cleared for kTLS
        sqe->user_data = Tag(KindTcpSend, gen, fd);
    }

    // Vectored send: one SQE gathers every write segment (primary + overflow) from the iovec the
    // connection prepared in BuildIovec. Plain SENDMSG (no zero-copy) for the segmented path.
    private void SubmitSendMsg(TcpConnection conn, int fd, ushort gen)
    {
        IoUringSqe* sqe = GetSqeOrFlush();   // before the count; see SubmitSend
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_SENDMSG;
        sqe->fd        = fd;
        sqe->addr      = (ulong)conn.MsgHdr;
        sqe->len       = 1;
        sqe->op_flags  = conn.SendOpFlags;   // MSG_WAITALL
        sqe->user_data = Tag(KindTcpSend, gen, fd);
    }

    private void SubmitAcceptMultishot(int listenFd)
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_ACCEPT;
        sqe->ioprio    = IORING_ACCEPT_MULTISHOT;
        sqe->fd        = listenFd;
        sqe->user_data = Tag(KindTcpAccept, 0, listenFd);
    }

    private void ArmTcpAccepts()
    {
        foreach (int listenFd in _listenFds)
        {
            SubmitAcceptMultishot(listenFd);
        }
    }

    // Recv completions, one method per loop mode - the single operation the two modes genuinely
    // differ on (where buffers come from and who returns them).

    private const int ENOBUFS = 105;

    // Connections whose multishot recv died on -ENOBUFS, packed (gen << 32 | fd), both modes (#93).
    // RearmStarvedRecvs re-arms them from the loop, gated on _buffersReturned - handler
    // continuations run inline in CQE dispatch, so buffers can return BEFORE the batch's trailing
    // -ENOBUFS is even seen; a per-return flag observed at the loop top misses neither ordering.
    private readonly List<ulong> _recvStarved = [];
    private bool _buffersReturned;

    // Shared mode: one reactor-wide provided-buffer ring; every CQE consumes a whole buffer, so
    // the EOF and stale paths must hand it straight back to the shared pool.
    private void OnTcpRecvCompletionShared(int fd, ushort gen, int res, uint flags)
    {
        bool   hasBuf = (flags & IORING_CQE_F_BUFFER) != 0;
        ushort bid    = hasBuf ? (ushort)(flags >> IORING_CQE_BUFFER_SHIFT) : (ushort)0;

        TcpConnection? conn = ConnAt(fd, gen);

        if (res == -ENOBUFS)
        {
            // Transient buffer-group exhaustion, not a peer error (#93): the multishot terminated
            // (F_MORE clear), so park the connection; RearmStarvedRecvs resumes it when buffers
            // return to the group.
            if (conn != null)
            {
                conn.LastActivityMs = NowMs;
                _recvStarved.Add(((ulong)gen << 32) | (uint)fd);
            }
            return;
        }

        if (res <= 0)
        {
            // Peer EOF or recv error - reactor owns teardown.
            if (hasBuf)
            {
                ReturnBufferDirect(bid);
            }
            if (conn != null)
            {
                CloseFromRecv(conn, fd);
            }
            return;
        }

        if (conn == null)
        {
            // Stale CQE from the fd's previous tenant.
            if (hasBuf)
            {
                ReturnBufferDirect(bid);
            }
            return;
        }

        conn.LastActivityMs = NowMs;

        byte* ptr = hasBuf ? _bufSlab + (nuint)bid * (nuint)_recvBufferSize : null;
        if (!conn.Complete(res, bid, hasBuf, ptr))
        {
            CloseFromRecvOverflow(conn, fd, gen);
            return;
        }

        if ((flags & IORING_CQE_F_MORE) == 0)
        {
            SubmitRecvMultishot(fd, gen, BgId);
        }
    }

    // Incremental mode: per-connection IOU_PBUF_RING_INC ring - the kernel keeps appending into
    // one bid at a running offset, so instead of returning buffers per CQE this tracks
    // offset/refcount/kernel-done per buffer (the ring is freed wholesale in Recycle).
    private void OnTcpRecvCompletionIncremental(int fd, ushort gen, int res, uint flags)
    {
        bool   more    = (flags & IORING_CQE_F_MORE)     != 0;
        bool   hasBuf  = (flags & IORING_CQE_F_BUFFER)   != 0;
        bool   bufMore = (flags & IORING_CQE_F_BUF_MORE) != 0;
        ushort bid     = hasBuf ? (ushort)(flags >> IORING_CQE_BUFFER_SHIFT) : (ushort)0;

        TcpConnection? conn = ConnAt(fd, gen);

        if (res == -ENOBUFS)
        {
            // Per-connection group drained - e.g. a body larger than the ring while the handler
            // still holds buffers (#93). Park; the loop re-arms once a buffer recycles.
            if (conn != null)
            {
                conn.LastActivityMs = NowMs;
                _recvStarved.Add(((ulong)gen << 32) | (uint)fd);
            }
            return;
        }

        if (res <= 0)
        {
            // Peer EOF / recv error - the per-conn ring is freed in Recycle.
            if (conn != null)
            {
                CloseFromRecv(conn, fd);
            }
            return;
        }

        if (conn == null)
        {
            return;   // stale CQE; its ring is already gone
        }

        conn.LastActivityMs = NowMs;

        // Data lands at the buffer's running offset; the kernel keeps appending
        // to this bid until the buffer is full (F_BUF_MORE clear).
        byte* ptr = conn.BufSlab + (nuint)bid * (nuint)_incRecvBufferSize + (nuint)conn.CumOffset![bid];
        conn.CumOffset[bid] += res;
        conn.RefCount![bid]++;
        if (!bufMore || !more)
        {
            conn.KernelDone![bid] = true;
        }

        if (!conn.Complete(res, bid, hasBuffer: true, ptr))
        {
            CloseFromRecvOverflow(conn, fd, gen);
            return;
        }

        if (!more)
        {
            SubmitRecvMultishot(fd, gen, conn.Bgid);
        }
    }

    // Accept, both modes. The mode branch picks the buffer-ring wiring; _incremental is readonly
    // for the reactor's lifetime, so it predicts perfectly.
    private void OnTcpAcceptCompletion(int listenFd, int res, bool more)
    {
        if (res >= 0)
        {
            int clientFd = res;

            if (_incremental && _freeGids!.Count == 0)
            {
                // At the gid cap (MaxConnections concurrent): shed the connection instead of
                // letting AllocGid throw and take the whole reactor down (#92).
                close(clientFd);
                if (!more)
                {
                    SubmitAcceptMultishot(listenFd);
                }
                return;
            }

            SetNoDelay(clientFd);
            TcpConnection conn = _pool.TryPop(out var pooled)
                ? pooled.SetFd(clientFd)
                : new TcpConnection(this, clientFd, _tcp.WriteSlabSize, _tcp.RecvQueueEntries,
                                 _incremental ? WriteOverflowStrategy.Grow : _tcp.WriteOverflow);
            Track(clientFd, conn);
            conn.InitRefs();
            conn.ListenerPort = PortOf(listenFd);
            conn.LastActivityMs = NowMs;   // the idle clock starts at accept

            if (_incremental)
            {
                SetupConnectionBufRing(conn);
                SubmitRecvMultishot(clientFd, (ushort)conn.Generation, conn.Bgid);
            }
            else
            {
                conn.UseZc = _zeroCopySend;   // config default; kTLS overrides to plain on handshake
                SubmitRecvMultishot(clientFd, (ushort)conn.Generation, BgId);
            }

            _ = RunHandlerAsync(conn);
        }
        else
        {
            Console.Error.WriteLine($"[r{_id}] accept error: {res}");
        }
        if (!more)
        {
            SubmitAcceptMultishot(listenFd);
        }
    }

    // Recv-side teardown, shared by both modes.
    private void CloseFromRecv(TcpConnection conn, int fd)
    {
        _connections[fd] = null;
        TrackDrainingSend(conn);
        conn.MarkClosed();
        conn.DecRef();
    }

    // Recv-queue overflow - tear down rather than zombify. The multishot recv is still armed
    // (F_MORE was set), so it is also cancelled by exact user_data.
    private void CloseFromRecvOverflow(TcpConnection conn, int fd, ushort gen)
    {
        _connections[fd] = null;
        TrackDrainingSend(conn);
        SubmitCancel(Tag(KindTcpRecv, gen, fd));
        conn.MarkClosed();
        conn.DecRef();
    }

    // Re-arm every recv parked on -ENOBUFS (#93). Runs once per loop iteration, but only when a
    // buffer actually came back since the last sweep - so a parked connection can't spin the loop
    // (no return, no re-arm).
    private void RearmStarvedRecvs()
    {
        if (_recvStarved.Count == 0 || !_buffersReturned)
        {
            return;
        }
        _buffersReturned = false;

        for (int i = 0; i < _recvStarved.Count; i++)
        {
            int    fd  = (int)(uint)_recvStarved[i];
            ushort gen = (ushort)(_recvStarved[i] >> 32);
            TcpConnection? conn = ConnAt(fd, gen);
            if (conn != null)
            {
                SubmitRecvMultishot(fd, gen, _incremental ? conn.Bgid : BgId);
            }
            // stale entries (recycled connections) just drop
        }
        _recvStarved.Clear();
    }

    // Accept-time only; the listener table is tiny (Port + ExtraPorts).
    private ushort PortOf(int listenFd)
    {
        for (int i = 0; i < _listenFds.Length; i++)
        {
            if (_listenFds[i] == listenFd)
            {
                return _listenPorts[i];
            }
        }
        return _port;
    }

    // Per accepted socket - TCP_NODELAY doesn't reliably inherit from the listener.
    private static void SetNoDelay(int fd)
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));
    }

    private int[] _listenFds = [];
    private ushort[] _listenPorts = [];

    // One SO_REUSEPORT listener per port; accepts route by listener fd. ServerConfig.Tcp == null
    // opens none at all, which leaves _listenFds empty and makes ArmTcpAccepts a no-op - a
    // QUIC-only server then binds no TCP port rather than accepting onto an unset TcpHandle.
    private void OpenTcpListeners()
    {
        if (!_tcpEnabled)
        {
            return;
        }

        _listenFds = new int[1 + _tcp.ExtraPorts.Length];

        // -1, not the default 0: the loop below can throw partway and Teardown runs on that path,
        // where an unset slot left at 0 would have it close stdin - handing the number to the next
        // socket opened, for a later teardown to shut.
        Array.Fill(_listenFds, -1);
        _listenPorts = new ushort[_listenFds.Length];
        _listenPorts[0] = _port;
        for (int i = 0; i < _tcp.ExtraPorts.Length; i++)
        {
            _listenPorts[i + 1] = _tcp.ExtraPorts[i];
        }
        for (int i = 0; i < _listenFds.Length; i++)
        {
            _listenFds[i] = OpenReusePortListener(_listenPorts[i], _tcp.ListenBacklog, _config.DualStack);
        }
    }

    private void CloseTcpListeners()
    {
        foreach (int listenFd in _listenFds)
        {
            if (listenFd >= 0)
            {
                close(listenFd);
            }
        }
    }

    // Close any still-open accepted sockets (the connection table is indexed by fd) so they don't
    // leak when a host is disposed and recreated many times in one process - e.g. across a test run.
    private void CloseAcceptedTcpSockets()
    {
        for (int fd = 0; fd < _connections.Length; fd++)
        {
            if (_connections[fd] != null)
            {
                close(fd);
                _connections[fd] = null;
            }
        }
    }

    private static int OpenReusePortListener(ushort port, int backlog, bool dualStack)
    {
        int fd = socket(dualStack ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            throw new InvalidOperationException($"socket failed: {fd}");
        }

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(int));

        if (dualStack)
        {
            // A single AF_INET6 listener bound to :: with IPV6_V6ONLY=0 accepts both IPv6 and
            // IPv4-mapped clients - one socket serves both families.
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(int));

            sockaddr_in6 addr6 = default;
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port   = Htons(port);
            // sin6_addr left zero == in6addr_any (::)

            if (bind(fd, &addr6, (uint)sizeof(sockaddr_in6)) < 0)
            {
                throw new InvalidOperationException("bind failed");
            }
        }
        else
        {
            sockaddr_in addr = default;
            addr.sin_family      = AF_INET;
            addr.sin_port        = Htons(port);
            addr.sin_addr.s_addr = 0; // 0.0.0.0

            if (bind(fd, &addr, (uint)sizeof(sockaddr_in)) < 0)
            {
                throw new InvalidOperationException("bind failed");
            }
        }

        if (listen(fd, backlog) < 0)
        {
            throw new InvalidOperationException("listen failed");
        }

        return fd;
    }
}
