using System.Net;
using System.Net.Sockets;
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

    private void SubmitSend(TcpConnection conn, int fd, ushort gen, byte* buf, uint len, uint opFlags)
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = conn.UseZc ? IORING_OP_SEND_ZC : IORING_OP_SEND;
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
        IoUringSqe* sqe = GetSqeOrFlush();
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
        sqe->op_flags  = SOCK_CLOEXEC;   // accept_flags
        sqe->user_data = Tag(KindTcpAccept, 0, listenFd);
    }

    // Accept failures that leave the connection in the backlog, so an accept re-armed at once fails
    // again at once (#222): out of descriptors, the process's or the system's, or out of memory.
    private const int ENFILE = 23, EMFILE = 24;

    // Listeners whose accept stopped on one of those; TcpSweep re-arms them on its next tick.
    private readonly List<int> _acceptPaused = [];
    private bool _acceptPauseReported;

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
                ParkStarvedRecv(conn, fd, gen);
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
                ParkStarvedRecv(conn, fd, gen);
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


        // Data lands at the buffer's running offset; the kernel keeps appending
        // to this bid until the buffer is full (F_BUF_MORE clear).
        byte* ptr = conn.BufSlab + (nuint)bid * (nuint)_incRecvBufferSize + (nuint)conn.CumOffset![bid];
        conn.CumOffset[bid] += res;
        // F_BUF_MORE alone decides: a recv ended by a full CQ still has its buffer at the ring head, part filled.
        if (!bufMore)
        {
            conn.KernelDone![bid] = true;
        }

        // Grown into the last item, the slice is handed back with it: the buffer's count stays.
        if (!conn.TryExtendRecv(res, bid, ptr))
        {
            conn.RefCount![bid]++;
            if (!conn.Complete(res, bid, hasBuffer: true, ptr))
            {
                CloseFromRecvOverflow(conn, fd, gen);
                return;
            }
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
            _acceptPauseReported = false;

            TcpConnection conn = _pool.TryPop(out var pooled)
                ? pooled.SetFd(clientFd)
                : new TcpConnection(this, clientFd, _tcp.WriteSlabSize, _tcp.RecvQueueEntries,
                                 _incremental ? WriteOverflowStrategy.Grow : _tcp.WriteOverflow);

            ushort bgid;
            if (_incremental)
            {
                // No ring at the gid cap (#92) or short of locked memory: shed this connection, not the reactor.
                if (!SetupConnectionBufRing(conn))
                {
                    _pool.Push(conn);   // never tracked nor handed out
                    close(clientFd);
                    if (!more)
                    {
                        SubmitAcceptMultishot(listenFd);
                    }
                    return;
                }
                bgid = conn.Bgid;
            }
            else
            {
                bgid = BgId;
            }

            conn.UseZc = _zeroCopySend;   // config default; kTLS overrides to plain on handshake
            Track(clientFd, conn);
            conn.InitRefs();
            conn.ListenerPort = PortOf(listenFd);
            conn.BindSendOpFlags(_sendOpFlags);   // TcpOptions.SendWaitAll; the kTLS handoff clears it
            SubmitRecvMultishot(clientFd, (ushort)conn.Generation, bgid);

            _ = RunHandlerAsync(conn);
        }
        else if (res is -EMFILE or -ENFILE or -ENOBUFS or -ENOMEM)
        {
            // Re-armed now it would fail again at once and spin the reactor; once a tick instead,
            // reported once until an accept succeeds.
            if (!_acceptPauseReported)
            {
                _acceptPauseReported = true;
                Console.Error.WriteLine($"[r{_id}] accept failed ({res}): out of file descriptors or memory, retrying every {TickMs} ms");
            }
            if (!more)
            {
                _acceptPaused.Add(listenFd);
            }
            return;
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

    // Recv-side teardown, shared by both modes. With a send in the kernel the reactor keeps its ref
    // and the table slot, so the slab cannot be recycled under it; FinishSend lets go (#221).
    private void CloseFromRecv(TcpConnection conn, int fd)
    {
        conn.SuppressFin();

        if (conn.FlushSubmitted)
        {
            conn.CloseAfterSend = true;
            conn.MarkClosed();
            return;
        }

        _connections[fd] = null;
        conn.MarkClosed();
        conn.ReleaseReactorRef();
    }

    // Recv-queue overflow - tear down rather than zombify. The multishot recv is still armed
    // (F_MORE was set), so it is also cancelled by exact user_data.
    private void CloseFromRecvOverflow(TcpConnection conn, int fd, ushort gen)
    {
        SubmitCancel(Tag(KindTcpRecv, gen, fd));
        CloseFromRecv(conn, fd);
    }

    private void ParkStarvedRecv(TcpConnection conn, int fd, ushort gen)
    {
        conn.ReadParkedMs = NowMs;   // the peer sent; the wait is ours, so the clock restarts
        if (conn.HandlerReleased)
        {
            ReturnReleasedBuffers(conn);
        }
        _recvStarved.Add(((ulong)gen << 32) | (uint)fd);
    }

    // Nobody will read a connection its handler let go, and its recv needs a buffer to reach the peer's close, which
    // is what tears it down. So what it holds goes back.
    private void ReturnReleasedBuffers(TcpConnection conn)
    {
        // Not claimed the way recycle claims it: a read left parked can still take more, for recycle to ask back.
        conn.BufferHolder?.ReleaseHeldBuffers();
        conn.DrainRecv();
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

    private int[] _listenFds = [];
    private ushort[] _listenPorts = [];

    // One SO_REUSEPORT listener per port; accepts route by listener fd. ServerConfig.Tcp == null, the
    // default, opens none at all, which leaves _listenFds empty and makes ArmTcpAccepts a no-op - a
    // QUIC-only server binds no TCP port rather than accepting onto an unset TcpHandle (#191).
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
            _listenFds[i] = OpenReusePortListener(_listenPorts[i], _tcp.ListenBacklog, _tcp.Address, _config.DualStack,
                _sendTimeoutMs);
        }
    }

    private void CloseTcpListeners()
    {
        foreach (int listenFd in _listenFds)
        {
            if (listenFd >= 0)
            {
                // Shut down first: the armed multishot accept holds the socket until the ring's deferred
                // cancel, about 50 ms after the ring goes, and the port stays bound and accepting until then.
                shutdown(listenFd, SHUT_RDWR);
                close(listenFd);
            }
        }
    }

    // Before any socket closes (#531): a parked read, or a flush the kernel doesn't have, resumes while the number is
    // still its own, and a flush started after it, on any connection, sends nothing.
    private void MarkAcceptedTcpConnectionsClosed()
    {
        for (int fd = 0; fd < _connections.Length; fd++)
        {
            if (_connections[fd] is { } conn)
            {
                // A handler letting go later must not shut down whatever socket gets the number next.
                conn.SuppressFin();
                conn.MarkClosed();
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
            }
        }
    }

    // A flush the kernel had ends only once the kernel is done with its send (#221).
    private void ReleaseAcceptedTcpConnections(bool canCancel)
    {
        for (int fd = 0; fd < _connections.Length; fd++)
        {
            if (_connections[fd] is { } conn)
            {
                if (canCancel && conn.FlushSubmitted && CancelAndWait(Tag(KindTcpSend, (ushort)conn.Generation, fd)))
                {
                    conn.CompleteFlush();
                }

                _connections[fd] = null;
            }
        }
    }

    private static int OpenReusePortListener(ushort port, int backlog, IPAddress? address, bool dualStack, int userTimeoutMs)
    {
        int fd = socket(IsIpv6(address, dualStack) ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
        {
            throw new InvalidOperationException($"socket failed: {fd}");
        }

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(int));
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));   // accepted sockets inherit it
        if (userTimeoutMs > 0)
        {
            // Inherited too. The kernel aborts a connection whose peer leaves data unacknowledged, or its
            // window shut, this long: a stream of small flushes never shows that to the flush deadline, and a
            // zero-copy send needs it to get its pages back (#245).
            setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &userTimeoutMs, sizeof(int));
        }

        BindTo(fd, port, address, dualStack, "tcp");

        if (listen(fd, backlog) < 0)
        {
            close(fd);
            throw new InvalidOperationException("listen failed");
        }

        return fd;
    }

    private static bool IsIpv6(IPAddress? address, bool dualStack)
        => address is null ? dualStack : address.AddressFamily == AddressFamily.InterNetworkV6;

    // Closes fd on failure: the caller has not stored it anywhere yet. No address is every interface.
    private static void BindTo(int fd, ushort port, IPAddress? address, bool dualStack, string transport)
    {
        int rc;
        if (IsIpv6(address, dualStack))
        {
            // :: with IPV6_V6ONLY=0 also takes IPv4-mapped peers, so one socket serves both families.
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(int));

            sockaddr_in6 addr6 = default;
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port   = Htons(port);
            if (address is not null)
            {
                address.TryWriteBytes(new Span<byte>(addr6.sin6_addr, 16), out _);
                addr6.sin6_scope_id = (uint)address.ScopeId;
            }
            // Otherwise sin6_addr left zero == in6addr_any (::)

            rc = bind(fd, &addr6, (uint)sizeof(sockaddr_in6));
        }
        else
        {
            sockaddr_in addr = default;
            addr.sin_family = AF_INET;
            addr.sin_port   = Htons(port);
            if (address is not null)
            {
                address.TryWriteBytes(new Span<byte>(&addr.sin_addr, sizeof(uint)), out _);   // already network byte order
            }
            // Otherwise s_addr left zero == 0.0.0.0

            rc = bind(fd, &addr, (uint)sizeof(sockaddr_in));
        }

        if (rc < 0)
        {
            close(fd);
            throw new InvalidOperationException($"{transport} bind failed on port {port}{(address is null ? "" : $" of {address}")}");
        }
    }
}
