using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

public delegate void UdpDatagramHandler(Reactor reactor, in UdpDatagram datagram);

/// <summary>
/// UDP transport: each reactor binds every <see cref="UdpOptions.Ports"/> port via SO_REUSEPORT
/// (mirroring the TCP listener sharding) and drives recv with one multishot RECVMSG per socket over a
/// shared provided-buffer ring - arm once, the kernel delivers a CQE per datagram and picks a buffer
/// from the ring, and the buffer returns as soon as its datagram has been handled. RECVMSG rather than
/// plain RECV because a shared datagram socket needs the per-packet peer address (msg_name) and the
/// GRO/TOS control messages, which multishot packs into the chosen buffer behind an
/// io_uring_recvmsg_out header. Sends go through pooled SENDMSG slots (copy-in), optionally
/// GSO-segmented. QUIC rides this layer (Reactor.Quic.cs).
/// </summary>
public sealed unsafe partial class Reactor
{
    // One warning per process, however many reactors and ports there are: the clamp below is a
    // property of the machine, so N reactors reporting it N times is noise, not information.
    private static int _udpBufferClampReported;

    /// <summary>
    /// Per-datagram handler, invoked inline on the reactor thread. Like the TCP <see cref="Reactor.TcpHandle"/>,
    /// set it before <see cref="Run"/>.
    /// </summary>
    public UdpDatagramHandler? OnDatagram;

    // ---- recv: multishot RECVMSG over a shared provided-buffer ring ----
    // Each ring buffer holds one datagram (or GRO train) as the kernel lays it out for multishot
    // recvmsg: [io_uring_recvmsg_out 16][name 128][control 256][payload 64K]. Name/control/payload
    // start at offsets fixed by the reserved namelen/controllen we arm with, so the payload is always
    // at UdpRecvPayloadOff. 64 KiB payload = the largest UDP_GRO train (truncation drops the tail).
    internal const int UdpNameCap       = 128;
    private const int UdpCtrlCap        = 256;
    private const int UdpPayloadCap     = 64 * 1024;
    private const int UdpMsOutSize      = 16;                              // sizeof(io_uring_recvmsg_out)
    private const int UdpRecvNameOff    = UdpMsOutSize;                    // 16
    private const int UdpRecvCtrlOff    = UdpMsOutSize + UdpNameCap;       // 144
    private const int UdpRecvPayloadOff = UdpMsOutSize + UdpNameCap + UdpCtrlCap;   // 400
    private const int UdpRecvBufSize    = UdpRecvPayloadOff + UdpPayloadCap;

    // Distinct buffer-group id: TCP shared ring is 1, incremental per-conn gids are 2..MaxConn+1,
    // gid 1 is reserved - so 0 is always free for the UDP ring.
    private const ushort UdpBgId = 0;

    // Send block: [msghdr 56][iovec 16][name 128][control][pad][payload 64K].
    private const int UdpSendIovOff     = 56;
    private const int UdpSendNameOff     = 72;
    private const int UdpSendCtrlOff     = 200;
    private const int UdpSendPayloadOff  = 320;   // one UDP_SEGMENT cmsg (CmsgSpace(2)=24) fits before this
    private const int UdpSendBlockSize   = UdpSendPayloadOff + UdpPayloadCap;

    private const int ECANCELED = 125;
    private const int ENOBUFS_UDP = 105;

    private int[]    _udpFds     = [];

    // Slots from released pins whose multishot has finished draining. Only recycled after the
    // kernel's last completion, or a stale one would read as the new socket's traffic.
    private readonly Stack<int> _udpFreeSlots = new();
    private ushort[] _udpFdPorts = [];

    // Shared provided-buffer ring for all UDP sockets (one registration, one bgid).
    private byte*  _udpBufRing;
    private byte*  _udpBufSlab;
    private ushort _udpBufRingTail;
    private uint   _udpBufRingMask;
    private int    _udpRingDepth;

    // One persistent msghdr template, shared by every socket's multishot arm: it only conveys the
    // reserved namelen/controllen (identical for all), the kernel writes into the ring buffer.
    private msghdr* _udpRecvTemplate;

    // Send slots: free-list-pooled, grown on demand (same shape as the client-op slot registry).
    private nint[] _udpSendBlocks = [];
    private int[]  _udpSendFree   = [];
    private int    _udpSendFreeTop;
    private int    _udpSendCount;

    private void OpenUdpSockets()
    {
        // Udp == null means no RAW datagram sockets; QUIC still binds its own port below and
        // uses the resolved _udp defaults for Gro / RecvSlots.
        ushort[] rawPorts = _udpEnabled ? _udp.Ports : [];

        if (rawPorts.Length == 0 && _config.Quic == null)
        {
            return;   // no datagram transport configured
        }

        // The QUIC port is a UDP socket like any other; only completion routing differs.
        ushort[] udpPorts = rawPorts;
        if (_config.Quic is { } quic && Array.IndexOf(udpPorts, quic.Port) < 0)
        {
            udpPorts = [.. udpPorts, quic.Port];
        }

        int ports = udpPorts.Length;
        _udpFds     = new int[ports];
        _udpFdPorts = new ushort[ports];

        InitUdpBufRing();

        // Ordered across the fleet ONLY when QuicRouting.KernelFilter is asked for: that program
        // answers with a position in the reuseport group and the position is bind order, so
        // reactor N's socket has to be the Nth one in. Under the default routing this returns null
        // immediately and startup is exactly as it was. See Reactor.Udp.Steering.cs.
        QuicSteeringGate? gate = QuicSteeringBegin();
        int quicFd = -1;

        try
        {
            for (int i = 0; i < ports; i++)
            {
                ushort port = udpPorts[i];
                _udpFds[i]     = OpenUdpSocket(port, _config.DualStack, _udp.Gro, _udp.SocketBufferBytes);
                _udpFdPorts[i] = port;
                ArmUdpRecv(i);   // one multishot per socket, all sharing the ring

                if (_config.Quic is { } configured && port == configured.Port)
                {
                    // Kept for the reactor's life: pins are only made against this socket, never
                    // a client's own ephemeral one.
                    quicFd = _quicServingFd = _udpFds[i];
                }
            }
        }
        finally
        {
            // Hands the turn on whatever happened. A reactor that threw reports -1, which abandons
            // steering for the fleet rather than attaching a filter whose indices are now wrong.
            QuicSteeringRelease(gate, quicFd);
        }
    }

    /// <summary>
    /// Open a UDP socket on an ephemeral port for outbound QUIC and arm it on this ring, appending
    /// it to the fd tables. Used by a reactor with no datagram transport configured at all, so it
    /// brings up the buffer ring on the way if OpenUdpSockets never ran. Returns its index.
    /// </summary>
    private int OpenClientUdpSocket()
    {
        if (_udpFds.Length == 0)
        {
            InitUdpBufRing();   // no UDP/QUIC in config, so startup skipped it
        }

        int fd = OpenUdpSocket(0, _config.DualStack, _udp.Gro, _udp.SocketBufferBytes);   // port 0: the kernel picks

        // Append. Indices stay stable (recv completions carry theirs in user_data), so growing the
        // tables cannot disturb the multishot recvs already armed on the existing sockets.
        int index = _udpFds.Length;
        _udpFds     = [.. _udpFds, fd];
        _udpFdPorts = [.. _udpFdPorts, BoundPort(fd, _config.DualStack)];

        ArmUdpRecv(index);
        return index;
    }

    // The port the kernel assigned to a bind(:0) - ngtcp2 needs the real local address for its
    // path, so 0 will not do.
    private static ushort BoundPort(int fd, bool dualStack)
    {
        if (dualStack)
        {
            sockaddr_in6 addr6 = default;
            uint len6 = (uint)sizeof(sockaddr_in6);
            if (getsockname(fd, &addr6, &len6) < 0)
            {
                throw new InvalidOperationException("getsockname failed on the QUIC client socket");
            }
            return Htons(addr6.sin6_port);   // Htons is its own inverse (16-bit swap)
        }

        sockaddr_in addr = default;
        uint len = (uint)sizeof(sockaddr_in);
        if (getsockname(fd, &addr, &len) < 0)
        {
            throw new InvalidOperationException("getsockname failed on the QUIC client socket");
        }
        return Htons(addr.sin_port);
    }

    // Provided-buffer ring (power-of-two depth) + a slab of UdpRecvBufSize buffers, plus the shared
    // msghdr template. Mirrors the TCP shared-ring setup; buffer 0's entry overlaps the tail field at
    // offset 14, so the fill writes only addr/len/bid and publishes the tail afterwards.
    private void InitUdpBufRing()
    {
        int depth = RoundUpPow2(_udp.RecvSlots);
        _udpRingDepth   = depth;
        _udpBufRingMask = (uint)(depth - 1);

        _udpBufRing = (byte*)NativeMemory.AlignedAlloc((nuint)depth * 16, 4096);
        NativeMemory.Clear(_udpBufRing, (nuint)depth * 16);
        _udpBufSlab = (byte*)NativeMemory.AlignedAlloc((nuint)depth * UdpRecvBufSize, 64);

        for (ushort bid = 0; bid < depth; bid++)
        {
            byte* entry = _udpBufRing + (uint)bid * 16;
            *(ulong*)(entry + 0)  = (ulong)(_udpBufSlab + (nuint)bid * UdpRecvBufSize);
            *(uint*)(entry + 8)   = UdpRecvBufSize;
            *(ushort*)(entry + 12) = bid;
        }
        _udpBufRingTail = (ushort)depth;
        Volatile.Write(ref *(ushort*)(_udpBufRing + 14), _udpBufRingTail);

        var reg = new io_uring_buf_reg
        {
            ring_addr    = (ulong)_udpBufRing,
            ring_entries = (uint)depth,
            bgid         = UdpBgId,
        };
        int ret = io_uring_register(_ring.Fd, IORING_REGISTER_PBUF_RING, &reg, 1);
        if (ret < 0)
        {
            throw new InvalidOperationException($"register udp pbuf_ring failed: ret={ret}");
        }

        // Template: reserved name/control sizes only; iov unused (buffer comes from the ring).
        _udpRecvTemplate = (msghdr*)NativeMemory.AlignedAlloc((nuint)sizeof(msghdr), 64);
        Unsafe.InitBlockUnaligned(_udpRecvTemplate, 0, (uint)sizeof(msghdr));
        _udpRecvTemplate->msg_namelen    = UdpNameCap;
        _udpRecvTemplate->msg_controllen = UdpCtrlCap;
    }

    /// <summary>
    /// Say so, once, when the kernel granted materially less buffer than was asked for.
    ///
    /// SO_RCVBUF does not fail when it cannot honour a request - it clamps to net.core.rmem_max and
    /// reports success. On a stock Linux box that ceiling is 212,992 bytes, so a server asking for
    /// 8 MiB quietly runs with about a fortieth of it and the only symptom is datagrams dropped
    /// under load, which looks like a bug anywhere but here. Reading the value back makes it visible.
    ///
    /// It deliberately does NOT tell the operator to raise the cap: which is better depends on the
    /// deployment (see <see cref="UdpOptions.SocketBufferBytes"/>), so this reports the fact and
    /// leaves the judgement.
    ///
    /// getsockopt reports DOUBLE what was granted - the kernel's own bookkeeping overhead is
    /// included - so the comparison halves it.
    /// </summary>
    private static void ReportBufferClamp(int fd, int requested)
    {
        int reported = 0;
        uint size = sizeof(int);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &reported, &size) < 0)
        {
            return;
        }

        int granted = reported / 2;
        if (granted >= requested / 2)
        {
            return;   // near enough; a small shortfall is not worth a startup warning
        }

        if (Interlocked.Exchange(ref _udpBufferClampReported, 1) != 0)
        {
            return;
        }

        Console.Error.WriteLine(
            $"[ioxide] udp: asked for {requested / 1024} KiB of socket buffer, the kernel granted "
            + $"{granted / 1024} KiB (capped by net.core.rmem_max). Expect datagrams to be dropped "
            + "under load; raising the cap trades those drops for queueing delay, so measure it.");
    }

    private static int RoundUpPow2(int n)
    {
        int p = 1;
        while (p < n)
        {
            p <<= 1;
        }
        return p;
    }

    private void ReturnUdpBuffer(ushort bid)
    {
        byte* entry = _udpBufRing + (_udpBufRingTail & _udpBufRingMask) * 16;
        *(ulong*)(entry + 0)  = (ulong)(_udpBufSlab + (nuint)bid * UdpRecvBufSize);
        *(uint*)(entry + 8)   = UdpRecvBufSize;
        *(ushort*)(entry + 12) = bid;
        _udpBufRingTail++;
        Volatile.Write(ref *(ushort*)(_udpBufRing + 14), _udpBufRingTail);
    }

    private static int OpenUdpSocket(ushort port, bool dualStack, bool gro, int socketBufferBytes,
        nint connectTo = 0, int connectLen = 0)
    {
        // Refused rather than clamped: a zero or negative request would leave the socket on the
        // kernel minimum, which looks identical to the clamp above and would be read as one.
        if (socketBufferBytes <= 0)
        {
            throw new InvalidOperationException(
                $"UdpOptions.SocketBufferBytes must be positive, got {socketBufferBytes}.");
        }

        int fd = socket(dualStack ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            throw new InvalidOperationException($"udp socket failed: {fd}");
        }

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(int));
        if (gro)
        {
            setsockopt(fd, SOL_UDP, UDP_GRO, &one, sizeof(int));
        }

        int buf = socketBufferBytes;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(int));
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(int));
        ReportBufferClamp(fd, socketBufferBytes);

        if (dualStack)
        {
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(int));
            // TCLASS covers native IPv6; RECVTOS covers IPv4-mapped peers on the same socket.
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof(int));
            setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof(int));

            sockaddr_in6 addr6 = default;
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port   = Htons(port);

            if (bind(fd, &addr6, (uint)sizeof(sockaddr_in6)) < 0)
            {
                throw new InvalidOperationException($"udp bind :{port} failed");
            }
        }
        else
        {
            setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof(int));

            sockaddr_in addr = default;
            addr.sin_family      = AF_INET;
            addr.sin_port        = Htons(port);
            addr.sin_addr.s_addr = 0;

            if (bind(fd, &addr, (uint)sizeof(sockaddr_in)) < 0)
            {
                throw new InvalidOperationException($"udp bind :{port} failed");
            }
        }

        // A pinned socket: same address as its siblings but naming ONE peer, so it outranks the
        // wildcard binds and the reuseport hash is never consulted for that peer. Measured: no
        // other peer moves. connect() on a datagram socket sends nothing.
        if (connectTo != 0 && connect(fd, (void*)connectTo, (uint)connectLen) < 0)
        {
            close(fd);
            return -1;
        }

        return fd;
    }

    // Arm (or re-arm) the multishot RECVMSG for one socket over the shared buffer ring. The kernel
    // then delivers a CQE per datagram, each selecting a ring buffer, until the multishot terminates.
    private void ArmUdpRecv(int socketIndex)
    {
        if (_udpFds[socketIndex] < 0)
        {
            return;   // slot released; nothing to arm and nothing to re-arm onto
        }

        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_RECVMSG;
        sqe->flags     = IOSQE_BUFFER_SELECT;
        sqe->ioprio    = IORING_RECV_MULTISHOT;
        sqe->fd        = _udpFds[socketIndex];
        sqe->addr      = (ulong)_udpRecvTemplate;
        sqe->len       = 1;
        sqe->buf_index = UdpBgId;
        sqe->user_data = Tag(KindUdpRecv, 0, socketIndex);
    }

    private void OnUdpRecvCompletion(int socketIndex, int res, uint flags)
    {
        if ((uint)socketIndex >= (uint)_udpFds.Length)
        {
            return;
        }

        bool more = (flags & IORING_CQE_F_MORE) != 0;

        if (_udpFds[socketIndex] < 0)
        {
            // Closed while this was in flight (a released pin). Hand back any buffer the kernel
            // selected; the terminating completion means nothing more references this slot.
            if ((flags & IORING_CQE_F_BUFFER) != 0)
            {
                ReturnUdpBuffer((ushort)(flags >> IORING_CQE_BUFFER_SHIFT));
            }
            if (!more)
            {
                _udpFreeSlots.Push(socketIndex);
            }
            return;
        }

        if (res < 0)
        {
            // -ENOBUFS: the ring momentarily drained (a burst outran the depth). Buffers return
            // inline, so re-arming picks them up. -ECANCELED / stop: teardown, drop.
            if (res == -ECANCELED || _stopRequested)
            {
                return;
            }
            if (res != -ENOBUFS_UDP)
            {
                Console.Error.WriteLine($"[r{_id}] udp recv error: {res}");
            }
            if (!more)
            {
                ArmUdpRecv(socketIndex);
            }
            return;
        }

        // Kernel-picked buffer id; without one there is nothing to parse or return.
        if ((flags & IORING_CQE_F_BUFFER) == 0)
        {
            if (!more)
            {
                ArmUdpRecv(socketIndex);
            }
            return;
        }

        ushort bid = (ushort)(flags >> IORING_CQE_BUFFER_SHIFT);
        byte*  buf = _udpBufSlab + (nuint)bid * UdpRecvBufSize;
        var    o   = (io_uring_recvmsg_out*)buf;

        // Packed layout: header, then the reserved name/control regions, then the payload at the
        // fixed offset. res is the total written, so payload length = res - payload offset.
        int payloadLen = res - UdpRecvPayloadOff;
        if (payloadLen < 0)
        {
            ReturnUdpBuffer(bid);
            if (!more)
            {
                ArmUdpRecv(socketIndex);
            }
            return;
        }

        int  gro = 0;
        byte tos = 0;
        if (o->controllen >= CmsgHdrLen)
        {
            // Parse cmsgs out of the control region via a throwaway msghdr pointing at it.
            msghdr ctrl = default;
            ctrl.msg_control    = buf + UdpRecvCtrlOff;
            ctrl.msg_controllen = o->controllen;
            for (cmsghdr* c = CmsgFirst(&ctrl); c != null; c = CmsgNext(&ctrl, c))
            {
                if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_GRO)
                {
                    gro = *(int*)CmsgData(c);
                }
                else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TOS)
                {
                    tos = *CmsgData(c);
                }
                else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_TCLASS)
                {
                    tos = (byte)*(int*)CmsgData(c);
                }
            }
        }

        if ((o->flags & MSG_TRUNC) != 0)
        {
            Console.Error.WriteLine($"[r{_id}] udp datagram truncated (payload={payloadLen})");
        }

        var datagram = new UdpDatagram(_udpFds[socketIndex], _udpFdPorts[socketIndex],
                                       (nint)(buf + UdpRecvNameOff), (int)o->namelen,
                                       new ReadOnlySpan<byte>(buf + UdpRecvPayloadOff, payloadLen), gro, tos);
        try
        {
            // Either the configured QUIC socket, or the ephemeral one a standalone client opened.
            if ((_quicOptions != null && _udpFdPorts[socketIndex] == _quicOptions.Port) ||
                socketIndex == _quicClientSocketIndex)
            {
                QuicDispatch(in datagram);   // QUIC
            }
            else
            {
                OnDatagram?.Invoke(this, in datagram);   // plain UDP
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[r{_id}] datagram handler faulted: {e.GetBaseException().Message}");
        }

        // Handler is done with the span; return the buffer (inline, so the ring rarely drains).
        ReturnUdpBuffer(bid);

        // Multishot terminated (buffer exhaustion or error) - re-arm to keep receiving.
        if (!more)
        {
            ArmUdpRecv(socketIndex);
        }
    }

    /// <summary>
    /// Send one datagram (copy-in) to <paramref name="peerAddr"/> on <paramref name="socketFd"/>.
    /// With <paramref name="gsoSegmentSize"/> &gt; 0 the payload is a batch the kernel splits into
    /// wire datagrams of that size (UDP_SEGMENT) - one submission, many packets. Reactor-thread-only
    /// (handlers and OnStart already are; marshal via <see cref="ScheduleOnReactor"/> otherwise).
    /// </summary>
    public void UdpSendTo(int socketFd, nint peerAddr, int peerAddrLen, ReadOnlySpan<byte> payload, int gsoSegmentSize = 0)
    {
        if (!OnReactorThread && _reactorThreadId != 0)
        {
            throw new InvalidOperationException("UdpSendTo must run on the reactor thread (marshal via ScheduleOnReactor).");
        }
        if (payload.Length > UdpPayloadCap)
        {
            throw new ArgumentException($"payload {payload.Length} exceeds the {UdpPayloadCap} send cap", nameof(payload));
        }
        if ((uint)peerAddrLen > UdpNameCap)
        {
            throw new ArgumentException($"peer sockaddr length {peerAddrLen} exceeds {UdpNameCap}", nameof(peerAddrLen));
        }

        int slot = AllocUdpSendSlot();
        byte* block = (byte*)_udpSendBlocks[slot];

        Buffer.MemoryCopy((void*)peerAddr, block + UdpSendNameOff, UdpNameCap, peerAddrLen);
        payload.CopyTo(new Span<byte>(block + UdpSendPayloadOff, UdpPayloadCap));

        var iov = (iovec*)(block + UdpSendIovOff);
        iov->iov_base = block + UdpSendPayloadOff;
        iov->iov_len  = (nuint)payload.Length;

        var m = (msghdr*)block;
        m->msg_name    = block + UdpSendNameOff;
        m->msg_namelen = (uint)peerAddrLen;
        m->msg_iov     = iov;
        m->msg_iovlen  = 1;
        m->msg_flags   = 0;

        if (gsoSegmentSize > 0)
        {
            var c = (cmsghdr*)(block + UdpSendCtrlOff);
            c->cmsg_len   = CmsgHdrLen + sizeof(ushort);
            c->cmsg_level = SOL_UDP;
            c->cmsg_type  = UDP_SEGMENT;
            *(ushort*)CmsgData(c) = (ushort)gsoSegmentSize;
            m->msg_control    = c;
            m->msg_controllen = CmsgSpace(sizeof(ushort));
        }
        else
        {
            m->msg_control    = null;
            m->msg_controllen = 0;
        }

        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_SENDMSG;
        sqe->fd        = socketFd;
        sqe->addr      = (ulong)m;
        sqe->len       = 1;
        sqe->user_data = Tag(KindUdpSend, 0, slot);
    }

    private void OnUdpSendCompletion(int slot, int res)
    {
        if (res < 0)
        {
            Console.Error.WriteLine($"[r{_id}] udp send error: {res}");
        }
        _udpSendFree[_udpSendFreeTop++] = slot;
    }

    private int AllocUdpSendSlot()
    {
        if (_udpSendFreeTop == 0)
        {
            GrowUdpSendSlots();
        }
        return _udpSendFree[--_udpSendFreeTop];
    }

    private void GrowUdpSendSlots()
    {
        int add = _udpSendCount == 0 ? 16 : _udpSendCount;
        int newCount = _udpSendCount + add;

        Array.Resize(ref _udpSendBlocks, newCount);
        Array.Resize(ref _udpSendFree, newCount);
        for (int i = _udpSendCount; i < newCount; i++)
        {
            _udpSendBlocks[i] = (nint)NativeMemory.AlignedAlloc(UdpSendBlockSize, 64);
            _udpSendFree[_udpSendFreeTop++] = i;
        }
        _udpSendCount = newCount;
    }

    // Split teardown: fds close while the ring is still alive (in-flight RECVMSG ops surface as
    // errors/cancels and are dropped); the native blocks are freed only after the ring fd is
    // closed, once the kernel holds no references into them (same discipline as the buffer slab).
    private void CloseUdpFds()
    {
        foreach (int fd in _udpFds)
        {
            if (fd >= 0)
            {
                close(fd);
            }
        }
    }

    private void FreeUdpMemory()
    {
        if (_udpBufRing != null)
        {
            NativeMemory.AlignedFree(_udpBufRing);
            _udpBufRing = null;
        }
        if (_udpBufSlab != null)
        {
            NativeMemory.AlignedFree(_udpBufSlab);
            _udpBufSlab = null;
        }
        if (_udpRecvTemplate != null)
        {
            NativeMemory.AlignedFree(_udpRecvTemplate);
            _udpRecvTemplate = null;
        }

        for (int i = 0; i < _udpSendCount; i++)
        {
            NativeMemory.AlignedFree((void*)_udpSendBlocks[i]);
        }
        _udpSendCount = 0;
        _udpSendFreeTop = 0;
        _udpSendBlocks = [];
        _udpSendFree = [];
    }
}
