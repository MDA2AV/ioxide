using System.Collections.Concurrent;
using static epoxide.Native;

namespace epoxide;

/// <summary>
/// TCP transport: SO_REUSEPORT listeners, accept, and the connection lifecycle the reactor owns -
/// the end it sees, and the recycle once every holder has let go.
/// </summary>
public sealed unsafe partial class Reactor
{
    private int[] _listenFds = [];
    private ushort[] _listenPorts = [];

    // Accepts per listener event. Level-triggered, so whatever is left is reported again next pass,
    // and the connections already accepted are served in between.
    private const int AcceptBatch = 64;

    // Listeners out of the epoll set after an accept failed on descriptors or memory (#222 in ioxide):
    // left in, a level-triggered listener would report itself readable on every pass and spin the
    // reactor. TcpSweep puts them back on its next tick.
    private readonly List<int> _acceptPaused = [];
    private bool _acceptPauseReported;

    // One SO_REUSEPORT listener per port. ServerConfig.Tcp == null, the default, opens none.
    private void OpenTcpListeners()
    {
        if (!_tcpEnabled)
        {
            return;
        }

        _listenFds = new int[1 + _tcp.ExtraPorts.Length];

        // -1, not the default 0: the loop below can throw partway and Teardown runs on that path,
        // where an unset slot left at 0 would have it close stdin.
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
            WatchListener(_listenFds[i]);
        }
    }

    private void WatchListener(int listenFd)
    {
        if (EpollCtl(_epfd, EPOLL_CTL_ADD, listenFd, EPOLLIN, Tag(KindListen, 0, listenFd)) < 0)
        {
            throw new InvalidOperationException($"[r{_id}] registering listener {listenFd} failed with errno {Errno}");
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
        _listenFds = [];
    }

    private void OnListenerReadable(int listenFd)
    {
        for (int i = 0; i < AcceptBatch; i++)
        {
            int fd = accept4(listenFd, null, null, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0)
            {
                int errno = Errno;
                if (errno == EAGAIN)
                {
                    return;
                }
                if (errno is EMFILE or ENFILE or ENOBUFS or ENOMEM)
                {
                    PauseAccept(listenFd, errno);
                    return;
                }
                if (errno != EINTR)
                {
                    // ECONNABORTED and the like: that one connection is gone, the next may be fine.
                    Console.Error.WriteLine($"[r{_id}] accept error: {errno}");
                }
                continue;
            }

            _acceptPauseReported = false;
            Adopt(fd, PortOf(listenFd));
        }
    }

    private void PauseAccept(int listenFd, int errno)
    {
        if (!_acceptPauseReported)
        {
            _acceptPauseReported = true;
            Console.Error.WriteLine($"[r{_id}] accept failed (errno {errno}): out of file descriptors or memory, retrying every {TickMs} ms");
        }

        EpollCtl(_epfd, EPOLL_CTL_DEL, listenFd, 0, 0);
        _acceptPaused.Add(listenFd);
    }

    private void ResumePausedAccepts()
    {
        foreach (int listenFd in _acceptPaused)
        {
            WatchListener(listenFd);
        }
        _acceptPaused.Clear();
    }

    // A connection the reactor watches from here on: tracked, registered once (edge-triggered), and
    // handed to the handler, inline.
    private void Adopt(int fd, ushort listenerPort)
    {
        TcpConnection conn = _pool.TryPop(out TcpConnection? pooled)
            ? pooled.SetFd(fd)
            : new TcpConnection(this, fd, _tcp.WriteSlabSize, _tcp.RecvQueueEntries, _tcp.WriteOverflow);

        conn.InitRefs();
        conn.ListenerPort = listenerPort;
        Interlocked.Increment(ref _liveConnections);

        // The request usually arrived with the connection, so the first read tries the socket at once.
        conn.BeginLife(readable: true);

        if (!Register(conn))
        {
            Interlocked.Decrement(ref _liveConnections);
            conn.Clear();
            _pool.Push(conn);   // never handed out
            close(fd);
            return;
        }

        _ = RunHandlerAsync(conn);
    }

    // Tracked before it is registered: the first event can be for it as soon as epoll_ctl returns.
    private bool Register(TcpConnection conn)
    {
        int fd = conn.ClientFd;
        Track(fd, conn);
        if (EpollCtl(_epfd, EPOLL_CTL_ADD, fd, ConnEvents, Tag(KindConn, (ushort)conn.Generation, fd)) == 0)
        {
            return true;
        }

        Console.Error.WriteLine($"[r{_id}] registering connection {fd} failed with errno {Errno}; closing it");
        Untrack(conn);
        return false;
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

    /// <summary>
    /// The reactor's end of a connection: forget it, wake whoever waits on it with the end, and let
    /// go of the reactor's ref. Reactor thread only.
    /// </summary>
    /// <remarks>
    /// The descriptor is NOT closed here. The handler may be inside a recv or send on it on another
    /// thread this very moment, and a number closed under it can be reused by the next accept, so its
    /// next send would land in somebody else's connection. It closes in Recycle, once the handler has
    /// let go as well.
    /// </remarks>
    internal void CloseFromReactor(TcpConnection conn)
    {
        if (!IsTracked(conn))
        {
            return;
        }

        conn.SuppressFin();   // the peer is gone or being cut off; nothing is owed a FIN
        Untrack(conn);
        conn.MarkClosed();
        conn.ReleaseReactorRef();
    }

    // Connections a handler saw end, or let go, off the reactor - (connection, generation at the time).
    private readonly ConcurrentQueue<(TcpConnection Conn, int Gen)> _closeQ = new();

    /// <summary>
    /// Ask the reactor to look at a connection: its handler saw the peer go, or let go of it. With an
    /// edge-triggered set no event may be left to bring the reactor round to it on its own.
    /// </summary>
    internal void Attend(TcpConnection conn)
    {
        if (OnReactorThread)
        {
            AttendNow(conn);
            return;
        }

        if (_stopped)
        {
            return;   // the teardown already let go of everything it tracked
        }

        _closeQ.Enqueue((conn, conn.Generation));
        SignalLoop();
    }

    // From the reactor itself: look again on the next pass, once everything else queued has had its turn.
    internal void AttendLater(TcpConnection conn) => _closeQ.Enqueue((conn, conn.Generation));

    private void DrainCloseQ()
    {
        // Only what was queued before this pass: a drain re-queued here waits for the next one.
        for (int queued = _closeQ.Count; queued > 0 && _closeQ.TryDequeue(out (TcpConnection Conn, int Gen) item); queued--)
        {
            if (item.Conn.Generation == item.Gen)
            {
                AttendNow(item.Conn);
            }
        }
    }

    private void AttendNow(TcpConnection conn)
    {
        if (!IsTracked(conn))
        {
            return;
        }

        if (conn.PeerGone)
        {
            CloseFromReactor(conn);
        }
        else if (conn.HandlerReleased)
        {
            conn.DrainReleased();
        }
    }

    // Recycle must run where the pool lives; a connection let go elsewhere is queued for it.
    private readonly ConcurrentQueue<TcpConnection> _recycleQ = new();

    // Called by TcpConnection at refcount 0.
    internal void EnqueueRecycle(TcpConnection conn)
    {
        if (OnReactorThread || _stopped)
        {
            Recycle(conn);
            return;
        }

        _recycleQ.Enqueue(conn);
        SignalLoop();

        // Raced the teardown's last drain: nobody else will take it out now.
        if (_stopped)
        {
            DrainRecycleQ();
        }
    }

    private void DrainRecycleQ()
    {
        while (_recycleQ.TryDequeue(out TcpConnection? conn))
        {
            Recycle(conn);
        }
    }

    // Every ref is gone, so no thread is in a syscall on the descriptor: now it can close.
    private void Recycle(TcpConnection conn)
    {
        conn.MarkClosed();

        // Buffers a reader dequeued and never gave back, then whatever is still queued.
        conn.ReleaseHeldRecvBuffers();
        conn.DrainRecv();

        close(conn.ClientFd);   // drops it from the epoll set too: no descriptor is ever dup'ed
        conn.Clear();

        if (!_stopped && OnReactorThread && _pool.Count < _poolMax)
        {
            _pool.Push(conn);
        }
        else
        {
            conn.Dispose();
        }

        // The last connection to outlive its stopped reactor takes the pools with it.
        if (Interlocked.Decrement(ref _liveConnections) == 0 && _stopped)
        {
            FreePools();
        }
    }

    // Connections handed out and not yet recycled, wherever their handlers are.
    private int _liveConnections;

    private int _poolsFreed;

    // Only once no connection is left: a reader past its closed check may still rent a recv buffer.
    // Both the teardown and the last late recycle can get here, so the first one does it.
    private void FreePools()
    {
        if (Interlocked.Exchange(ref _poolsFreed, 1) != 0)
        {
            return;
        }

        RecvPool.TryFree();
        WriteSlabPool.TryFree();
    }

    private static int OpenReusePortListener(ushort port, int backlog, bool dualStack)
    {
        int fd = socket(dualStack ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
        {
            throw new InvalidOperationException($"socket failed with errno {Errno}");
        }

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(int));
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));   // accepted sockets inherit it

        if (dualStack)
        {
            // A single AF_INET6 listener bound to :: with IPV6_V6ONLY=0 accepts both IPv6 and
            // IPv4-mapped clients - one socket serves both families.
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(int));

            sockaddr_in6 addr6 = default;
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port   = Htons(port);

            if (bind(fd, &addr6, (uint)sizeof(sockaddr_in6)) < 0)
            {
                int errno = Errno;
                close(fd);
                throw new InvalidOperationException($"bind to [::]:{port} failed with errno {errno}");
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
                int errno = Errno;
                close(fd);
                throw new InvalidOperationException($"bind to 0.0.0.0:{port} failed with errno {errno}");
            }
        }

        if (listen(fd, backlog) < 0)
        {
            int errno = Errno;
            close(fd);
            throw new InvalidOperationException($"listen on {port} failed with errno {errno}");
        }

        return fd;
    }
}
