using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using static epoxide.Native;

namespace epoxide;

/// <summary>
/// Outbound TCP: a connection to a remote endpoint, watched by this reactor, usable from any thread.
/// </summary>
public sealed unsafe partial class Reactor
{
    // Outbound connections opened off the reactor, waiting for the reactor to enter them in its table.
    private readonly ConcurrentQueue<(TcpConnection Conn, TaskCompletionSource<TcpConnection> Result, bool Connected)> _registerQ = new();

    /// <summary>
    /// Connect to <paramref name="remote"/> (IPv4 or IPv6) and return the connection, watched by this
    /// reactor. Callable from any thread, and the result is usable from any thread: an awaiter on this
    /// reactor resumes inline, any other on its own context or the thread pool. The caller holds the
    /// handler's ref - <see cref="TcpConnection.DecRef"/> when done, exactly as a handler does.
    /// </summary>
    /// <remarks>
    /// No DNS here: resolve first (Dns.GetHostAddressesAsync on the thread pool, say). There is no
    /// connect timeout either, beyond the kernel's own SYN retries; bound it with WaitAsync, and the
    /// connection is torn down if it does settle later and nobody takes it - it is not, today.
    /// </remarks>
    public Task<TcpConnection> ConnectAsync(IPEndPoint remote)
    {
        ArgumentNullException.ThrowIfNull(remote);
        if (_stopRequested || _stopped)
        {
            return Task.FromException<TcpConnection>(new ObjectDisposedException(nameof(Reactor), "The reactor has stopped."));
        }

        bool v6 = remote.AddressFamily == AddressFamily.InterNetworkV6;
        int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
        {
            return Task.FromException<TcpConnection>(new SocketException((int)ToSocketError(Errno)));
        }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));

        int rc;
        if (v6)
        {
            sockaddr_in6 addr6 = default;
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = Htons((ushort)remote.Port);
            remote.Address.TryWriteBytes(new Span<byte>(addr6.sin6_addr, 16), out _);
            addr6.sin6_scope_id = (uint)remote.Address.ScopeId;
            rc = connect(fd, &addr6, (uint)sizeof(sockaddr_in6));
        }
        else
        {
            sockaddr_in addr = default;
            addr.sin_family = AF_INET;
            addr.sin_port = Htons((ushort)remote.Port);
            Span<byte> bytes = stackalloc byte[4];
            remote.Address.TryWriteBytes(bytes, out _);
            addr.sin_addr.s_addr = MemoryMarshal.Read<uint>(bytes);   // already network byte order
            rc = connect(fd, &addr, (uint)sizeof(sockaddr_in));
        }

        int errno = rc < 0 ? Errno : 0;
        if (rc < 0 && errno != EINPROGRESS)
        {
            close(fd);
            return Task.FromException<TcpConnection>(new SocketException((int)ToSocketError(errno)));
        }

        // An awaiter on this reactor resumes inline; any other must never run on it.
        var result = new TaskCompletionSource<TcpConnection>(
            OnReactorThread ? TaskCreationOptions.None : TaskCreationOptions.RunContinuationsAsynchronously);

        TcpConnection conn = new(this, fd, _tcp.WriteSlabSize, _tcp.RecvQueueEntries, _tcp.WriteOverflow);
        conn.InitRefs();
        Interlocked.Increment(ref _liveConnections);

        if (OnReactorThread)
        {
            RegisterOutbound(conn, result, connected: rc == 0);
        }
        else
        {
            _registerQ.Enqueue((conn, result, rc == 0));
            SignalLoop();

            // Raced the teardown: nothing will take it out of the queue now.
            if (_stopped)
            {
                DrainRegisterQ();
            }
        }

        return result.Task;
    }

    private void DrainRegisterQ()
    {
        while (_registerQ.TryDequeue(out var item))
        {
            RegisterOutbound(item.Conn, item.Result, item.Connected);
        }
    }

    // Reactor thread, or a teardown that left nobody else to do it.
    private void RegisterOutbound(TcpConnection conn, TaskCompletionSource<TcpConnection> result, bool connected)
    {
        conn.BeginLife(readable: false);

        if (_stopped || _stopRequested)
        {
            AbandonOutbound(conn);
            result.TrySetException(new ObjectDisposedException(nameof(Reactor), "The reactor has stopped."));
            return;
        }

        if (!connected)
        {
            conn.BeginConnect(result);   // before the registration: its first writable edge settles the connect
        }

        if (!Register(conn))
        {
            AbandonOutbound(conn);
            result.TrySetException(new SocketException((int)SocketError.SocketError));
            return;
        }

        if (connected)
        {
            result.TrySetResult(conn);
        }
    }

    // Never handed to anyone and never tracked: both refs go, and the descriptor with them.
    private void AbandonOutbound(TcpConnection conn)
    {
        conn.CancelConnect();
        conn.SuppressFin();
        conn.ReleaseReactorRef();
        conn.DecRef();
    }
}
