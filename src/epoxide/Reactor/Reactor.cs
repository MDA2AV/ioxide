using System.Numerics;
using System.Runtime.CompilerServices;
using epoxide.utils;

namespace epoxide;

/// <summary>
/// One reactor = one thread + one epoll set + one SO_REUSEPORT listener per port + one connection
/// table. The reactor owns the table, the pools and the connections' lifecycle; the I/O itself is
/// ordinary non-blocking syscalls, so a connection's handler may read and write it from any thread
/// and only waits on the reactor for readiness.
/// </summary>
public sealed unsafe partial class Reactor
{
    private readonly int _id;
    private readonly ServerConfig _config;

    /// <summary>This reactor's position in the fleet - the <c>id</c> it was constructed with.</summary>
    public int ShardIndex => _id;

    /// <summary>How many reactors share this server's ports (<see cref="ServerConfig.ReactorCount"/>).</summary>
    public int ShardCount => _config.ReactorCount;

    // epoll data: [63:56] kind | [47:32] connection generation | [31:0] fd. The generation makes an
    // event still queued for a closed connection's fd detectable once the number is reused.
    private const int  KindShift   = 56;
    private const int  GenShift    = 32;
    private const byte KindListen  = 1;
    private const byte KindWake    = 2;
    private const byte KindConn    = 3;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Tag(byte kind, ushort gen, int fd)
        => ((ulong)kind << KindShift) | ((ulong)gen << GenShift) | (uint)fd;

    // Edge-triggered and registered once per connection: readiness is tracked by the connection's
    // own read and write states, so nothing is re-armed per operation.
    internal const uint ConnEvents = Native.EPOLLIN | Native.EPOLLPRI | Native.EPOLLOUT | Native.EPOLLRDHUP | Native.EPOLLET;

    // TcpConnection table indexed by fd (dense small ints). Reactor thread only: an outbound
    // connection opened elsewhere is entered by a posted registration.
    private TcpConnection?[] _connections = new TcpConnection?[1024];

    private readonly TcpOptions _tcp;
    private readonly bool _tcpEnabled;
    private readonly ushort _port;

    // Connection objects kept for reuse with their write slabs. Reactor thread only; a connection let
    // go elsewhere comes back through the recycle queue.
    private readonly int _poolMax;
    private readonly Stack<TcpConnection> _pool;

    /// <summary>The reactor's recv buffers, rented by whichever thread receives and returned by whichever consumes.</summary>
    internal readonly BufferPool RecvPool;

    /// <summary>Base-size slabs a segmented write spills into past its primary slab.</summary>
    internal readonly BufferPool WriteSlabPool;

    internal int RecvBufferSize => RecvPool.BufferSize;

    public Reactor(int id, ServerConfig config)
    {
        _id = id;
        _config = config;

        _tcpEnabled = config.Tcp is not null;
        _tcp = config.Tcp ?? new TcpOptions();
        _port = _tcp.Port;

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(config.MaxEvents, "config.MaxEvents");

        // epoll_wait refuses more than INT_MAX / sizeof(struct epoll_event); past it, the event
        // buffer's int-sized allocation in Run wraps and throws OutOfMemoryException first.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(config.MaxEvents, int.MaxValue / Native.EpollEventSize, "config.MaxEvents");
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(config.RecvBufferSize, "config.RecvBufferSize");
        ThrowUnlessPow2(_tcp.RecvQueueEntries, "config.Tcp.RecvQueueEntries");
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(_tcp.WriteSlabSize, "config.Tcp.WriteSlabSize");

        _poolMax = _tcp.PoolMax;
        _pool = new Stack<TcpConnection>(Math.Min(_poolMax, 1024));
        RecvPool = new BufferPool(config.RecvBufferSize);
        WriteSlabPool = new BufferPool(_tcp.WriteSlabSize);
        _readTimeoutMs = _tcp.ReadTimeoutMs;
        _sendTimeoutMs = _tcp.SendTimeoutMs;
    }

    private static void ThrowUnlessPow2(int value, string paramName)
    {
        if (!BitOperations.IsPow2(value))
        {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} ('{value}') must be a power of two.");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private TcpConnection? ConnAt(int fd, ushort gen)
    {
        TcpConnection?[] conns = _connections;
        TcpConnection? conn = (uint)fd < (uint)conns.Length ? conns[fd] : null;
        return conn != null && (ushort)conn.Generation == gen ? conn : null;
    }

    private void Track(int fd, TcpConnection conn)
    {
        if (fd >= _connections.Length)
        {
            int newLength = _connections.Length;
            while (newLength <= fd)
            {
                newLength *= 2;
            }
            Array.Resize(ref _connections, newLength);
        }
        _connections[fd] = conn;
    }

    // Reactor thread only: forget a connection, so no later event or sweep reaches it.
    private void Untrack(TcpConnection conn)
    {
        int fd = conn.ClientFd;
        if ((uint)fd < (uint)_connections.Length && ReferenceEquals(_connections[fd], conn))
        {
            _connections[fd] = null;
        }
    }

    private bool IsTracked(TcpConnection conn)
    {
        int fd = conn.ClientFd;
        return (uint)fd < (uint)_connections.Length && ReferenceEquals(_connections[fd], conn);
    }
}
