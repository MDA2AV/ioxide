using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// One reactor = one thread + one io_uring + one SO_REUSEPORT listener + one connection table.
/// The reactor thread is the sole writer of the SQ, the buf_ring, and the connection table;
/// off-reactor handlers reach it through MPSC queues woken by an eventfd poll.
/// </summary>
public sealed unsafe partial class Reactor
{
    private readonly int _id;

    /// <summary>
    /// This reactor's position in the fleet - the <c>id</c> it was constructed with, in
    /// <c>0 .. ShardCount-1</c>. QUIC stamps it into the connection ids it mints so the kernel can
    /// steer a connection's datagrams back here after the client changes address.
    /// </summary>
    public int ShardIndex => _id;

    /// <summary>How many reactors share this server's ports (<see cref="ServerConfig.ReactorCount"/>).</summary>
    public int ShardCount => _config.ReactorCount;
    private Ring _ring = null!;   // created on the reactor thread (DEFER_TASKRUN requires same-thread setup+enter)

    // TcpConnection table indexed by fd (dense small ints - array beats Dictionary per CQE).
    private TcpConnection?[] _connections = new TcpConnection?[4096];

    // The response-send strategy from config (ZeroCopySend), copied per-connection at accept into
    // TcpConnection.UseZc. The send hot path branches on that bool (predictable, inlinable) instead of
    // dispatching through an indirect function pointer.
    private readonly bool _zeroCopySend;
    private readonly ushort _port;
    private readonly uint _ringEntries;
    private readonly uint _recvBufferSize;

    // user_data: [63:56] kind | [47:32] connection generation | [31:0] fd (or client-op slot).
    // The generation makes straggler CQEs from a reused fd detectable as stale.
    private const int  KindShift  = 56;
    private const int  GenShift   = 32;
    private const byte KindTcpAccept = 1;
    private const byte KindTcpRecv   = 2;
    private const byte KindTcpSend   = 3;
    private const byte KindWake      = 4;
    private const byte KindClient    = 5;   // low 32 bits = op slot (Reactor.RingHost.cs)
    private const byte KindCancel    = 6;
    private const byte KindTimer     = 7;
    private const byte KindUdpRecv   = 8;   // low 32 bits = recv-slot index (Reactor.Udp.cs)
    private const byte KindUdpSend   = 9;   // low 32 bits = send-slot index (Reactor.Udp.cs)

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Tag(byte kind, ushort gen, int fd)
        => ((ulong)kind << KindShift) | ((ulong)gen << GenShift) | (uint)fd;

    // Shared provided-buffer ring (one per reactor).
    private const ushort BgId = 1;
    private readonly uint _bufferRingEntries;   // power of two
    private byte*  _bufRing;                   // io_uring_buf_ring (kernel-shared)
    private byte*  _bufSlab;
    private uint   _bufRingMask;
    private ushort _bufRingTail;

    // Transport settings resolved once. _tcp / _udp are always non-null so the sizing knobs stay
    // readable; the _enabled flags record whether the config actually asked for that transport.
    // TCP off = no listener. UDP off = no raw datagram sockets, though QUIC still binds its own
    // port and uses the resolved defaults.
    private readonly TcpOptions _tcp;
    private readonly bool _tcpEnabled;
    private readonly UdpOptions _udp;
    private readonly bool _udpEnabled;

    // TcpConnection pool, reactor-thread-only. PoolMax × WriteSlabSize × ReactorCount bounds
    // the reserved native memory.
    private readonly int _poolMax;
    private readonly Stack<TcpConnection> _pool;

    // Per-reactor pool of base-size write slabs, rented by connections in Segmented overflow mode.
    // Reactor-thread-only, so no locking. Capped so a burst of large responses doesn't retain memory.
    private readonly Stack<nint> _writeSlabPool = new();
    private const int WriteSlabPoolMax = 4096;

    internal nint RentWriteSlab()
        => _writeSlabPool.TryPop(out nint p) ? p : (nint)NativeMemory.AlignedAlloc((nuint)_tcp.WriteSlabSize, 64);

    internal void ReturnWriteSlab(nint p)
    {
        if (_writeSlabPool.Count < WriteSlabPoolMax)
        {
            _writeSlabPool.Push(p);
        }
        else
        {
            NativeMemory.AlignedFree((void*)p);
        }
    }

    // Incremental-mode sizing (see Reactor.Incremental.cs).
    private readonly int  _maxConnections;       // one bgid per active connection
    private readonly int  _connBufRingEntries;
    private readonly uint _incRecvBufferSize;

    // Transient io_uring_enter errnos.
    private const int EINTR  = 4;
    private const int EAGAIN = 11;
    private const int EBUSY  = 16;

    public Reactor(int id, ServerConfig config)
    {
        _id = id;
        _config = config;

        // Tcp == null means "no TCP listener". The sizing knobs are still resolved from a default
        // instance so the pools below stay valid; they simply go unused when TCP is off.
        _tcpEnabled = config.Tcp is not null;
        _tcp = config.Tcp ?? new TcpOptions();
        _udpEnabled = config.Udp is not null;
        _udp = config.Udp ?? new UdpOptions();

        _port = _tcp.Port;
        _ringEntries = config.RingEntries;
        _incremental = config.Incremental is not null;
        _recvBufferSize = (uint)config.RecvBufferSize;
        _bufferRingEntries = (uint)config.RecvSlots;
        _poolMax = _tcp.PoolMax;
        IncrementalOptions inc = config.Incremental ?? new IncrementalOptions();
        _maxConnections = inc.MaxConnections;
        _connBufRingEntries = inc.RecvSlots;
        _incRecvBufferSize = (uint)inc.RecvBufferSize;
        _pool = new Stack<TcpConnection>(_tcp.PoolMax);
        _zeroCopySend = _tcp.ZeroCopySend;
        _idleTimeoutMs = _tcp.IdleTimeoutMs;
        _sendTimeoutMs = _tcp.SendTimeoutMs;
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

    // Stage a buffer without publishing; batch drains publish once for N buffers.
    private void ReturnBufferLocal(ushort bid)
    {
        byte* slot = _bufRing + (_bufRingTail & _bufRingMask) * 16;
        *(ulong*)(slot + 0)  = (ulong)(_bufSlab + bid * (nuint)_recvBufferSize);
        *(uint*)(slot + 8)   = _recvBufferSize;
        *(ushort*)(slot + 12) = bid;
        _bufRingTail++;
        _buffersReturned = true;   // lets the loop re-arm recvs parked on -ENOBUFS (#93)
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void PublishBufRingTail()
    {
        Volatile.Write(ref *(ushort*)(_bufRing + 14), _bufRingTail);
    }

    // Reactor-thread-only; off-reactor callers use EnqueueReturnQ.
    internal void ReturnBufferDirect(ushort bid)
    {
        ReturnBufferLocal(bid);
        PublishBufRingTail();
    }

    // SQE producers - reactor-thread-only.
    private IoUringSqe* GetSqeOrFlush()
    {
        IoUringSqe* sqe = _ring.GetSqe();
        if (sqe != null)
        {
            return sqe;
        }

        // SQ is full: flush queued SQEs to the kernel (which frees ring slots) and retry. A few
        // submit rounds clear the transient fullness a large CQE batch can cause; only a genuinely
        // stuck ring falls through to throw, instead of crashing the reactor on the first miss.
        for (int attempt = 0; attempt < 16 && sqe == null; attempt++)
        {
            _ring.SubmitAndWait(0);
            sqe = _ring.GetSqe();
        }

        if (sqe == null)
        {
            throw new InvalidOperationException("io_uring SQ still full after repeated flush");
        }

        return sqe;
    }
}
