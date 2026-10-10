using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// A client TCP socket whose connect, sends, and receives all run on the host's ring - the
/// building block for ring-native protocol clients. Two op sources (tx/rx) allow one send and one
/// recv in flight concurrently. Results: bytes (0 for connect success) or a negative errno.
/// Dispose only when no operation is in flight.
/// </summary>
public sealed unsafe class RingSocket : IDisposable
{
    private readonly IRingHost _host;
    private readonly RingOpSource _rx = new();
    private readonly RingOpSource _tx = new();

    private sockaddr_in* _connectAddr;   // must outlive the connect op
    private int _disposed;

    public int Fd { get; }

    private RingSocket(IRingHost host, int fd)
    {
        _host = host;
        Fd = fd;
    }

    /// <summary>Create an IPv4 TCP socket (TCP_NODELAY) ready to connect over the ring.</summary>
    public static RingSocket CreateTcp(IRingHost host)
    {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
        {
            throw new InvalidOperationException($"socket() failed: {fd}");
        }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));

        return new RingSocket(host, fd);
    }

    /// <summary>
    /// Connect on the ring. IPv4 literal only - DNS would block the reactor, resolve up front.
    /// </summary>
    public ValueTask<int> ConnectAsync(string ipv4, ushort port)
    {
        if (!IPAddress.TryParse(ipv4, out IPAddress? address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException($"'{ipv4}' is not an IPv4 literal.", nameof(ipv4));
        }

        if (_connectAddr == null)
        {
            _connectAddr = (sockaddr_in*)NativeMemory.AllocZeroed((nuint)sizeof(sockaddr_in));
        }

        Span<byte> bytes = stackalloc byte[4];
        address.TryWriteBytes(bytes, out _);

        _connectAddr->sin_family = AF_INET;
        _connectAddr->sin_port = Htons(port);
        _connectAddr->sin_addr.s_addr = MemoryMarshal.Read<uint>(bytes);   // already network byte order

        ValueTask<int> pending = _rx.Prepare();
        _host.SubmitConnect(Fd, (nint)_connectAddr, sizeof(sockaddr_in), _rx);
        return pending;
    }

    public ValueTask<int> SendAsync(nint buffer, int length)
    {
        ValueTask<int> pending = _tx.Prepare();
        _host.SubmitSend(Fd, buffer, length, _tx);
        return pending;
    }

    public ValueTask<int> RecvAsync(nint buffer, int length)
    {
        ValueTask<int> pending = _rx.Prepare();
        _host.SubmitRecv(Fd, buffer, length, _rx);
        return pending;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        close(Fd);

        if (_connectAddr != null)
        {
            NativeMemory.Free(_connectAddr);
            _connectAddr = null;
        }
    }
}
