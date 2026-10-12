using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using RESPite.Transports;

namespace ioxide.redis.stackexchange;

/// <summary>
/// One StackExchange.Redis connection as a socket on a reactor's ring. Receives are ring operations
/// whose completions push the bytes into StackExchange.Redis on the reactor's thread, where it parses
/// them and completes the commands; each loop turn that delivered anything ends with one
/// <see cref="TransportReceiver.OnBatchEnd"/>, posted to run after the turn's completions. Writers
/// stage from any thread (StackExchange.Redis keeps to one at a time) and <see cref="Flush"/> hands
/// the batch to the ring as one send.
/// </summary>
internal sealed class IoxideTransport : DuplexTransport
{
    private const int InitialOutbound = 16 * 1024;

    private readonly Reactor _reactor;
    private readonly RingSocket _socket;
    private readonly byte[] _received;

    // The send side. The writer owns _stage; a send in flight owns _wire; bytes flushed while it is
    // in flight wait in _queued and go next. Only the swaps between them take the lock.
    private readonly object _gate = new();
    private Outbound _stage = new(), _wire = new(), _queued = new();
    private bool _sending;
    private int _sent;

    private TransportReceiver? _receiver;
    private bool _batchEndPosted;   // reactor thread only
    private int _closing;
    private Exception? _fault;

    // The transport's own reference, the receive loop's and a send's: the socket is disposed, and the
    // receiver told, when the last of them lets go - never under an operation still in flight.
    private int _refs = 1;
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private IoxideTransport(Reactor reactor, RingSocket socket, int receiveBufferSize)
    {
        _reactor = reactor;
        _socket = socket;
        _received = GC.AllocateUninitializedArray<byte>(receiveBufferSize, pinned: true);
    }

    /// <summary>Resolve <paramref name="endpoint"/> and connect to its addresses in turn, on
    /// <paramref name="reactor"/>'s ring.</summary>
    internal static async ValueTask<IoxideTransport> ConnectAsync(
        Reactor reactor, EndPoint endpoint, int receiveBufferSize, CancellationToken cancellationToken)
    {
        (IPAddress[] addresses, int port) = await ResolveAsync(endpoint, cancellationToken).ConfigureAwait(false);
        string? failure = null;

        foreach (IPAddress address in addresses)
        {
            RingSocket socket = RingSocket.CreateTcp(reactor, address.AddressFamily);
            Task<int> connect = socket.ConnectAsync(address, (ushort)port).AsTask();
            int result;
            try
            {
                result = await connect.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // A ring connect cannot be cancelled: the socket goes once the connect completes.
                _ = connect.ContinueWith(static (_, state) => ((RingSocket)state!).Dispose(), socket,
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                throw;
            }

            if (result == 0)
            {
                return new IoxideTransport(reactor, socket, receiveBufferSize);
            }

            socket.Dispose();
            failure = $"connect to {new IPEndPoint(address, port)} failed: errno {-result}";
        }

        throw new IOException(failure ?? $"{endpoint} resolved to no address");
    }

    private static async ValueTask<(IPAddress[] Addresses, int Port)> ResolveAsync(
        EndPoint endpoint, CancellationToken cancellationToken)
    {
        if (endpoint is IPEndPoint ip)
        {
            return ([ip.Address], ip.Port);
        }

        if (endpoint is DnsEndPoint dns)
        {
            if (IPAddress.TryParse(dns.Host, out IPAddress? literal))
            {
                return ([literal], dns.Port);
            }

            // Off the reactor: a lookup blocks its thread.
            return (await Dns.GetHostAddressesAsync(dns.Host, cancellationToken).ConfigureAwait(false), dns.Port);
        }

        throw new NotSupportedException($"the ioxide transport connects over TCP only, not to a {endpoint.GetType().Name}");
    }

    // ---- inbound ----------------------------------------------------------------------------

    public override void Start(TransportReceiver receiver)
    {
        if (Interlocked.CompareExchange(ref _receiver, receiver, null) is not null)
        {
            throw new InvalidOperationException("the transport already has its receiver");
        }

        if (!TryAddRef())
        {
            return;   // closed before it started: the receiver was never going to hear anything
        }

        _ = ReceiveAsync();
    }

    private async Task ReceiveAsync()
    {
        Exception? fault = null;
        try
        {
            nint buffer = Address(_received);
            while (Volatile.Read(ref _closing) == 0)
            {
                // Resumes inline on the reactor thread when the receive completes.
                int received = await _socket.RecvAsync(buffer, _received.Length);
                if (received <= 0)
                {
                    if (received < 0 && Volatile.Read(ref _closing) == 0)
                    {
                        fault = new IOException($"receive failed: errno {-received}");
                    }
                    break;
                }

                if (!_receiver!.OnReceived(_received.AsSpan(0, received)))
                {
                    break;   // the receiver asked to close
                }

                if (!_batchEndPosted)
                {
                    // A post from the reactor thread runs after this turn's completions, which is
                    // where the burst ends.
                    _batchEndPosted = true;
                    _reactor.ScheduleOnReactor(static state => ((IoxideTransport)state!).EndBatch(), this);
                }
            }
        }
        catch (Exception e)
        {
            fault = e;
        }

        Close(fault);
        Release();
    }

    private void EndBatch()
    {
        _batchEndPosted = false;
        if (Volatile.Read(ref _closing) == 0)
        {
            _receiver?.OnBatchEnd();
        }
    }

    // ---- outbound ---------------------------------------------------------------------------

    public override Memory<byte> GetMemory(int sizeHint = 0) => _stage.Reserve(sizeHint).AsMemory(_stage.Length);

    public override Span<byte> GetSpan(int sizeHint = 0) => _stage.Reserve(sizeHint).AsSpan(_stage.Length);

    public override void Advance(int count) => _stage.Length += count;

    public override bool Flush()
    {
        if (Volatile.Read(ref _closing) != 0)
        {
            _stage.Length = 0;
            return false;
        }

        if (_stage.Length == 0)
        {
            return true;
        }

        lock (_gate)
        {
            if (_sending)
            {
                _queued.Append(_stage.Bytes.AsSpan(0, _stage.Length));   // goes when the send in flight is done
                _stage.Length = 0;
                return true;
            }

            // The staged bytes become the send, and the writer stages into the idle buffer.
            (_stage, _wire) = (_wire, _stage);
            _stage.Length = 0;
            _sent = 0;
            _sending = true;
        }

        if (!TryAddRef())
        {
            lock (_gate)
            {
                _sending = false;
            }
            return false;
        }

        _ = SendAsync();
        return true;
    }

    private async Task SendAsync()
    {
        try
        {
            while (true)
            {
                byte[] bytes;
                int from, to;
                lock (_gate)
                {
                    (bytes, from, to) = (_wire.Bytes, _sent, _wire.Length);
                }

                int sent = await _socket.SendAsync(Address(bytes) + from, to - from);
                if (sent <= 0)
                {
                    Close(sent < 0 ? new IOException($"send failed: errno {-sent}") : null);
                    break;
                }

                lock (_gate)
                {
                    _sent += sent;
                    if (_sent < _wire.Length)
                    {
                        continue;   // a partial send: the rest goes next
                    }

                    if (_queued.Length == 0)
                    {
                        _sending = false;
                        break;
                    }

                    (_wire, _queued) = (_queued, _wire);
                    _queued.Length = 0;
                    _sent = 0;
                }
            }
        }
        catch (Exception e)
        {
            Close(e);
        }

        Release();
    }

    // ---- lifetime ---------------------------------------------------------------------------

    public override ValueTask DisposeAsync()
    {
        Close(null);
        return new ValueTask(_closed.Task);
    }

    private void Close(Exception? fault)
    {
        if (Interlocked.Exchange(ref _closing, 1) != 0)
        {
            return;
        }

        _fault = fault;
        Native.shutdown(_socket.Fd, Native.SHUT_RDWR);   // ends the receive in flight, and a stuck send
        Release();                                       // the transport's own reference
    }

    private bool TryAddRef()
    {
        int refs;
        do
        {
            refs = Volatile.Read(ref _refs);
            if (refs == 0)
            {
                return false;
            }
        }
        while (Interlocked.CompareExchange(ref _refs, refs + 1, refs) != refs);
        return true;
    }

    private void Release()
    {
        if (Interlocked.Decrement(ref _refs) != 0)
        {
            return;
        }

        _socket.Dispose();
        Interlocked.Exchange(ref _receiver, null)?.OnClosed(_fault);
        _closed.TrySetResult();
    }

    private static unsafe nint Address(byte[] pinned) => (nint)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(pinned));

    /// <summary>A growable outbound buffer on the pinned object heap, so the ring can read it in place.</summary>
    private sealed class Outbound
    {
        public byte[] Bytes = GC.AllocateUninitializedArray<byte>(InitialOutbound, pinned: true);
        public int Length;

        public byte[] Reserve(int sizeHint)
        {
            int needed = Length + Math.Max(sizeHint, 1);
            if (needed > Bytes.Length)
            {
                byte[] grown = GC.AllocateUninitializedArray<byte>(Math.Max(needed, Bytes.Length * 2), pinned: true);
                Bytes.AsSpan(0, Length).CopyTo(grown);
                Bytes = grown;
            }
            return Bytes;
        }

        public void Append(ReadOnlySpan<byte> bytes)
        {
            bytes.CopyTo(Reserve(bytes.Length).AsSpan(Length));
            Length += bytes.Length;
        }
    }
}
