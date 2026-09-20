using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks.Sources;

namespace ioxide.redis;

/// <summary>
/// One Redis connection on a reactor's ring. Connect, auth, and every command run as ring ops with
/// inline completion resume. The protocol surface is generic - <see cref="ExecuteAsync(string, RedisArg[])"/>
/// runs any command - with typed helpers (in RedisConnection.Commands.cs) layered on top. Commands are
/// pipelined: many in flight at once, replies routed FIFO, so one connection stays busy under load.
/// </summary>
public sealed partial class RedisConnection : IDisposable
{
    private const int InitialBufferSize = 16 * 1024;
    private const int SendBufferSize = 512 * 1024;   // fixed: a pipelined send holds _send's address, so never realloc'd
    private const int MaxBufferSize = 64 * 1024 * 1024;

    private readonly RingSocket _socket;

    private nint _send;
    private int _sendCapacity;
    private nint _recv;
    private int _recvCapacity;
    private int _received;   // valid bytes in _recv
    private int _scan;       // start of the first unparsed reply
    private int _need;       // examined-cursor: bytes required in [_scan,_received) before the front reply can parse (0 = unknown)

    // Pipelining: commands sent back to back, one RESP reply each, routed FIFO. Single-threaded
    // per reactor, so no locks. _send staged at [_sendOffset, _sendEnd).
    private readonly Queue<Pending> _inflight = new();
    private bool _sending;
    private bool _reading;
    private int _sendOffset;
    private int _sendEnd;

    public bool IsBroken { get; private set; }

    private unsafe RedisConnection(RingSocket socket)
    {
        _socket = socket;
        _send = (nint)NativeMemory.Alloc(SendBufferSize);
        _sendCapacity = SendBufferSize;
        _recv = (nint)NativeMemory.Alloc(InitialBufferSize);
        _recvCapacity = InitialBufferSize;
    }

    public static async Task<RedisConnection> ConnectAsync(IRingHost host, RedisOptions options)
    {
        RingSocket socket = RingSocket.CreateTcp(host);
        var connection = new RedisConnection(socket);

        try
        {
            int rc = await socket.ConnectAsync(options.Host, options.Port);
            if (rc < 0)
            {
                throw RedisException.Transport($"connect to {options.Host}:{options.Port}", rc);
            }

            if (!string.IsNullOrEmpty(options.Password))
            {
                _ = options.User is { } user
                    ? await connection.ExecuteAsync("AUTH", user, options.Password)
                    : await connection.ExecuteAsync("AUTH", options.Password);
            }

            if (options.Database != 0)
            {
                await connection.ExecuteAsync("SELECT", options.Database);
            }

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    // Command names are a tiny fixed set; cache the full pre-framed RESP token ($len\r\nNAME\r\n) so
    // the hot path memcpy's it in one shot - no per-call encoding or framing, no byte[] alloc.
    // Static ConcurrentDictionary: shared and thread-safe across reactors.
    private static readonly ConcurrentDictionary<string, byte[]> CommandCache = new();
    private static byte[] EncodeCommand(string command) =>
        CommandCache.GetOrAdd(command, static c => RespProtocol.FrameName(Encoding.ASCII.GetBytes(c)));

    /// <summary>Run any command and return its reply. Throws on a top-level error reply.</summary>
    public async ValueTask<RespValue> ExecuteAsync(string command, params RedisArg[] args)
    {
        RespValue reply = await SubmitCore(EncodeCommand(command), args);
        if (reply.IsError)
        {
            throw new RedisException(reply.AsString() ?? "redis error");
        }

        return reply;
    }

    // Stage a command, enqueue its waiter, ensure the sender and reader are running.
    private ValueTask<RespValue> SubmitCore(ReadOnlySpan<byte> nameToken, RedisArg[] args)
    {
        if (IsBroken)
        {
            return ValueTask.FromException<RespValue>(new RedisException("connection is broken"));
        }

        try
        {
            AppendCommand(nameToken, args);
        }
        catch (RedisException ex)
        {
            return ValueTask.FromException<RespValue>(ex);
        }

        var pending = new Pending { EnqueuedAtMs = Environment.TickCount64 };
        _inflight.Enqueue(pending);

        if (!_sending)
        {
            _sending = true;
            _ = SenderLoopAsync();
        }

        if (!_reading)
        {
            _reading = true;
            _ = ReaderLoopAsync();
        }

        return new ValueTask<RespValue>(pending, pending.Version);
    }

    /// <summary>
    /// Send several commands back to back and read all replies in one round trip. Each element of
    /// <paramref name="commands"/> is (command, args). Error replies are returned, not thrown, so
    /// the caller can inspect per-command outcomes.
    /// </summary>
    public async ValueTask<RespValue[]> PipelineAsync(params RedisCommand[] commands)
    {
        if (IsBroken)
        {
            throw new RedisException("connection is broken");
        }

        var pending = new ValueTask<RespValue>[commands.Length];
        for (int i = 0; i < commands.Length; i++)
        {
            pending[i] = SubmitCore(commands[i].NameToken, commands[i].Args);
        }

        var replies = new RespValue[commands.Length];
        for (int i = 0; i < commands.Length; i++)
        {
            replies[i] = await pending[i];
        }

        return replies;
    }

    // -- wire I/O ---------------------------------------------------------

    // Append a RESP command to the pipelined send buffer. Fixed buffer (an in-flight send holds its
    // address), so this never realloc's - it throws on overflow instead.
    private unsafe void AppendCommand(ReadOnlySpan<byte> nameToken, RedisArg[] args)
    {
        int size = RespProtocol.CommandSize(nameToken, args);
        if (size > _sendCapacity)
        {
            throw new RedisException($"command exceeds send buffer ({_sendCapacity} bytes)");
        }

        if (_sendEnd + size > _sendCapacity)
        {
            throw new RedisException("pipelined send buffer full");
        }

        int written = RespProtocol.WriteCommand(new Span<byte>((void*)(_send + _sendEnd), _sendCapacity - _sendEnd), nameToken, args);
        _sendEnd += written;
    }

    private async Task SenderLoopAsync()
    {
        try
        {
            while (_sendOffset < _sendEnd)
            {
                int n = await _socket.SendAsync(_send + _sendOffset, _sendEnd - _sendOffset);
                if (n <= 0)
                {
                    IsBroken = true;
                    throw RedisException.Transport("send", n);
                }
                _sendOffset += n;
            }
            // No re-check is needed before clearing _sending: there is no await between the final
            // drain check above and here, and send completions resume inline (synchronously) on the
            // reactor, so no SubmitCore can interleave between them. A command appended while a send
            // was in flight already advanced _sendEnd and was picked up by the loop condition. (This
            // invariant depends on RingOpSource keeping RunContinuationsAsynchronously = false.)
            _sendOffset = 0;   // all staged bytes sent; reuse the buffer from the front
            _sendEnd = 0;
            _sending = false;
        }
        catch (Exception ex)
        {
            IsBroken = true;
            _sending = false;
            FailAll(ex);
        }
    }

    private async Task ReaderLoopAsync()
    {
        try
        {
            while (_inflight.Count > 0)
            {
                RespValue reply = await ReceiveReplyAsync();
                _inflight.Dequeue().Complete(reply);
            }
            _reading = false;
        }
        catch (Exception ex)
        {
            IsBroken = true;
            _reading = false;
            FailAll(ex);
        }
    }

    private void FailAll(Exception ex)
    {
        RedisException re = ex as RedisException ?? new RedisException(ex.Message);
        while (_inflight.TryDequeue(out Pending? p))
        {
            p.Fail(re);
        }
    }

    // Reactor-thread (pool ticker): tear the connection down if its oldest in-flight command is
    // overdue - fail waiters with a diagnostic error and mark it broken; the pool disposes it, and
    // closing the fd cancels the stuck ring recv/send. Returns true if it timed out.
    internal bool CheckTimeout(long nowMs, int timeoutMs, string host, ushort port)
    {
        if (timeoutMs <= 0 || _inflight.Count == 0)
        {
            return false;
        }

        long age = nowMs - _inflight.Peek().EnqueuedAtMs;
        if (age <= timeoutMs)
        {
            return false;
        }

        int inflight = _inflight.Count;
        IsBroken = true;
        FailAll(new RedisException(
            $"redis command timed out after {timeoutMs} ms ({inflight} in flight on {host}:{port}, oldest sent ~{age} ms ago)"));
        return true;
    }

    // One pipelined command: completes its waiter with the RESP reply (inline on the reactor).
    private sealed class Pending : IValueTaskSource<RespValue>
    {
        private ManualResetValueTaskSourceCore<RespValue> _core = new() { RunContinuationsAsynchronously = false };

        public short Version => _core.Version;
        public long EnqueuedAtMs;   // Environment.TickCount64 at enqueue - drives the command-timeout sweep
        public void Complete(RespValue reply) => _core.SetResult(reply);
        public void Fail(RedisException ex) => _core.SetException(ex);

        public RespValue GetResult(short token) => _core.GetResult(token);
        public ValueTaskSourceStatus GetStatus(short token) => _core.GetStatus(token);
        // Completes on the reactor thread only - strip the context-post so resumes stay inline
        // (see ReactorSynchronizationContext).
        public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => _core.OnCompleted(continuation, state, token, flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }

    private async ValueTask<RespValue> ReceiveReplyAsync()
    {
        while (true)
        {
            // Only re-parse once enough bytes for the current sticking point have arrived; below that
            // threshold a re-scan can't make progress (examined-cursor). _need == 0 means "unknown" -
            // parse eagerly.
            if (_received - _scan >= _need)
            {
                if (TryParseReply(out RespValue reply, out int need))
                {
                    _need = 0;
                    return reply;
                }
                _need = need;
            }

            if (_scan == _received)
            {
                _scan = 0;
                _received = 0;
                _need = 0;
            }

            EnsureRecvSpace();

            int n = await _socket.RecvAsync(_recv + _received, _recvCapacity - _received);
            if (n <= 0)
            {
                IsBroken = true;
                throw RedisException.Transport("recv", n);
            }
            _received += n;
        }
    }

    private unsafe bool TryParseReply(out RespValue reply, out int needed)
    {
        var buffered = new ReadOnlySpan<byte>((void*)(_recv + _scan), _received - _scan);
        if (RespProtocol.TryParse(buffered, out reply, out int consumed, out needed))
        {
            _scan += consumed;
            return true;
        }

        return false;
    }

    private unsafe void EnsureRecvSpace()
    {
        if (_received < _recvCapacity)
        {
            return;
        }

        if (_scan > 0)
        {
            Buffer.MemoryCopy((void*)(_recv + _scan), (void*)_recv, _recvCapacity, _received - _scan);
            _received -= _scan;
            _scan = 0;
            return;
        }

        if (_recvCapacity >= MaxBufferSize)
        {
            IsBroken = true;
            throw new RedisException($"reply exceeds {MaxBufferSize} bytes");
        }
        _recvCapacity *= 2;
        _recv = (nint)NativeMemory.Realloc((void*)_recv, (nuint)_recvCapacity);
    }

    public unsafe void Dispose()
    {
        _socket.Dispose();
        if (_send != 0)
        {
            NativeMemory.Free((void*)_send);
            _send = 0;
        }

        if (_recv != 0)
        {
            NativeMemory.Free((void*)_recv);
            _recv = 0;
        }
    }
}

/// <summary>A command for <see cref="RedisConnection.PipelineAsync"/>: a name and its arguments.</summary>
public readonly struct RedisCommand
{
    internal readonly byte[] NameToken;   // pre-framed $len\r\nNAME\r\n
    internal readonly RedisArg[] Args;

    public RedisCommand(string name, params RedisArg[] args)
    {
        NameToken = RespProtocol.FrameName(Encoding.ASCII.GetBytes(name));
        Args = args;
    }
}
