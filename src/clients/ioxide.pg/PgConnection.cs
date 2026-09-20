using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks.Sources;

namespace ioxide.pg;

/// <summary>
/// A Postgres connection that runs entirely on the host's ring - connect and handshake included,
/// so opening one never blocks the reactor. Commands are pipelined - many in flight at once,
/// sent back to back, replies routed to waiters in FIFO order - so one connection stays busy under
/// load instead of one round trip at a time. A server ErrorResponse throws but leaves the connection usable (the
/// stream resyncs at ReadyForQuery); a transport failure marks it <see cref="IsBroken"/> and the
/// pool replaces it.
/// </summary>
public sealed class PgConnection : IDisposable
{
    private const int InitialBufferSize = 64 * 1024;
    private const int SendBufferSize = 512 * 1024;   // fixed: a pipelined send holds _send's address, so it is never realloc'd

    // Auto-prepared statement cache cap; past it, new SQL uses the unnamed statement (re-parsed each
    // call, not cached) so a connection can't accumulate unbounded server-side prepared statements.
    private const int MaxPreparedStatements = 256;

    private readonly RingSocket _socket;

    // Native wire buffers. Kept as nint (not byte*) so the async protocol flow can do address
    // arithmetic without an unsafe context; only the small parse/format helpers touch memory.
    private nint _send;
    private int _sendCapacity;
    private nint _recv;
    private int _recvCapacity;
    private readonly int _maxBufferSize;   // ceiling on a single backend message (PgOptions.MaxReceiveBytes)

    private int _received;   // valid bytes in _recv
    private int _scan;       // start of the first unparsed message

    // Pipelining: commands sent back to back, replies routed FIFO. Single-threaded per reactor,
    // so the queue and flags need no locks. _send is staged at [_sendOffset, _sendEnd).
    private readonly Queue<Pending> _inflight = new();
    private bool _sending;
    private bool _reading;
    private int _sendOffset;
    private int _sendEnd;

    // Auto-prepared statements: SQL text -> server statement name. Parse once per connection, then
    // Bind/Execute on every reuse.
    private readonly Dictionary<string, string> _prepared = new();
    private int _statementCounter;

    /// <summary>Transport-level failure happened; the connection must be discarded, not reused.</summary>
    public bool IsBroken { get; private set; }

    private unsafe PgConnection(RingSocket socket, int maxBufferSize)
    {
        _socket = socket;
        _maxBufferSize = maxBufferSize;
        _send = (nint)NativeMemory.Alloc(SendBufferSize);
        _sendCapacity = SendBufferSize;
        _recv = (nint)NativeMemory.Alloc(InitialBufferSize);
        _recvCapacity = InitialBufferSize;
    }

    /// <summary>
    /// Open a connection over the ring: connect, send the startup message, and consume the
    /// handshake until ReadyForQuery.
    /// </summary>
    public static async Task<PgConnection> ConnectAsync(IRingHost host, PgOptions options)
    {
        RingSocket socket = RingSocket.CreateTcp(host);
        var connection = new PgConnection(socket, options.MaxReceiveBytes);

        try
        {
            int rc = await socket.ConnectAsync(options.Host, options.Port);
            if (rc < 0)
            {
                throw PgException.Transport($"connect to {options.Host}:{options.Port}", rc);
            }

            await connection.StartupAsync(options);
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private async Task StartupAsync(PgOptions options)
    {
        int length = WriteStartup(options.User, options.Database);
        await SendAllAsync(length);

        PgScram? scram = null;

        while (true)
        {
            Message message = await ReceiveMessageAsync();

            switch (message.Tag)
            {
                case PgProtocol.Authentication:
                    int code = ReadAuthCode(message);
                    if (code == 0)
                    {
                        break;   // AuthenticationOk
                    }

                    if (code == 10)
                    {
                        // SASL: the server lists mechanisms; we speak SCRAM-SHA-256.
                        if (!ScramOffered(message))
                        {
                            throw new PgException("server offers SASL but not SCRAM-SHA-256");
                        }
                        scram = new PgScram(options.Password
                            ?? throw new PgException("server requires SCRAM-SHA-256 but PgOptions.Password is not set"));
                        await SendAllAsync(WriteSaslInitial(scram.ClientFirst()));
                        break;
                    }

                    if (code == 11)
                    {
                        // SASLContinue: server-first in, client-final (with proof) out.
                        if (scram == null)
                        {
                            throw new PgException("unexpected SASLContinue");
                        }
                        await SendAllAsync(WriteSaslFinal(scram.ClientFinal(ReadAuthData(message))));
                        break;
                    }

                    if (code == 12)
                    {
                        // SASLFinal: verify the server signature.
                        if (scram == null)
                        {
                            throw new PgException("unexpected SASLFinal");
                        }
                        scram.VerifyServerFinal(ReadAuthData(message));
                        break;
                    }
                    throw new PgException($"authentication method {code} not supported (trust or SCRAM-SHA-256)");

                case PgProtocol.ErrorResponse:
                    throw ReadServerError(message);

                case PgProtocol.ReadyForQuery:
                    return;

                // ParameterStatus, BackendKeyData, NoticeResponse: skipped by the walker.
            }
        }
    }

    /// <summary>
    /// Run one simple query, pipelined onto this connection (resumes inline on the reactor): collects
    /// the first column of the first row, the row count, and the command tag. Throws
    /// <see cref="PgException"/> on a server error - after the stream resyncs at ReadyForQuery, so the
    /// connection stays usable.
    /// </summary>
    public ValueTask<PgResult> QueryAsync(string sql) => SubmitAsync(sql, null);

    /// <summary>
    /// Run a parameterized query as a prepared statement - auto-Parse on first use of this SQL on
    /// this connection, then Bind/Execute on every reuse, so the server plans it once. Pipelined and
    /// resumes inline on the reactor, same as <see cref="QueryAsync(string)"/>.
    /// </summary>
    public ValueTask<PgResult> QueryAsync(string sql, ReadOnlySpan<PgParam> args) => SubmitParamAsync(sql, args, null);

    /// <summary>
    /// Prepared parameterized query, streaming each DataRow to <paramref name="onRow"/> (inline). Read
    /// the row count from <see cref="PgResult.Rows"/> on the awaited result.
    /// </summary>
    public ValueTask<PgResult> QueryAsync(string sql, ReadOnlySpan<PgParam> args, PgRowHandler onRow) => SubmitParamAsync(sql, args, onRow);

    // Stage an extended-protocol command (Parse on first use + Bind + Execute + Sync), enqueue its
    // waiter, and make sure the loops run. Synchronous: args is consumed into _send before returning,
    // so the span never crosses an await.
    private ValueTask<PgResult> SubmitParamAsync(string sql, ReadOnlySpan<PgParam> args, PgRowHandler? onRow)
    {
        if (IsBroken)
        {
            return ValueTask.FromException<PgResult>(new PgException("connection is broken"));
        }

        if (args.Length > short.MaxValue)
        {
            return ValueTask.FromException<PgResult>(
                new PgException($"too many parameters ({args.Length}); the Bind message caps at {short.MaxValue}"));
        }

        bool parse = !_prepared.TryGetValue(sql, out string? name);
        if (parse)
        {
            name = _prepared.Count < MaxPreparedStatements ? "s" + _statementCounter++ : "";
        }

        try
        {
            WriteExtendedAt(parse, name!, sql, args);   // append to _send; throws on overflow before any state changes
        }
        catch (PgException ex)
        {
            return ValueTask.FromException<PgResult>(ex);
        }

        bool cached = parse && name!.Length != 0;
        if (cached)
        {
            _prepared[sql] = name!;
        }

        var pending = new Pending(onRow) { PreparedSql = cached ? sql : null, Sql = sql, EnqueuedAtMs = Environment.TickCount64 };
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

        return new ValueTask<PgResult>(pending, pending.Version);
    }

    // Stage the command, enqueue its waiter, and make sure the sender and reader are running.
    private ValueTask<PgResult> SubmitAsync(string sql, PgRowHandler? onRow)
    {
        if (IsBroken)
        {
            return ValueTask.FromException<PgResult>(new PgException("connection is broken"));
        }

        try
        {
            WriteQueryAt(sql);   // append to _send; throws on overflow before any state changes
        }
        catch (PgException ex)
        {
            return ValueTask.FromException<PgResult>(ex);
        }

        var pending = new Pending(onRow) { EnqueuedAtMs = Environment.TickCount64 };
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

        return new ValueTask<PgResult>(pending, pending.Version);
    }

    // Drains the staged send buffer; picks up commands appended while a send was in flight, and
    // reclaims the sent prefix every cycle so the buffer doesn't march to capacity under a sustained
    // submit rate (it is append-only, and resetting only on a full drain rarely happens under load).
    private async Task SenderLoopAsync()
    {
        try
        {
            while (_sendOffset < _sendEnd)
            {
                int end = _sendEnd;   // snapshot; more may be appended (at _sendEnd) while we send
                while (_sendOffset < end)
                {
                    int n = await _socket.SendAsync(_send + _sendOffset, end - _sendOffset);
                    if (n <= 0)
                    {
                        IsBroken = true;
                        throw PgException.Transport("send", n);
                    }
                    _sendOffset += n;
                }

                // The snapshot is fully sent and nothing is in flight, so the consumed prefix is free:
                // slide any bytes appended during the send to the front and continue from there. The
                // reactor is single-threaded, so no append interleaves with this move.
                int tail = _sendEnd - end;
                if (tail > 0)
                {
                    CompactSend(end, tail);
                }
                _sendOffset = 0;
                _sendEnd = tail;
            }
            _sending = false;
        }
        catch (Exception ex)
        {
            IsBroken = true;
            _sending = false;
            FailAll(ex);
        }
    }

    // Move [from, from+length) to the front of the send buffer. CopyTo is memmove-safe for the
    // (rare) case where the appended tail overlaps the front.
    private unsafe void CompactSend(int from, int length)
    {
        new Span<byte>((void*)(_send + from), length).CopyTo(new Span<byte>((void*)_send, length));
    }

    // Reads replies and routes each to the front in-flight command; completes it at ReadyForQuery.
    private async Task ReaderLoopAsync()
    {
        try
        {
            while (_inflight.Count > 0)
            {
                Message message = await ReceiveMessageAsync();
                Pending front = _inflight.Peek();

                switch (message.Tag)
                {
                    case PgProtocol.RowDescription:
                        // Materialize columns only when the caller streams rows; the single-value path
                        // skips this so QueryAsync(sql) stays allocation-free.
                        if (front.OnRow != null)
                        {
                            front.Columns = PgProtocol.ParseRowDescription(Body(message));
                        }
                        break;

                    case PgProtocol.DataRow:
                        front.Rows++;
                        if (front.OnRow != null)
                        {
                            InvokeRow(front.OnRow, front.Columns, in message);
                        }
                        else if (!front.ValueCaptured)
                        {
                            front.ValueCaptured = true;
                            front.Value = ReadFirstField(message);
                        }
                        break;

                    case PgProtocol.CommandComplete:
                        front.CommandTag = ReadBodyCString(message);
                        break;

                    case PgProtocol.ParseComplete:
                    case PgProtocol.BindComplete:
                        break;   // extended-protocol acks; nothing to collect

                    case PgProtocol.ErrorResponse:
                        // Per-command: the stream resyncs at the next ReadyForQuery, so siblings still run.
                        front.Error = ReadServerError(message);
                        if (front.PreparedSql != null)
                        {
                            // The Parse failed - the statement was never created, so drop it and a retry re-parses.
                            _prepared.Remove(front.PreparedSql);
                            front.PreparedSql = null;
                        }
                        else if (front.Sql != null && IsStaleStatement(front.Error))
                        {
                            // A cached statement was invalidated server-side (e.g. a schema change):
                            // evict it so the next call re-parses instead of failing on every call.
                            _prepared.Remove(front.Sql);
                        }
                        break;

                    case PgProtocol.ReadyForQuery:
                        _inflight.Dequeue();
                        front.Complete();
                        break;
                }
            }
            _reading = false;
        }
        catch (Exception ex)
        {
            IsBroken = true;
            _reading = false;
            FailAll(ex is PgException p ? p : new PgException(ex.Message));
        }
    }

    private void FailAll(Exception ex)
    {
        PgException pe = ex as PgException ?? new PgException(ex.Message);
        while (_inflight.TryDequeue(out Pending? p))
        {
            p.Fail(pe);
        }
    }

    // Reactor-thread (pool ticker): if the oldest in-flight command is older than the timeout, tear
    // the connection down - fail its waiters with a diagnostic error and mark it broken. The pool then
    // disposes it, and closing the fd cancels the stuck ring recv/send. Returns true if it timed out.
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
        FailAll(new PgException(
            $"pg command timed out after {timeoutMs} ms ({inflight} in flight on {host}:{port}, oldest sent ~{age} ms ago)"));
        return true;
    }

    // One pipelined command: accumulates its reply and completes its waiter (inline on the reactor).
    private sealed class Pending : IValueTaskSource<PgResult>
    {
        private ManualResetValueTaskSourceCore<PgResult> _core = new() { RunContinuationsAsynchronously = false };

        public readonly PgRowHandler? OnRow;
        public string? Value;
        public bool ValueCaptured;
        public int Rows;
        public string CommandTag = "";
        public PgException? Error;
        public string? PreparedSql;   // set when this command included a Parse, so it can be evicted on error
        public string? Sql;           // SQL text (extended protocol) - for stale-statement cache eviction
        public PgColumn[]? Columns;   // captured from RowDescription for row-streaming queries
        public long EnqueuedAtMs;     // Environment.TickCount64 at enqueue - drives the command-timeout sweep

        public Pending(PgRowHandler? onRow) => OnRow = onRow;
        public short Version => _core.Version;

        public void Complete()
        {
            if (Error != null) _core.SetException(Error);
            else _core.SetResult(new PgResult(Value, Rows, CommandTag, Columns ?? []));
        }

        public void Fail(PgException ex) => _core.SetException(ex);

        public PgResult GetResult(short token) => _core.GetResult(token);
        public ValueTaskSourceStatus GetStatus(short token) => _core.GetStatus(token);
        // Completes on the reactor thread only - strip the context-post so resumes stay inline
        // (see ReactorSynchronizationContext).
        public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => _core.OnCompleted(continuation, state, token, flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }

    private readonly record struct Message(byte Tag, int BodyStart, int BodyLength);

    private async ValueTask<Message> ReceiveMessageAsync()
    {
        while (true)
        {
            if (TryParseMessage(out Message message))
            {
                return message;
            }

            // Everything buffered is consumed - rewind so the buffer never fills
            // from pure accumulation across queries.
            if (_scan == _received)
            {
                _scan = 0;
                _received = 0;
            }

            EnsureRecvSpace();

            int n = await _socket.RecvAsync(_recv + _received, _recvCapacity - _received);
            if (n <= 0)
            {
                IsBroken = true;
                throw PgException.Transport("recv", n);
            }
            _received += n;
        }
    }

    private async ValueTask SendAllAsync(int length)
    {
        int sent = 0;
        while (sent < length)
        {
            int n = await _socket.SendAsync(_send + sent, length - sent);
            if (n <= 0)
            {
                IsBroken = true;
                throw PgException.Transport("send", n);
            }
            sent += n;
        }
    }

    private unsafe bool TryParseMessage(out Message message)
    {
        var buffered = new ReadOnlySpan<byte>((void*)_recv, _received);
        int position = _scan;

        try
        {
            if (PgProtocol.TryReadMessage(buffered, ref position, out byte tag, out int bodyStart, out int bodyLength))
            {
                _scan = position;
                message = new Message(tag, bodyStart, bodyLength);
                return true;
            }
        }
        catch (PgException)
        {
            // Malformed framing - the stream can't be resynchronized.
            IsBroken = true;
            throw;
        }

        message = default;
        return false;
    }

    private unsafe void EnsureRecvSpace()
    {
        if (_received < _recvCapacity)
        {
            return;
        }

        // Buffer is full with a partial message at the end. First reclaim the
        // consumed prefix; only grow when a single message outsizes the buffer.
        if (_scan > 0)
        {
            Buffer.MemoryCopy((void*)(_recv + _scan), (void*)_recv, _recvCapacity, _received - _scan);
            _received -= _scan;
            _scan = 0;
            return;
        }

        if (_recvCapacity >= _maxBufferSize)
        {
            IsBroken = true;
            throw new PgException($"backend message exceeds {_maxBufferSize} bytes");
        }

        _recvCapacity *= 2;
        _recv = (nint)NativeMemory.Realloc((void*)_recv, (nuint)_recvCapacity);
    }

    /// <summary>
    /// Run one simple query, streaming every DataRow to <paramref name="onRow"/> (inline, on the
    /// reactor) and returning the row count. <see cref="PgRow.Columns"/> is populated for by-name
    /// access. Server errors throw after the stream resyncs at ReadyForQuery, like <see cref="QueryAsync(string)"/>.
    /// </summary>
    public async ValueTask<int> QueryRowsAsync(string sql, PgRowHandler onRow)
    {
        PgResult result = await SubmitAsync(sql, onRow);
        return result.Rows;
    }

    private unsafe void InvokeRow(PgRowHandler onRow, PgColumn[]? columns, in Message message)
    {
        onRow(new PgRow(new ReadOnlySpan<byte>((void*)(_recv + message.BodyStart), message.BodyLength), columns));
    }

    // SQLSTATEs that mean a cached prepared statement is no longer valid - its plan/result type
    // changed (0A000) or it doesn't exist on the server (26000). Evicting lets the next call re-Parse.
    private static bool IsStaleStatement(PgException error) =>
        error.SqlState is "0A000" or "26000";

    private unsafe bool ScramOffered(in Message message)
    {
        ReadOnlySpan<byte> body = Body(message);
        return body.Length > 4 && PgProtocol.OffersScramSha256(body[4..]);
    }

    private unsafe string ReadAuthData(in Message message)
    {
        ReadOnlySpan<byte> body = Body(message);
        return Encoding.UTF8.GetString(body[4..]);
    }

    private unsafe int WriteSaslInitial(string clientFirst)
    {
        byte[] payload = Encoding.UTF8.GetBytes(clientFirst);
        return PgProtocol.WriteSaslInitialResponse(new Span<byte>((void*)_send, _sendCapacity), "SCRAM-SHA-256", payload);
    }

    private unsafe int WriteSaslFinal(string clientFinal)
    {
        byte[] payload = Encoding.UTF8.GetBytes(clientFinal);
        return PgProtocol.WriteSaslResponse(new Span<byte>((void*)_send, _sendCapacity), payload);
    }

    private unsafe int WriteStartup(string user, string database)
    {
        return PgProtocol.WriteStartup(new Span<byte>((void*)_send, _sendCapacity), user, database);
    }

    // Append a Query message to the pipelined send buffer. Fixed buffer (an in-flight send holds its
    // address), so this never realloc's - it throws on overflow instead.
    private unsafe void WriteQueryAt(string sql)
    {
        int needed = PgProtocol.QueryLength(sql);
        if (needed > _sendCapacity)
        {
            throw new PgException($"query exceeds send buffer ({_sendCapacity} bytes)");
        }

        if (_sendEnd + needed > _sendCapacity)
        {
            throw new PgException("pipelined send buffer full");
        }

        int written = PgProtocol.WriteQuery(new Span<byte>((void*)(_send + _sendEnd), _sendCapacity - _sendEnd), sql);
        _sendEnd += written;
    }

    // Append an extended-protocol command (Parse? + Bind + Execute + Sync) to the pipelined send
    // buffer. Fixed buffer like WriteQueryAt: throws on overflow rather than realloc'ing.
    private unsafe void WriteExtendedAt(bool parse, string statementName, string sql, ReadOnlySpan<PgParam> args)
    {
        int needed = PgProtocol.ExtendedLength(parse, statementName, sql, args);
        if (needed > _sendCapacity)
        {
            throw new PgException($"query exceeds send buffer ({_sendCapacity} bytes)");
        }

        if (_sendEnd + needed > _sendCapacity)
        {
            throw new PgException("pipelined send buffer full");
        }

        int written = PgProtocol.WriteExtended(
            new Span<byte>((void*)(_send + _sendEnd), _sendCapacity - _sendEnd), parse, statementName, sql, args);
        _sendEnd += written;
    }

    private unsafe ReadOnlySpan<byte> Body(in Message message)
    {
        return new ReadOnlySpan<byte>((void*)(_recv + message.BodyStart), message.BodyLength);
    }

    private string? ReadFirstField(in Message message)
    {
        ReadOnlySpan<byte> body = Body(message);
        if (!PgProtocol.TryReadFirstField(body, out int offset, out int length) || length < 0)
        {
            return null;   // no fields, or SQL NULL
        }

        return Encoding.UTF8.GetString(body.Slice(offset, length));
    }

    private string ReadBodyCString(in Message message)
    {
        return PgProtocol.ReadCString(Body(message));
    }

    private int ReadAuthCode(in Message message)
    {
        return PgProtocol.ReadAuthCode(Body(message));
    }

    private PgException ReadServerError(in Message message)
    {
        (string severity, string sqlState, string text) = PgProtocol.ReadError(Body(message));
        return new PgException(severity, sqlState, text);
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
