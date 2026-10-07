namespace ioxide.pg;

/// <summary>
/// N Postgres connections on one reactor's ring, with pipelining. Commands round-robin across the
/// connections and each connection multiplexes many in flight, so the connections stay busy under
/// load instead of one round trip at a time. Broken connections are evicted and replaced. One pool
/// per reactor - create from <c>Reactor.OnStart</c>.
/// </summary>
/// <remarks>
/// Not thread-safe by design: every member must run on the owning reactor thread - queries arrive
/// from reactor-thread handlers and connect completions resume there too. Do not call the pool from
/// off-reactor code.
/// </remarks>
public sealed class PgPool
{
    // Bound the slow-path wait so a pool that can't reach Postgres fails fast with a clear error
    // instead of parking queries forever; each attempt drives one coalesced connect try.
    private const int MaxConnectAttempts = 10;

    private readonly List<PgConnection> _connections = new();
    private readonly IRingHost _host;
    private readonly PgOptions _options;
    private int _next;
    private int _opening;                          // in-flight connect attempts (coalesces opens)
    private long _reopenAtMs;                       // jittered backoff gate for background replenishment
    private TaskCompletionSource<bool>? _opened;   // completed when any open attempt finishes

    private PgPool(IRingHost host, PgOptions options)
    {
        _host = host;
        _options = options;
    }

    /// <summary>Open <see cref="PgOptions.PoolSize"/> connections and register the pool as a service.</summary>
    public static PgPool Start(Reactor reactor, PgOptions options)
    {
        var pool = new PgPool(reactor, options);
        for (int i = 0; i < options.PoolSize; i++)
        {
            pool.StartOpen();
        }
        reactor.AddService(pool);
        reactor.AddTicker(pool.Sweep);   // per-command timeout sweep + background replenishment
        return pool;
    }

    // Begin one connect attempt; OpenOneAsync clears the in-flight count and wakes waiters when done.
    private void StartOpen()
    {
        _opening++;
        _ = OpenOneAsync();
    }

    private async Task OpenOneAsync()
    {
        try
        {
            PgConnection connection = await PgConnection.ConnectAsync(_host, _options);
            _connections.Add(connection);
            _reopenAtMs = 0;   // healthy - allow immediate replenishment
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[pg] connect to {_options.Host}:{_options.Port} failed: {e.Message}");
            _reopenAtMs = Environment.TickCount64 + BackoffMs();   // jittered backoff before the next attempt
        }
        finally
        {
            _opening--;
            // Wake every slow-path waiter whether the attempt succeeded or failed, so a run of
            // failures surfaces as a fast error instead of a permanent hang. Swap the field out
            // before completing so a fresh waiter arms a new signal.
            TaskCompletionSource<bool>? signal = _opened;
            _opened = null;
            signal?.TrySetResult(true);
        }
    }

    /// <summary>Live connections (for diagnostics).</summary>
    public int ConnectionCount => _connections.Count;

    /// <summary>Run one simple query on the next connection (pipelined).</summary>
    public ValueTask<PgResult> QueryAsync(string sql)
    {
        PgConnection? c = Pick();
        return c != null ? c.QueryAsync(sql) : QuerySlowAsync(sql);
    }

    /// <summary>Run one simple query, streaming rows through <paramref name="onRow"/> (pipelined).</summary>
    public ValueTask<int> QueryRowsAsync(string sql, PgRowHandler onRow)
    {
        PgConnection? c = Pick();
        return c != null ? c.QueryRowsAsync(sql, onRow) : QueryRowsSlowAsync(sql, onRow);
    }

    /// <summary>Run a prepared parameterized query on the next connection (pipelined).</summary>
    public ValueTask<PgResult> QueryAsync(string sql, ReadOnlySpan<PgParam> args)
    {
        PgConnection? c = Pick();
        // Slow path is startup-only (no connection open yet); copying the params to the heap there is
        // fine, and keeps the span off the async state machine.
        return c != null ? c.QueryAsync(sql, args) : QuerySlowAsync(sql, args.ToArray());
    }

    /// <summary>Run a prepared parameterized query, streaming rows through <paramref name="onRow"/>. Read the count from the result.</summary>
    public ValueTask<PgResult> QueryAsync(string sql, ReadOnlySpan<PgParam> args, PgRowHandler onRow)
    {
        PgConnection? c = Pick();
        return c != null ? c.QueryAsync(sql, args, onRow) : QueryRowsSlowAsync(sql, args.ToArray(), onRow);
    }

    private async ValueTask<PgResult> QuerySlowAsync(string sql)
        => await (await WaitForConnectionAsync()).QueryAsync(sql);

    private async ValueTask<int> QueryRowsSlowAsync(string sql, PgRowHandler onRow)
        => await (await WaitForConnectionAsync()).QueryRowsAsync(sql, onRow);

    private async ValueTask<PgResult> QuerySlowAsync(string sql, PgParam[] args)
        => await (await WaitForConnectionAsync()).QueryAsync(sql, args);

    private async ValueTask<PgResult> QueryRowsSlowAsync(string sql, PgParam[] args, PgRowHandler onRow)
        => await (await WaitForConnectionAsync()).QueryAsync(sql, args, onRow);

    // Round-robin over healthy connections; evict and replace any found broken.
    private PgConnection? Pick()
    {
        while (_connections.Count > 0)
        {
            int index = (_next++ & 0x7fffffff) % _connections.Count;
            PgConnection c = _connections[index];
            if (!c.IsBroken)
            {
                return c;
            }
            _connections.RemoveAt(index);
            c.Dispose();
            StartOpen();
        }
        return null;
    }

    // No live connection (cold start, or every connection broke). Drive coalesced connect attempts
    // and wait for one to finish; fail fast after MaxConnectAttempts so queries never hang.
    private async ValueTask<PgConnection> WaitForConnectionAsync()
    {
        for (int attempt = 1; ; attempt++)
        {
            PgConnection? c = Pick();
            if (c != null)
            {
                return c;
            }

            if (attempt > MaxConnectAttempts)
            {
                throw new PgException(
                    $"pg pool: no connection to {_options.Host}:{_options.Port} after {MaxConnectAttempts} attempts");
            }

            _opened ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task wait = _opened.Task;
            if (_opening == 0)
            {
                StartOpen();   // nothing live and nothing opening - kick one off
            }
            await wait;
        }
    }

    // Reactor-thread ticker (~250 ms): time out stuck connections and replenish toward PoolSize.
    private void Sweep()
    {
        long now = Environment.TickCount64;

        int timeoutMs = _options.CommandTimeoutMs;
        if (timeoutMs > 0)
        {
            for (int i = _connections.Count - 1; i >= 0; i--)
            {
                PgConnection c = _connections[i];
                if (c.CheckTimeout(now, timeoutMs, _options.Host, _options.Port))
                {
                    // Its failed waiters resumed inline, and a Pick of theirs may have removed it or others.
                    _connections.Remove(c);
                    c.Dispose();   // closes the fd - unsticks the connection's stuck send/recv loops
                    i = Math.Min(i, _connections.Count);
                }
            }
        }

        // Background replenishment toward PoolSize, gated by a jittered backoff so a recovering
        // server isn't hammered by every reactor at once.
        if (_connections.Count < _options.PoolSize && _opening == 0 && now >= _reopenAtMs)
        {
            StartOpen();
        }
    }

    private static int BackoffMs() => 200 + Random.Shared.Next(400);   // jittered ~200-600 ms
}
