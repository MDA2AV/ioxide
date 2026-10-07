namespace ioxide.redis;

/// <summary>
/// N Redis connections on one reactor's ring, with pipelining. Commands round-robin across the
/// connections and each connection multiplexes many in flight, so the connections stay busy under
/// load instead of one round trip at a time. Broken connections are evicted and replaced. One pool
/// per reactor - create from <c>Reactor.OnStart</c>.
/// </summary>
/// <remarks>
/// Not thread-safe by design: every member must run on the owning reactor thread - commands arrive
/// from reactor-thread handlers and connect completions resume there too. Do not call the pool from
/// off-reactor code.
/// </remarks>
public sealed class RedisPool
{
    // Bound the slow-path wait so a pool that can't reach Redis fails fast with a clear error
    // instead of parking commands forever; each attempt drives one coalesced connect try.
    private const int MaxConnectAttempts = 10;

    private readonly List<RedisConnection> _connections = new();
    private readonly IRingHost _host;
    private readonly RedisOptions _options;
    private int _next;
    private int _opening;                          // in-flight connect attempts (coalesces opens)
    private long _reopenAtMs;                       // jittered backoff gate for background replenishment
    private TaskCompletionSource<bool>? _opened;   // completed when any open attempt finishes

    private RedisPool(IRingHost host, RedisOptions options)
    {
        _host = host;
        _options = options;
    }

    /// <summary>Open <see cref="RedisOptions.PoolSize"/> connections and register the pool as a service.</summary>
    public static RedisPool Start(Reactor reactor, RedisOptions options)
    {
        var pool = new RedisPool(reactor, options);
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
            RedisConnection connection = await RedisConnection.ConnectAsync(_host, _options);
            _connections.Add(connection);
            _reopenAtMs = 0;   // healthy - allow immediate replenishment
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[redis] connect to {_options.Host}:{_options.Port} failed: {e.Message}");
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

    /// <summary>Run any command on the next connection (pipelined).</summary>
    public ValueTask<RespValue> ExecuteAsync(string command, params RedisArg[] args)
    {
        RedisConnection? c = Pick();
        return c != null ? c.ExecuteAsync(command, args) : ExecuteSlowAsync(command, args);
    }

    /// <summary>Send several commands on one connection in a single round trip; replies returned in order.</summary>
    public ValueTask<RespValue[]> PipelineAsync(params RedisCommand[] commands)
    {
        RedisConnection? c = Pick();
        return c != null ? c.PipelineAsync(commands) : PipelineSlowAsync(commands);
    }

    /// <summary>GET (the cache-aside read path).</summary>
    public ValueTask<string?> GetAsync(string key)
    {
        RedisConnection? c = Pick();
        return c != null ? c.GetAsync(key) : GetSlowAsync(key);
    }

    /// <summary>SET key value EX seconds (the cache-aside populate path).</summary>
    public ValueTask SetExAsync(string key, RedisArg value, int seconds)
    {
        RedisConnection? c = Pick();
        return c != null ? c.SetExAsync(key, value, seconds) : SetExSlowAsync(key, value, seconds);
    }

    /// <summary>DEL (cache invalidation).</summary>
    public ValueTask<long> DelAsync(params string[] keys)
    {
        RedisConnection? c = Pick();
        return c != null ? c.DelAsync(keys) : DelSlowAsync(keys);
    }

    private async ValueTask<RespValue> ExecuteSlowAsync(string command, RedisArg[] args)
        => await (await WaitForConnectionAsync()).ExecuteAsync(command, args);
    private async ValueTask<string?> GetSlowAsync(string key)
        => await (await WaitForConnectionAsync()).GetAsync(key);
    private async ValueTask SetExSlowAsync(string key, RedisArg value, int seconds)
        => await (await WaitForConnectionAsync()).SetExAsync(key, value, seconds);
    private async ValueTask<long> DelSlowAsync(string[] keys)
        => await (await WaitForConnectionAsync()).DelAsync(keys);
    private async ValueTask<RespValue[]> PipelineSlowAsync(RedisCommand[] commands)
        => await (await WaitForConnectionAsync()).PipelineAsync(commands);

    // Round-robin over healthy connections; evict and replace any found broken.
    private RedisConnection? Pick()
    {
        while (_connections.Count > 0)
        {
            int index = (_next++ & 0x7fffffff) % _connections.Count;
            RedisConnection c = _connections[index];
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
    // and wait for one to finish; fail fast after MaxConnectAttempts so commands never hang.
    private async ValueTask<RedisConnection> WaitForConnectionAsync()
    {
        for (int attempt = 1; ; attempt++)
        {
            RedisConnection? c = Pick();
            if (c != null)
            {
                return c;
            }

            if (attempt > MaxConnectAttempts)
            {
                throw new RedisException(
                    $"redis pool: no connection to {_options.Host}:{_options.Port} after {MaxConnectAttempts} attempts");
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
                if (_connections[i].CheckTimeout(now, timeoutMs, _options.Host, _options.Port))
                {
                    RedisConnection c = _connections[i];
                    _connections.RemoveAt(i);
                    c.Dispose();   // shuts the socket down - unsticks the connection's stuck send/recv loops
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
