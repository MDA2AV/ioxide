namespace ioxide.httpclient;

/// <summary>
/// N keep-alive HTTP/1.1 connections to one origin on a single reactor's ring. Requests take a
/// free connection, send, read the response, and hand it back; a connection that broke, that the
/// origin closed while it sat idle, or that sat idle past <see cref="HttpClientOptions.IdleTimeoutMs"/>
/// is dropped and replaced in the background. One pool per reactor per origin - create it from
/// <c>Reactor.OnStart</c> so the connections belong to that reactor's ring:
///
/// <code>
/// reactor.OnStart = r => HttpClientPool.Start(r, new HttpClientOptions { Host = "10.0.0.7", Port = 8080 });
/// ...
/// var upstream = reactor.GetService&lt;HttpClientPool&gt;();
/// using HttpClientResponse response = await upstream.GetAsync("/api/things"u8);
/// </code>
/// </summary>
/// <remarks>
/// Not thread-safe by design: every member runs on the owning reactor thread - requests come from
/// reactor-thread handlers and every completion resumes there too.
/// </remarks>
public sealed class HttpClientPool : IDisposable
{
    private readonly IRingHost _host;
    private readonly HttpClientOptions _options;

    private readonly List<HttpClientConnection> _idle = [];
    // Requests waiting for a connection, each with the deadline the sweep fails it at.
    private readonly Queue<(TaskCompletionSource<HttpClientConnection?> Waiter, long DeadlineMs)> _waiters = new();

    private int _live;        // connected + connecting
    private int _opening;
    private long _reopenAtMs; // jittered backoff gate after a failed connect
    private int _ticksToSweep; // reactor ticks until the next sweep (SweepIntervalMs)
    private int _requests;     // inside SendAsync: acquiring, waiting or sending
    private bool _disposed;

    // Warm: PoolSize connections opened up front and kept that way, the long-lived upstream shape.
    // Otherwise connections open as requests need them, which is how RingHttpClient's pools run.
    private readonly bool _warm;

    // Why the most recent connect failed, so an acquire timeout can say something more useful than
    // that it waited. Cleared on success.
    private string? _lastOpenFailure;

    private HttpClientPool(IRingHost host, HttpClientOptions options, bool warm)
    {
        _host = host;
        _options = options;
        _warm = warm;
    }

    /// <summary>Open <see cref="HttpClientOptions.PoolSize"/> connections and register the pool as
    /// a reactor service. Services are keyed by type, so a second pool started on the same reactor
    /// replaces the first in <c>GetService&lt;HttpClientPool&gt;()</c> - with several origins, keep
    /// the pools this returns.</summary>
    public static HttpClientPool Start(Reactor reactor, HttpClientOptions options)
    {
        var pool = new HttpClientPool(reactor, options, warm: true);
        for (int i = 0; i < options.PoolSize; i++)
        {
            pool.StartOpen();
        }
        reactor.AddService(pool);
        reactor.AddTicker(pool.Sweep);
        return pool;
    }

    // A pool that opens nothing until asked and is swept by its owner, not a ticker of its own.
    internal static HttpClientPool CreateOnDemand(IRingHost host, HttpClientOptions options)
        => new(host, options, warm: false);

    /// <summary>Connections currently open or opening (for diagnostics).</summary>
    public int ConnectionCount => _live;

    /// <summary>Connections sitting idle in the pool right now.</summary>
    public int IdleCount => _idle.Count;

    // Nothing open or opening, and no request inside: an on-demand pool its owner can drop. Not the
    // waiter queue - a failed open empties it, and the requests it woke have yet to queue again.
    internal bool IsUnused => _live == 0 && _requests == 0;

    // A waiter that timed out stays queued until a Release passes it; one at the head is dropped
    // here, so a pool with nobody waiting does not open connections for them.
    private bool AnyWaiter()
    {
        while (_waiters.Count > 0 && _waiters.Peek().Waiter.Task.IsCompleted)
        {
            _waiters.Dequeue();
        }
        return _waiters.Count > 0;
    }

    // --- request API ---------------------------------------------------------------------------

    public ValueTask<HttpClientResponse> GetAsync(ReadOnlyMemory<byte> path)
        => SendAsync(new HttpClientRequest(HttpMethods.Get, path));

    public ValueTask<HttpClientResponse> GetAsync(string path)
        => SendAsync(new HttpClientRequest(HttpMethods.Get, path));

    public ValueTask<HttpClientResponse> PostAsync(ReadOnlyMemory<byte> path, ReadOnlyMemory<byte> body)
        => SendAsync(new HttpClientRequest(HttpMethods.Post, path) { Body = body });

    /// <summary>
    /// Send one request on a pooled connection. The returned response owns its bytes - dispose it
    /// when done (see <see cref="HttpClientResponse"/>).
    /// </summary>
    public async ValueTask<HttpClientResponse> SendAsync(HttpClientRequest request)
    {
        HttpClientConnection.ValidateHead(request);   // before acquiring: a refused request must not cost a connection
        await new ReactorSwitch(_host);   // the pool is the reactor's
        _requests++;
        try
        {
            HttpClientConnection connection = await AcquireAsync();

            try
            {
                HttpClientResponse response = await connection.SendAsync(request);
                Release(connection);
                return response;
            }
            catch
            {
                Discard(connection);
                throw;
            }
        }
        finally
        {
            _requests--;
        }
    }

    // --- connection lifecycle ------------------------------------------------------------------

    private async ValueTask<HttpClientConnection> AcquireAsync()
    {
        // One deadline for the whole acquire, not one per attempt. A refused connect completes in
        // microseconds and wakes this waiter, so a per-attempt timer would be re-armed faster than
        // it could ever elapse - the caller would spin here forever instead of failing.
        long deadlineMs = Native.MonotonicMs + _options.AcquireTimeoutMs;

        while (true)
        {
            if (_disposed)
            {
                throw new HttpClientException(
                    $"pool for {_options.Host}:{_options.Port} is disposed");
            }

            // Newest first: a recently used connection is the one most likely still warm at the
            // peer, and it keeps the idle set from cycling through every socket.
            while (_idle.Count > 0)
            {
                HttpClientConnection candidate = _idle[^1];
                _idle.RemoveAt(_idle.Count - 1);
                if (!candidate.IsBroken)
                {
                    return candidate;
                }
                Discard(candidate);   // died while idle (peer closed it)
            }

            // Honour the same backoff gate Sweep() does. Without it, a dead origin turns this loop
            // into a connect() storm: open, refuse, wake, reopen - thousands of syscalls a second
            // on the reactor thread. Behind the gate the ticker paces the retries instead. One open
            // in flight per waiting request, so a burst that finds no connection opens in parallel.
            if (_live < _options.PoolSize && _opening <= _waiters.Count && Native.MonotonicMs >= _reopenAtMs)
            {
                StartOpen();
            }

            if (Native.MonotonicMs >= deadlineMs)
            {
                throw new HttpClientException(AcquireTimeoutMessage());
            }

            // No timer of its own: the sweep fails a waiter at its deadline. A Task.WhenAny with a
            // Task.Delay ran the hand-over through the thread pool and back for every request that
            // waited - most of them, in a pool that is the bottleneck. Completed from the reactor,
            // this continuation yields to the reactor's own queue.
            var waiter = new TaskCompletionSource<HttpClientConnection?>();
            _waiters.Enqueue((waiter, deadlineMs));

            HttpClientConnection? handed = await waiter.Task;
            await ReactorSwitch.Yield(_host);   // out of the completer's frame, still on the reactor
            if (handed is not null && !handed.IsBroken)
            {
                return handed;
            }
            if (handed is not null)
            {
                Discard(handed);   // handed a corpse: drop it so the slot is replenished
            }
            // Woken by a failed open, handed a corpse, or failed by the sweep at the deadline: loop,
            // which throws once past it.
        }
    }

    private void Release(HttpClientConnection connection)
    {
        // A disposed pool takes nothing back: this is how connections still checked out at Dispose
        // are closed - whenever their request finishes. Nor one past MaxLifetimeMs, whose replacement
        // resolves the origin again.
        if (connection.IsBroken || _disposed
            || (_options.MaxLifetimeMs > 0 && Native.MonotonicMs - connection.OpenedAtMs >= _options.MaxLifetimeMs))
        {
            Discard(connection);
            return;
        }

        // Hand straight to a waiter when one is queued - it skips a trip through the idle list.
        while (_waiters.Count > 0)
        {
            if (_waiters.Dequeue().Waiter.TrySetResult(connection))
            {
                return;   // one the sweep already failed takes nothing, and the next is tried
            }
        }

        connection.IdleSinceMs = Native.MonotonicMs;
        _idle.Add(connection);
    }

    private void Discard(HttpClientConnection connection)
    {
        connection.Dispose();
        _live--;
        WakeWaiters();   // they must re-check: a replacement is opening
    }

    private void StartOpen()
    {
        if (_disposed)
        {
            return;
        }

        _live++;
        _opening++;
        _ = OpenOneAsync();
    }

    private async Task OpenOneAsync()
    {
        try
        {
            HttpClientConnection connection = await HttpClientConnection.ConnectAsync(_host, _options);
            _reopenAtMs = 0;   // healthy - allow immediate replenishment
            _lastOpenFailure = null;
            Release(connection);
        }
        catch (Exception e)
        {
            _live--;
            _reopenAtMs = Native.MonotonicMs + BackoffMs();

            // Keep the reason, not just the log line. A caller that times out acquiring otherwise
            // sees only "no connection within N ms", which cannot tell a rejected certificate from
            // a refused connect - the two failures a TLS origin most needs distinguished.
            _lastOpenFailure = e.Message;

            Console.Error.WriteLine($"[httpclient] connect to {_options.Host}:{_options.Port} failed: {e.Message}");
            WakeWaiters();   // fail fast instead of parking requests forever
        }
        finally
        {
            _opening--;
        }
    }

    // Wake every waiter with null so each re-checks the pool state (a connection may now be idle,
    // or the open failed and it should retry or time out).
    private void WakeWaiters()
    {
        while (_waiters.Count > 0)
        {
            _waiters.Dequeue().Waiter.TrySetResult(null);
        }
    }

    // Ticker, every SweepIntervalMs: drop idle connections that are broken, closed by the origin, idle
    // past IdleTimeoutMs or older than MaxLifetimeMs, and replenish behind a jittered backoff - toward
    // PoolSize when warm, for waiting requests only when on demand.
    internal void Sweep()
    {
        if (_disposed)
        {
            return;   // AddTicker has no removal API, so a disposed pool must no-op: replenishing
                      // here would reopen the connections Dispose just closed, for the rest of the
                      // reactor's life.
        }

        // Every tick, whatever SweepIntervalMs says: an acquire deadline is this pool's only timer.
        long tickMs = Native.MonotonicMs;
        foreach ((TaskCompletionSource<HttpClientConnection?> waiter, long deadlineMs) in _waiters)
        {
            if (tickMs >= deadlineMs)
            {
                waiter.TrySetResult(null);
            }
        }

        if (--_ticksToSweep > 0)
        {
            return;
        }
        _ticksToSweep = (_options.SweepIntervalMs + Reactor.TickMs - 1) / Reactor.TickMs;

        long nowMs = Native.MonotonicMs;
        for (int i = _idle.Count - 1; i >= 0; i--)
        {
            HttpClientConnection connection = _idle[i];
            if (connection.IsBroken
                || (_options.IdleTimeoutMs > 0 && nowMs - connection.IdleSinceMs >= _options.IdleTimeoutMs)
                || (_options.MaxLifetimeMs > 0 && nowMs - connection.OpenedAtMs >= _options.MaxLifetimeMs)
                || connection.ClosedWhileIdle())
            {
                _idle.RemoveAt(i);
                Discard(connection);
            }
        }

        if (_live < _options.PoolSize && _opening == 0 && nowMs >= _reopenAtMs && (_warm || AnyWaiter()))
        {
            StartOpen();
        }
    }

    // The acquire deadline, plus why connecting kept failing when we know.
    private string AcquireTimeoutMessage()
    {
        string basic = $"no connection to {_options.Host}:{_options.Port} within {_options.AcquireTimeoutMs} ms";
        return _lastOpenFailure is { } reason ? $"{basic}: {reason}" : basic;
    }

    private static int BackoffMs() => 200 + Random.Shared.Next(200);

    /// <summary>
    /// Close the idle connections and stop replenishing. Connections currently checked out by an
    /// in-flight request are not touched - the request owns them, and they are dropped by
    /// <see cref="Release"/> when it finishes, because a disposed pool takes nothing back.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        foreach (HttpClientConnection connection in _idle)
        {
            connection.Dispose();
        }
        _live -= _idle.Count;
        _idle.Clear();

        // Queued callers would otherwise sit until their acquire deadline for connections that are
        // never coming. Null wakes them to re-check, where the disposed guard fails them at once.
        WakeWaiters();
    }
}
