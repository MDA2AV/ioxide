using System.Text;
using ioxide;
using ioxide.redis.stackexchange;
using ioxide.utils;
using Playground.Shared;
using StackExchange.Redis;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  redis via StackExchange.Redis - the whole StackExchange.Redis API, with its connections on
//  the reactor's ring. IoxideTunnel hands the multiplexer a transport whose connect, sends and
//  receives are io_uring operations on this reactor; StackExchange.Redis parses the replies and
//  completes the commands on this reactor's thread, so a handler's await never leaves it.
//
//      docker run --rm -p 6379:6379 redis            # or point PLAYGROUND_REDIS_* elsewhere
//      dotnet run -c Release --project Playground/Clients/RedisStackExchange
//
//      curl http://127.0.0.1:8080/                   # GET hot path (the wrk-able route)
//      curl http://127.0.0.1:8080/incr               # INCR
//      curl http://127.0.0.1:8080/cache/user42       # cache-aside: GET, miss -> SET with expiry
//
//  One multiplexer per reactor, made in OnStart and awaited by that reactor's handlers. Async
//  APIs only: a synchronous call (StringGet rather than StringGetAsync) on a reactor waits for a
//  completion only that reactor can run. No TLS through the tunnel yet.
//
//  Experimental: built on StackExchange.Redis's transport seam (SER009), which may change in any
//  StackExchange.Redis release.
//
//  Needs: ioxide.redis.stackexchange
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment; the literal is what
// applies otherwise. Delete those lines when you copy this out and the literals above them are
// the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The Redis this talks to; a null password means no AUTH. No pool size: a multiplexer
// pipelines every command over one connection.
string  redisHost     = "127.0.0.1";
ushort  redisPort     = 6379;
string? redisPassword = null;

// "ioxide" puts the connections on the ring; "sockets" leaves StackExchange.Redis on its own
// sockets and threads, everything else the same - the difference this sample exists to show.
string transport = "ioxide";

Env.Override(ref redisHost, "PLAYGROUND_REDIS_HOST");
Env.Override(ref redisPort, "PLAYGROUND_REDIS_PORT");
Env.OverrideOptional(ref redisPassword, "PLAYGROUND_REDIS_PASSWORD");
Env.Override(ref transport, "PLAYGROUND_REDIS_TRANSPORT");
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/* and Quic/Alpn
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                          // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 4096,                           // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);
    bool seed = i == 0;

    // A multiplexer per reactor, its connections on THIS reactor's ring. Keep the task: the
    // connect completes on the loop that starts after OnStart returns, so never wait on it here.
    reactor.OnStart = r =>
    {
        var options = new ConfigurationOptions
        {
            EndPoints      = { { redisHost, redisPort } },
            Password       = redisPassword,
            ConnectTimeout = 5000,
        };
        Task<ConnectionMultiplexer> redis = transport == "ioxide"
            ? IoxideRedis.ConnectAsync(r, options)
            : ConnectionMultiplexer.ConnectAsync(options);
        r.AddService(redis);
        if (seed)
        {
            _ = SeedAsync(redis);   // the "/" route reads this key
        }
    };

    reactor.TcpHandle = async (r, conn) =>
    {
        IDatabase db = (await r.GetService<Task<ConnectionMultiplexer>>()).GetDatabase();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = ReadPath(conn, snapshot);

                try
                {
                    string body = path switch
                    {
                        var p when p.StartsWith("/cache/", StringComparison.Ordinal)
                                => await CacheAside(db, p["/cache/".Length..]),
                        "/incr" => $"counter = {await db.StringIncrementAsync("play:counter")}",
                        // The hot path: a single GET per request. wrk this one.
                        _       => $"redis = {await db.StringGetAsync("play:bench")}",
                    };
                    WriteText(conn, "200 OK", body);
                }
                catch (RedisException e)
                {
                    WriteText(conn, "500 Internal Server Error", e.Message);
                }

                await conn.FlushAsync();

                if (snapshot.IsClosed) return;
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[redis via SE.Redis] {config.ReactorCount} reactors on :{config.Tcp!.Port} "
                + $"-> {redisHost}:{redisPort}, transport: {transport}, one multiplexer per reactor");

foreach (Thread thread in threads)
{
    thread.Join();
}

static async Task SeedAsync(Task<ConnectionMultiplexer> redis)
{
    try
    {
        await (await redis).GetDatabase().StringSetAsync("play:bench", "42");
    }
    catch (Exception e)
    {
        Console.Error.WriteLine($"[redis via SE.Redis] seed failed: {e.Message}");
    }
}

static async Task<string> CacheAside(IDatabase db, string key)
{
    key = "play:cache:" + key;
    RedisValue cached = await db.StringGetAsync(key);
    if (cached.HasValue)
    {
        return $"hit {key} = {cached}";
    }

    string value = $"value-{key.Length}";   // stands in for the expensive computation
    await db.StringSetAsync(key, value, TimeSpan.FromSeconds(60));
    return $"miss {key} = {value} (cached 60s)";
}

// "GET /cache/x HTTP/1.1" -> "/cache/x", draining the recv on the way past.
static string ReadPath(TcpConnection conn, RecvSnapshot snapshot)
{
    string path = "/";
    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
    {
        if (item.HasBuffer)
        {
            ReadOnlySpan<byte> request = item.AsSpan();
            int lineEnd = request.IndexOfAny((byte)'\r', (byte)'\n');
            ReadOnlySpan<byte> line = lineEnd < 0 ? request : request[..lineEnd];
            int first = line.IndexOf((byte)' ');
            int last = line.LastIndexOf((byte)' ');
            if (first >= 0 && last > first + 1)
            {
                path = Encoding.ASCII.GetString(line[(first + 1)..last]);
            }
            conn.ReturnBuffer(in item);
        }
    }
    return path;
}

static void WriteText(TcpConnection conn, string status, string body)
{
    conn.Write(Encoding.ASCII.GetBytes(
        $"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n{body}"));
}
