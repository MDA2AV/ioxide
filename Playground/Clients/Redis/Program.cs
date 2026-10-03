using System.Text;
using ioxide;
using ioxide.redis;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  redis - a RedisPool per reactor, driven on the same ring that accepted the request. Every
//  await below resumes inline on the reactor thread; commands from concurrent requests share
//  the pool's connections and pipeline automatically.
//
//      docker run --rm -p 6379:6379 redis            # or point PLAYGROUND_REDIS_* elsewhere
//      dotnet run -c Release --project Playground/Redis
//
//      curl http://127.0.0.1:8080/                   # GET hot path (the wrk-able route)
//      curl http://127.0.0.1:8080/cache/user42       # cache-aside: GET, miss -> SET EX
//      curl http://127.0.0.1:8080/incr               # RESP integer reply
//      curl http://127.0.0.1:8080/hash               # RESP array (HGETALL)
//      curl http://127.0.0.1:8080/list               # RESP array (LRANGE)
//      curl http://127.0.0.1:8080/pipeline           # SET+INCR+GET in one round trip
//
//  Needs: ioxide.redis
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The Redis this talks to. IPv4 literal for the same reason as everywhere else - a DNS lookup
// would block the reactor - and the pool is per reactor. A null password means no AUTH.
string  redisHost     = "127.0.0.1";
ushort  redisPort     = 6379;
string? redisPassword = null;
int     redisPoolSize = 4;

Env.OverrideRedis(ref redisHost, ref redisPort, ref redisPassword, ref redisPoolSize);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,  // io_uring rings/threads - one per core
    RingEntries    = 8192,                                                        // SQ/CQ depth per ring
    DualStack      = false,                                                       // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                                                   // bytes per shared recv buffer
    RecvSlots      = 4096,                                                        // shared recv buffer-ring depth
    Incremental    = null,                                                        // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                                        // no raw UDP sockets (TCP-only server)
    Quic           = null,                                                        // no QUIC transport - see Http3/* and Quic/Alpn
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                                                    // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                                                  // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                                             // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                                                  // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,                            // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                                                 // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 4096,                                                  // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                                                // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                                                // close a connection whose flush takes this long to go out; 0 = off
    },
};

var redisOptions = new RedisOptions
{
    Host             = redisHost,  // IPv4 literal - resolve names up front, DNS blocks the reactor
    Port             = redisPort,        // Redis wire port
    Password         = redisPassword,     // AUTH password; null = no auth
    User             = null,                                           // ACL username (Redis 6+); null = default user
    Database         = 0,                                              // logical DB index to SELECT on connect
    PoolSize         = redisPoolSize,            // per reactor, not global
    CommandTimeoutMs = 30_000,                                         // oldest in-flight command past this -> torn down; 0 disables
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // The pool lives on the reactor: its connections ride this reactor's ring, so a query is
    // an io_uring send + recv with the continuation resuming right here.
    reactor.OnStart = r =>
    {
        RedisPool pool = RedisPool.Start(r, redisOptions);
        _ = SeedAsync(pool);   // the "/" route reads this key; seed it so the demo answers
    };

    reactor.TcpHandle = async (r, conn) =>
    {
        RedisPool pool = r.GetService<RedisPool>();

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
                        // Cache-aside: try the key; on a miss compute, SET with a TTL, return.
                        var p when p.StartsWith("/cache/", StringComparison.Ordinal)
                            => await CacheAside(pool, p["/cache/".Length..]),

                        // One RESP reply type per route, through the generic ExecuteAsync.
                        "/incr"     => $"counter = {(await pool.ExecuteAsync("INCR", "play:counter")).AsInteger()}",
                        "/hash"     => await Hash(pool),
                        "/list"     => await List(pool),

                        // Several commands, one round trip, replies in order.
                        "/pipeline" => await Pipeline(pool),

                        // The hot path: a single GET per request. wrk this one.
                        _           => $"redis = {await pool.GetAsync("play:bench") ?? "(nil)"}",
                    };

                    WriteText(conn, "200 OK", body);
                }
                catch (RedisException e)
                {
                    // A server error is an exception, not a broken socket: the connection has
                    // resynced and goes back to the pool usable.
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

Console.WriteLine($"[redis] {config.ReactorCount} reactors on :{config.Tcp!.Port} "
                + $"-> {redisOptions.Host}:{redisOptions.Port}, {redisOptions.PoolSize} connections each");

foreach (Thread thread in threads)
{
    thread.Join();
}

static async Task SeedAsync(RedisPool pool)
{
    try
    {
        await pool.ExecuteAsync("SET", "play:bench", "42");
    }
    catch (Exception e) { Console.Error.WriteLine($"[redis] seed failed: {e.Message}"); }
}

static async Task<string> CacheAside(RedisPool pool, string key)
{
    key = "play:cache:" + key;
    string? cached = await pool.GetAsync(key);
    if (cached != null)
    {
        return $"hit {key} = {cached}";
    }

    string value = $"value-{key.Length}";           // stands in for the expensive computation
    await pool.SetExAsync(key, value, seconds: 60);
    return $"miss {key} = {value} (cached 60s)";
}

// RESP array of bulk strings: field, value, field, value, ...
static async Task<string> Hash(RedisPool pool)
{
    await pool.ExecuteAsync("HSET", "play:hash", "lang", "csharp", "engine", "io_uring");
    RespValue all = await pool.ExecuteAsync("HGETALL", "play:hash");
    return "hash = [" + string.Join(", ", all.Items.Select(v => v.AsString())) + "]";
}

static async Task<string> List(RedisPool pool)
{
    await pool.ExecuteAsync("DEL", "play:list");
    await pool.ExecuteAsync("RPUSH", "play:list", "a", "b", "c");
    RespValue items = await pool.ExecuteAsync("LRANGE", "play:list", "0", "-1");
    return "list = [" + string.Join(", ", items.Items.Select(v => v.AsString())) + "]";
}

static async Task<string> Pipeline(RedisPool pool)
{
    RespValue[] replies = await pool.PipelineAsync(
        new RedisCommand("SET", "play:pipe", "1"),
        new RedisCommand("INCR", "play:pipe"),
        new RedisCommand("GET", "play:pipe"));
    return $"set={replies[0].AsString()} incr={replies[1].AsInteger()} get={replies[2].AsString()}";
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
            int firstSpace = request.IndexOf((byte)' ');
            if (firstSpace >= 0)
            {
                ReadOnlySpan<byte> rest = request[(firstSpace + 1)..];
                int secondSpace = rest.IndexOf((byte)' ');
                if (secondSpace > 0)
                {
                    ReadOnlySpan<byte> target = rest[..secondSpace];
                    int query = target.IndexOf((byte)'?');
                    path = Encoding.ASCII.GetString(query >= 0 ? target[..query] : target);
                }
            }
            conn.ReturnBuffer(in item);
        }
    }

    return path;
}

static void WriteText(TcpConnection conn, string status, string body)
    => conn.Write(Encoding.ASCII.GetBytes(
        $"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
