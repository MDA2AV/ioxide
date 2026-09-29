using System.Text;
using ioxide;
using ioxide.pg;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  pg - a Postgres-backed ioxide server, whole. A pool per reactor; connect, query and row
//  streaming are all ring operations, so a request never leaves the thread it arrived on.
//
//      docker run --rm -d -p 5432:5432 -e POSTGRES_USER=bench -e POSTGRES_DB=bench \
//        -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18
//      dotnet run -c Release --project Playground/Pg
//      curl http://127.0.0.1:8080/          # -> db=42
//
//      /        SELECT 42
//      /sleep   a 100ms query, to watch pool concurrency
//      /hang    a 10s query, to watch the command timeout
//      /err     a server error -> 500, and the connection stays usable
//
//  Needs: ioxide, ioxide.pg
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The Postgres this queries. The host must be an IPv4 literal - resolving a name would block the
// reactor - and the pool is per reactor, not global. A null password means trust auth; set one and
// the driver does SCRAM-SHA-256. CommandTimeoutMs tears down the connection when the oldest
// in-flight command passes it; 0 disables that.
string  pgHost      = "127.0.0.1";
ushort  pgPort      = 5432;
string  pgUser      = "bench";
string? pgPassword  = null;
string  pgDatabase  = "bench";
int     pgPoolSize  = 4;
int     pgTimeoutMs = 30_000;

Env.OverridePg(ref pgHost, ref pgPort, ref pgUser, ref pgPassword, ref pgDatabase,
               ref pgPoolSize, ref pgTimeoutMs);
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
        RecvQueueEntries = 64,                                                    // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                                                // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                                                // close a connection whose flush takes this long to go out; 0 = off
    },
};

var pgOptions = new PgOptions
{
    Host             = pgHost,  // IPv4 literal - resolve names up front, DNS blocks the reactor
    Port             = pgPort,        // Postgres wire port
    User             = pgUser,      // required
    Password         = pgPassword,     // null = trust auth; else SCRAM-SHA-256
    Database         = pgDatabase,        // required
    PoolSize         = pgPoolSize,            // per reactor, not global
    MaxReceiveBytes  = 64 * 1024 * 1024,                            // ceiling on one backend message; buffer grows to this (64 MB)
    CommandTimeoutMs = pgTimeoutMs,    // oldest in-flight command past this -> torn down; 0 disables
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // OnStart runs ON the reactor thread, so every connection the pool opens belongs to THIS
    // reactor's ring. Start registers the pool as a reactor service; the handler fetches it back
    // with GetService. One pool per reactor, no sharing, no lock.
    reactor.OnStart = r => PgPool.Start(r, pgOptions);

    reactor.TcpHandle = async (r, conn) =>
    {
        PgPool pg = r.GetService<PgPool>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                // Drain the recv, pulling the request target out on the way past. The buffers must
                // go back to the ring, so read what you need before returning them.
                string path = "/";
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        if (TryReadTarget(item.AsSpan(), out ReadOnlySpan<byte> target))
                        {
                            path = Encoding.ASCII.GetString(target);
                        }
                        conn.ReturnBuffer(in item);
                    }
                }

                try
                {
                    string responseBody;

                    if (path.StartsWith("/add/", StringComparison.Ordinal))
                    {
                        // Parameterized (prepared): each distinct SQL text is Parse'd once per
                        // connection, then Bind/Execute'd on reuse - the server plans it once.
                        long n = long.TryParse(path["/add/".Length..], out long parsed) ? parsed : 41;
                        PgResult result = await pg.QueryAsync("SELECT $1::bigint + 1", [PgParam.Int(n)]);
                        responseBody = $"{n}+1={result.Value}";
                    }
                    else if (path.StartsWith("/upper/", StringComparison.Ordinal))
                    {
                        // A text parameter rides the same prepared path - no SQL escaping, ever.
                        PgResult result = await pg.QueryAsync("SELECT upper($1)", [PgParam.Text(path["/upper/".Length..])]);
                        responseBody = $"upper={result.Value}";
                    }
                    else if (path.StartsWith("/rows/", StringComparison.Ordinal))
                    {
                        // Multiple rows stream through the inline callback as they arrive - fields
                        // read by column name, no materialized result set.
                        long count = Math.Clamp(long.TryParse(path["/rows/".Length..], out long c) ? c : 5, 1, 100);
                        var values = new StringBuilder();
                        int rows = await pg.QueryRowsAsync(
                            $"SELECT n, n * n AS square FROM generate_series(1, {count}) AS n",
                            row => values.Append(Encoding.ASCII.GetString(row.Field("n")))
                                         .Append("^2=")
                                         .Append(Encoding.ASCII.GetString(row.Field("square")))
                                         .Append(' '));
                        responseBody = $"rows={rows}: {values}";
                    }
                    else
                    {
                        string sql = path switch
                        {
                            "/sleep" => "SELECT 42 FROM pg_sleep(0.1)",
                            "/hang"  => "SELECT pg_sleep(10)",   // outlives PLAYGROUND_PG_TIMEOUT -> torn down
                            "/err"   => "SELECT * FROM this_table_does_not_exist",
                            _        => "SELECT 42",
                        };

                        // io_uring send + recv to Postgres, on the same ring that accepted the
                        // request. The continuation resumes inline, on this thread.
                        PgResult result = await pg.QueryAsync(sql);
                        responseBody = $"db={result.Value}";
                    }

                    conn.Write(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {responseBody.Length}\r\n\r\n{responseBody}"));
                }
                catch (PgException e)
                {
                    // A server error is just an exception. The connection goes back to the pool
                    // usable - Postgres told us about a bad query, it didn't break the socket.
                    Console.Error.WriteLine($"[pg] query failed: {e.Message}");
                    conn.Write("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"u8);
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

Console.WriteLine($"[pg] {config.ReactorCount} reactors on :{config.Tcp.Port} "
                + $"-> {pgOptions.Host}:{pgOptions.Port}, {pgOptions.PoolSize} connections each");

foreach (Thread thread in threads)
{
    thread.Join();
}

// "GET /sleep?x=1 HTTP/1.1" -> "/sleep". Your framework of choice would do this for you; ioxide
// deliberately doesn't, so here it is in full.
static bool TryReadTarget(ReadOnlySpan<byte> request, out ReadOnlySpan<byte> target)
{
    target = default;

    int firstSpace = request.IndexOf((byte)' ');
    if (firstSpace < 0) return false;

    ReadOnlySpan<byte> afterMethod = request[(firstSpace + 1)..];
    int secondSpace = afterMethod.IndexOf((byte)' ');
    if (secondSpace < 0) return false;

    target = afterMethod[..secondSpace];

    int query = target.IndexOf((byte)'?');
    if (query >= 0) target = target[..query];

    return true;
}
