using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http - calling an origin over HTTP/1.1 from inside a handler. Both hops - the inbound
//  connection and the outbound call - run on this reactor's ring and resume inline, so a request
//  never leaves the thread it arrived on.
//
//  The pool is what makes that true: HttpClientPool.Start opens its connections on the reactor
//  that will use them, so GetAsync never hands work to another thread. PoolSize is per reactor,
//  and it is the ceiling on requests in flight to the origin, since HTTP/1.1 carries one exchange
//  at a time.
//
//      dotnet run -c Release --project Playground/Tcp/Raw                     # an origin to call
//      PLAYGROUND_UPSTREAM_PORT=8080 dotnet run -c Release --project Playground/Clients/Http
//      curl http://127.0.0.1:8090/
//
//  Needs: ioxide, ioxide.httpclient
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port     = 8090;                        // http://127.0.0.1:8090/ - what this proxy serves
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The origin this forwards to. The host must be an IPv4 literal - a DNS lookup would block the
// reactor - and PoolSize is per protocol, per reactor.
string upstreamHost = "127.0.0.1";
ushort upstreamPort = 8081;
int    upstreamPool = 8;

// The path every inbound request is forwarded to, whatever was asked for.
string upstreamPath = "/";

Env.Override(ref upstreamHost, "PLAYGROUND_UPSTREAM_HOST");
Env.Override(ref upstreamPort, "PLAYGROUND_UPSTREAM_PORT");
Env.Override(ref upstreamPool, "PLAYGROUND_UPSTREAM_POOL");
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount = reactors,
    RingEntries  = 8192,                         // io_uring SQ/CQ depth
    DualStack    = false,                        // true = one AF_INET6 socket takes v6 + v4-mapped

    // Shared recv ring - the default mode, used while Incremental is null.
    RecvBufferSize = 32 * 1024,
    RecvSlots      = 4096,

    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                   // more listeners; conn.ListenerPort says which
        ListenBacklog    = 1024,                 // accept queue per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,            // per-connection write buffer
        PoolMax          = 1024,                 // connection objects recycled per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,   // Segmented = chained slabs, one SENDMSG
        ZeroCopySend     = false,                // SEND_ZC; only pays off on large responses
        RecvQueueEntries = 64,                   // per-connection SPSC queue, power of two
        ReadTimeoutMs    = 60_000,               // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,               // close a connection whose flush takes this long to go out; 0 = off
    },
};

var upstream = new HttpClientOptions
{
    Host     = upstreamHost,
    Port     = upstreamPort,
    PoolSize = upstreamPool,
};

var threads = new Thread[config.ReactorCount];

for (int id = 0; id < threads.Length; id++)
{
    var reactor = new Reactor(id, config);

    // The pool opens its connections on THIS reactor's ring, which is what keeps both hops on
    // one thread.
    reactor.OnStart = r => HttpClientPool.Start(r, upstream);

    reactor.TcpHandle = async (r, conn) =>
    {
        HttpClientPool http = r.GetService<HttpClientPool>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                // This sample forwards a fixed path, so the request bytes are drained rather than
                // parsed - the Proxy/* samples show real target extraction.
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer) conn.ReturnBuffer(in item);
                }

                try
                {
                    // The response owns its bytes - dispose it when done.
                    using HttpClientResponse response = await http.GetAsync(upstreamPath);

                    conn.Write(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 {response.Status} OK\r\nContent-Length: {response.Body.Length}\r\n\r\n"));
                    conn.Write(response.Body.Span);   // bytes straight through, no decode
                }
                catch (Exception e)
                {
                    // A dead origin surfaces here rather than hanging: the pool bounds the acquire.
                    byte[] message = Encoding.ASCII.GetBytes($"upstream: {e.Message}");
                    conn.Write(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {message.Length}\r\n\r\n"));
                    conn.Write(message);
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

    threads[id] = new Thread(reactor.Run) { Name = $"reactor-{id}" };
    threads[id].Start();
}

Console.WriteLine($"[http] {config.ReactorCount} reactors on :{config.Tcp!.Port} -> "
                + $"{upstream.Host}:{upstream.Port} ({upstream.PoolSize} conns per reactor)");

foreach (Thread thread in threads)
{
    thread.Join();
}
