using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  gateway - one front door, several origins behind it, picked by path. Clients/Http with more
//  than one origin: each gets its own HttpClientPool on every reactor, with its own options, and
//  a request stays on the thread it arrived on whichever origin it goes to.
//
//  HttpClientPool.Start registers the pool as a reactor service, and services are keyed by type,
//  so with several pools GetService<HttpClientPool>() finds only the last one started. Keep the
//  pools Start returns instead - here in Gateway, a service of this sample's own.
//
//      PLAYGROUND_PORT=8081 dotnet run -c Release --project Playground/Tcp/Raw   # origin "users"
//      PLAYGROUND_PORT=8082 dotnet run -c Release --project Playground/Tcp/Raw   # origin "orders"
//      dotnet run -c Release --project Playground/Clients/Gateway
//      curl -i http://127.0.0.1:8090/users/42      # x-origin: users
//      curl -i http://127.0.0.1:8090/orders/7      # x-origin: orders
//
//  Needs: ioxide, ioxide.httpclient
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment; the literal is what
// applies otherwise. Delete those lines when you copy this out and the literals above them are
// the entire configuration.

ushort port     = 8090;                        // http://127.0.0.1:8090/ - what this gateway serves
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The origins, matched by path prefix in this order. Each has its own options, and PoolSize is
// per origin, per reactor - the ceiling on requests in flight to it from one reactor. Host can be
// a name: it is resolved off the reactor each time a connection opens.
Origin[] origins =
[
    new("users",  "/users/",  new HttpClientOptions { Host = "127.0.0.1", Port = 8081, PoolSize = 8 }),
    new("orders", "/orders/", new HttpClientOptions { Host = "127.0.0.1", Port = 8082, PoolSize = 4,
                                                      IdleTimeoutMs = 0 }),   // idle connections stay until the origin closes them
];
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

var threads = new Thread[config.ReactorCount];

for (int id = 0; id < threads.Length; id++)
{
    var reactor = new Reactor(id, config);

    // OnStart runs on the reactor thread, so each pool opens its connections on THIS ring. Start
    // also registers each one as the reactor's HttpClientPool service, every call replacing the
    // last - so the handler finds the pools through Gateway instead.
    reactor.OnStart = r => r.AddService(new Gateway(
        [.. origins.Select(origin => new Route(origin, HttpClientPool.Start(r, origin.Options)))]));

    reactor.TcpHandle = async (r, conn) =>
    {
        Gateway gateway = r.GetService<Gateway>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                // Drain the recv, pulling the request target out on the way past. The buffers must
                // go back to the ring, so read what you need before returning them.
                string? target = null;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        target ??= RequestTarget(item.AsSpan());
                        conn.ReturnBuffer(in item);
                    }
                }

                if (target is null)
                {
                    conn.Write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"u8);
                }
                else if (gateway.Match(target) is not Route route)
                {
                    conn.Write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"u8);
                }
                else
                {
                    try
                    {
                        // The same call as with one origin - only the pool it goes to changes.
                        using HttpClientResponse response = await route.Pool.GetAsync(target);

                        conn.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 {response.Status} OK\r\nx-origin: {route.Origin.Name}\r\n"
                          + $"Content-Length: {response.Body.Length}\r\n\r\n"));
                        conn.Write(response.Body.Span);   // bytes straight through, no decode
                    }
                    catch (Exception e)
                    {
                        // An origin that is down fails only its own routes; the other pools carry on.
                        byte[] message = Encoding.ASCII.GetBytes($"{route.Origin.Name}: {e.Message}");
                        conn.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {message.Length}\r\n\r\n"));
                        conn.Write(message);
                    }
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

Console.WriteLine($"[gateway] {config.ReactorCount} reactors on :{config.Tcp!.Port} -> "
                + string.Join(", ", origins.Select(o => $"{o.Prefix} {o.Options.Host}:{o.Options.Port}"))
                + ", a pool each per reactor");

foreach (Thread thread in threads)
{
    thread.Join();
}

// "GET /users/42?x=1 HTTP/1.1" -> "/users/42?x=1", forwarded whole; null when the line is not a
// request. It is cut at the line's first CR or LF, so nothing a client sends can add lines to the
// request an origin sees. Your framework of choice would do this for you; ioxide deliberately
// doesn't, so here it is in full.
static string? RequestTarget(ReadOnlySpan<byte> request)
{
    int end = request.IndexOfAny((byte)'\r', (byte)'\n');
    ReadOnlySpan<byte> line = end < 0 ? request : request[..end];
    int first = line.IndexOf((byte)' ');
    int last = line.LastIndexOf((byte)' ');
    if (first < 0 || last <= first + 1 || line[first + 1] != (byte)'/' || line.Contains((byte)0)) return null;
    return Encoding.ASCII.GetString(line[(first + 1)..last]);
}

// An origin and the paths sent to it.
record Origin(string Name, string Prefix, HttpClientOptions Options);

// An origin and this reactor's pool for it.
record Route(Origin Origin, HttpClientPool Pool);

// One reactor's routes: the first prefix that matches wins.
sealed class Gateway(Route[] routes)
{
    public Route? Match(string target)
    {
        foreach (Route route in routes)
        {
            if (target.StartsWith(route.Origin.Prefix, StringComparison.Ordinal)) return route;
        }
        return null;
    }
}
