using System.Text;
using epoxide;
using epoxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  raw on epoll - Playground/Tcp/Raw on epoxide: the same server, the same connection loop, the
//  raw connection API instead of the pipe adapters. The throughput baseline the other epoxide
//  samples are read against, and the one to run against Tcp/Raw.
//
//      dotnet run -c Release --project Playground/Epoxide/Raw
//      curl http://127.0.0.1:8080/
//
//  Needs: epoxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. An Env.Override line means the value can also be set from the environment, which is
// how bench/any.sh drives the sample; the literal is what applies otherwise.

ushort port      = 8080;
int    reactors  = 12;
int    bodyBytes = 2;

Env.Override(ref port, ref reactors, ref bodyBytes);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // epoll sets/threads - one per core
    MaxEvents      = 1024,                                 // events one epoll_wait takes in
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per pooled recv buffer
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored sendmsg
        RecvQueueEntries = 64,                             // per-connection recv queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

// One pre-encoded response, built once and written for every request. PLAYGROUND_BODY sizes the
// body (2 = "ok"), matching Tcp/Raw so the two are comparable.
byte[] body = bodyBytes == 2 ? "ok"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes - 1), (byte)'\n'];
byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    // Each reactor owns its epoll set, its SO_REUSEPORT listener and its connections outright.
    var reactor = new Reactor(i, config);

    // The handler. It starts on the reactor thread, and a read or flush that waits resumes it there.
    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            while (true)
            {
                // A recv on this thread while the socket has data; parked on the reactor once it is empty.
                RecvSnapshot snapshot = await conn.ReadAsync();

                // No HTTP parsing here either: every received buffer goes straight back to the pool.
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        conn.ReturnBuffer(in item);
                    }
                }

                // Stage into the connection's write slab, then one send.
                conn.Write(response);
                await conn.FlushAsync();

                if (snapshot.IsClosed) return;   // peer went away
            }
        }
        finally
        {
            conn.DecRef();   // hand the connection object back to the reactor's pool
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[epoxide-raw] {config.ReactorCount} reactors on :{config.Tcp.Port}, {bodyBytes}-byte body");

foreach (Thread thread in threads)
{
    thread.Join();
}
