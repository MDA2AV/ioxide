using System.Text;
using ioxide;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  raw - a complete ioxide server in one file. Everything below is the real thing: the config,
//  the reactors, the threads, the connection loop. Copy it into your own project and it runs.
//
//      dotnet run -c Release --project Playground/Tcp/Raw
//      curl http://127.0.0.1:8080/
//
//  No I/O beyond the socket, so this is the throughput baseline the other samples are read
//  against. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port      = 8080;
int    reactors  = 12;
int    bodyBytes = 2;

Env.Override(ref port, ref reactors, ref bodyBytes);

// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor. The
// handler code is identical either way; this only changes how recv buffers are handed out.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);
// ─────────────────────────────────────────────────────────────────────────────────────────────

// The engine. Every ServerConfig + TcpOptions knob is set here at its default, so the whole tuning
// surface is visible in one place - edit any line. One ring per reactor, one reactor per thread.
var config = new ServerConfig
{
    ReactorCount   = reactors,  // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                 // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = incrementalBuffers ? new IncrementalOptions { MaxConnections = 1024, RecvSlots = 8, RecvBufferSize = 16 * 1024 } : null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
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

// One pre-encoded response, built once and written for every request. PLAYGROUND_BODY sizes the
// body (2 = "ok"); 1024 matches the object size load-generator grids conventionally measure.
byte[] body = bodyBytes == 2 ? "ok"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes - 1), (byte)'\n'];
byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    // Each reactor owns its ring, its SO_REUSEPORT listener and its connections outright.
    // Nothing is shared between them, so nothing is locked.
    var reactor = new Reactor(i, config);

    // The handler. It runs on the reactor thread and every await resumes right back on it.
    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            while (true)
            {
                // io_uring recv. The continuation resumes inline on this thread - no thread pool.
                RecvSnapshot snapshot = await conn.ReadAsync();

                // ioxide hands you raw bytes and stays out of HTTP. This sample doesn't parse the
                // request at all - it just returns every received buffer to the ring.
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        conn.ReturnBuffer(in item);
                    }
                }

                // Stage into the connection's write slab, then one io_uring send.
                conn.Write(response);
                await conn.FlushAsync();

                if (snapshot.IsClosed) return;   // peer went away
                conn.ResetRead();                // arm the next read
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

Console.WriteLine($"[raw] {config.ReactorCount} reactors on :{config.Tcp.Port}, {bodyBytes}-byte body");

foreach (Thread thread in threads)
{
    thread.Join();
}
