using ioxide;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  hop - Playground/Tcp/Raw, except every request deliberately bounces off the reactor and back.
//  Task.Yield() sends the continuation to the thread pool; the reactor's SynchronizationContext
//  then posts it home, which wakes the reactor through its eventfd.
//
//  This is the sample to read if you need to call something that ISN'T ring-native - a blocking
//  library, a CPU-bound step - and want to see what leaving the reactor costs. Run it against Raw.
//
//      dotnet run -c Release --project Playground/Tcp/Hop
//      curl http://127.0.0.1:8080/
//
//  Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);
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

byte[] response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"u8.ToArray();

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                // Off to the thread pool and back. Everything after this line runs on the reactor
                // again, because the per-reactor SynchronizationContext posts it home - which is
                // what makes it safe to touch the connection below.
                await Task.Yield();

                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer) conn.ReturnBuffer(in item);
                }

                conn.Write(response);
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

Console.WriteLine($"[hop] {config.ReactorCount} reactors on :{config.Tcp.Port} (every request bounces off-reactor)");

foreach (Thread thread in threads)
{
    thread.Join();
}
