using System.Text;
using ioxide;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  incremental - Tcp.Raw with ONE thing changed: the buffer-ring mode. The handler below is
//  byte-for-byte the raw handler; setting ServerConfig.Incremental is the whole difference.
//
//      dotnet run -c Release --project Playground/Tcp/Incremental
//      curl http://127.0.0.1:8080/
//
//  Shared mode gives every connection buffers from one big ring. Incremental mode
//  (IOU_PBUF_RING_INC, kernel 6.12+) gives each connection a SMALL ring of its own that the
//  kernel fills incrementally - many idle connections then cost a few small buffers each
//  instead of holding slots in the shared ring. The trade is per-connection setup cost, so
//  it pays at high connection counts, not high request rates. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port      = 8080;                        // http://127.0.0.1:8080/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 2;                           // "ok"

Env.Override(ref port, ref reactors, ref bodyBytes);

// The per-connection ring geometry - this block IS the mode. A connection gets its own ring of
// incRecvSlots buffers of incRecvBufferSize each, and the kernel appends across recvs into them,
// so a request split over several reads arrives contiguous. It costs memory per connection:
// incMaxConnections * incRecvSlots * incRecvBufferSize per reactor.
int incMaxConnections = 4096;   // per reactor
int incRecvSlots      = 16;     // per connection
int incRecvBufferSize = 4096;   // bytes per buffer

Env.OverrideIncrementalRing(ref incMaxConnections, ref incRecvSlots, ref incRecvBufferSize);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,  // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth

    // Selecting the mode is setting this block. The shared-ring knobs (RecvBufferSize,
    // RecvSlots) go unused once it is set.
    Incremental = new IncrementalOptions
    {
        MaxConnections = incMaxConnections,      // per reactor
        RecvSlots      = incRecvSlots     ,        // per connection
        RecvBufferSize = incRecvBufferSize,    // bytes per buffer, kernel appends across recvs
    },

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

byte[] body = bodyBytes == 2 ? "ok"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes - 1), (byte)'\n'];
byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // Identical to Tcp.Raw on purpose: the read surface doesn't change with the mode, so a
    // handler written against the shared ring runs unmodified here.
    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        conn.ReturnBuffer(in item);
                    }
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

Console.WriteLine($"[incremental] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{config.Incremental!.RecvSlots}x{config.Incremental.RecvBufferSize}B per connection "
                + $"(kernel 6.12+)");

foreach (Thread thread in threads)
{
    thread.Join();
}
