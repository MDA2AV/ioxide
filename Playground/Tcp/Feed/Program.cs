using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.timer;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  feed - a server-sent event stream: every client that connects gets a tick each second. The
//  writers sit on a list that outlives their handlers, so before each write the feed asks the
//  writer IsValid(). Connections are pooled, so a writer kept from before acts on whichever
//  client the connection serves next.
//
//      dotnet run -c Release --project Playground/Tcp/Feed
//      curl -N http://127.0.0.1:8080/
//
//  Needs: ioxide, ioxide.timer
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port       = 8080;
int    reactors   = Environment.ProcessorCount;
int    intervalMs = 1000;

Env.Override(ref port, ref reactors);
Env.Override(ref intervalMs, "PLAYGROUND_INTERVAL_MS");
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,  // io_uring rings/threads - one per core
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
        RecvQueueEntries = 64,                             // per-connection recv completion queue depth
        ReadTimeoutMs    = 0,                              // off: a subscriber sends nothing after its request
        SendTimeoutMs    = 5_000,                          // close a client whose flush takes this long; the feed flushes one client at a time
    },
};

byte[] head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n"u8.ToArray();

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // This reactor's subscribers. Only its own thread touches the list, so it needs no lock.
    var subscribers = new List<TcpConnectionPipeWriter>();

    reactor.OnStart = r => _ = Feed(r, subscribers, intervalMs);

    reactor.TcpHandle = async (r, conn) =>
    {
        var reader = new TcpConnectionPipeReader(conn);
        var writer = new TcpConnectionPipeWriter(conn);

        try
        {
            // Any request subscribes: the handler writes the head, and the feed writes everything after.
            ReadResult result = await reader.ReadAsync();
            reader.AdvanceTo(result.Buffer.End);
            if (result.IsCompleted) return;

            writer.Write(head);
            await writer.FlushAsync();
            subscribers.Add(writer);

            // Until the client hangs up. The writer stays on the list; the feed drops it.
            while (!result.IsCompleted)
            {
                result = await reader.ReadAsync();
                reader.AdvanceTo(result.Buffer.End);
            }
        }
        finally
        {
            reader.Complete();
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[feed] {config.ReactorCount} reactors on :{config.Tcp.Port}, a tick every {intervalMs} ms");

foreach (Thread thread in threads)
{
    thread.Join();
}

// One per reactor, on its thread.
static async Task Feed(Reactor r, List<TcpConnectionPipeWriter> subscribers, int intervalMs)
{
    var timer = new RingTimer(r);

    for (long tick = 1; ; tick++)
    {
        await timer.DelayAsync(intervalMs);
        byte[] line = Encoding.ASCII.GetBytes($"data: tick {tick}\n\n");

        for (int i = subscribers.Count - 1; i >= 0; i--)
        {
            TcpConnectionPipeWriter writer = subscribers[i];

            // Right before each write, not once per tick: a connection can end while this loop waits on another client's flush.
            if (!writer.IsValid())
            {
                subscribers.RemoveAt(i);
                continue;
            }

            writer.Write(line);
            await writer.FlushAsync();
        }
    }
}
