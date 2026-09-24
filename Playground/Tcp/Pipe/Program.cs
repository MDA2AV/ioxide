using System.IO.Pipelines;
using ioxide;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  pipe - the same workload as Playground/Tcp/Raw, but read and written through the System.IO.Pipelines
//  adapters instead of the raw connection API. If your code already speaks PipeReader/PipeWriter,
//  this is the shape to copy; run it against Raw to price what the adapter costs.
//
//  The reader owns the carry: unconsumed bytes are held across reads with no copy and no slab, and
//  buffers return to the ring automatically once fully consumed.
//
//      dotnet run -c Release --project Playground/Tcp/Pipe
//      curl http://127.0.0.1:8080/
//
//  Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port      = 8080;
int    reactors  = Environment.ProcessorCount;
int    bodyBytes = 2;

Env.Override(ref port, ref reactors, ref bodyBytes);

// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor. The
// handler code is identical either way; this only changes how recv buffers are handed out.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,  // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
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
        RecvQueueEntries = 64,                             // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

// PLAYGROUND_BODY sizes the body (2 = "ok"), matching Tcp.Raw so the two are comparable.
byte[] body = bodyBytes == 2 ? "ok"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes - 1), (byte)'\n'];
byte[] response =
[
    .. System.Text.Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        var reader = new TcpConnectionPipeReader(conn);
        var writer = new TcpConnectionPipeWriter(conn);

        try
        {
            while (true)
            {
                // io_uring recv behind the PipeReader surface - still resumes inline on the reactor.
                ReadResult result = await reader.ReadAsync();

                // This sample doesn't parse the request either: consume everything. A real handler
                // would walk result.Buffer for complete requests and AdvanceTo(consumed, examined)
                // so a partial one stays buffered for the next read.
                reader.AdvanceTo(result.Buffer.End);

                response.CopyTo(writer.GetSpan(response.Length));
                writer.Advance(response.Length);
                await writer.FlushAsync();

                if (result.IsCompleted) return;
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

Console.WriteLine($"[pipe] {config.ReactorCount} reactors on :{config.Tcp.Port}");

foreach (Thread thread in threads)
{
    thread.Join();
}
