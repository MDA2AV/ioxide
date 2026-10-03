using System.Text;
using ioxide;
using ioxide.http2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-managed-buffered - an HTTP/2 server in pure C#: framing, HPACK and flow control; ioxide owns the
//  ring, the loop and the connection, so a response is written straight into the write slab.
//
//      dotnet run -c Release --project Playground/Http2/ManagedBuffered
//      curl --http2-prior-knowledge http://127.0.0.1:8080/hello
//
//  This is h2c with PRIOR KNOWLEDGE: the peer opens with the HTTP/2 connection preface and no
//  upgrade dance. For h2 over TLS, terminate with ioxide's TlsService (ALPN "h2") and feed the
//  decrypted bytes in the same way. Needs: ioxide, ioxide.http2
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
    RingEntries    = 8192,                                                        // SQ/CQ depth per ring
    DualStack      = false,                                                       // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                                                   // bytes per shared recv buffer
    RecvSlots      = 4096,                                                        // shared recv buffer-ring depth
    Incremental    = incrementalBuffers ? new IncrementalOptions { MaxConnections = 1024, RecvSlots = 8, RecvBufferSize = 16 * 1024 } : null,                                                        // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                                        // no raw UDP sockets (TCP-only server)
    Quic           = null,                                                        // no QUIC transport - see Http3/* and Quic/Alpn
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

byte[] body = bodyBytes == 2
    ? "ok"u8.ToArray()
    : [.. Enumerable.Repeat((byte)'x', bodyBytes)];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            // The connection owns the read loop from here: it parses frames, dispatches each
            // request once its stream ends, and flushes the batch in one write.
            await new Http2Connection(conn).RunBufferedAsync(_ => new Http2Response
            {
                Status = 200,
                Body = body,
            });
        }
        finally
        {
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[http2-managed-buffered] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{body.Length}-byte body (h2c prior knowledge)");

foreach (Thread thread in threads)
{
    thread.Join();
}
