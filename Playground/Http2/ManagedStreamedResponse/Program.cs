using System.Text;
using ioxide;
using ioxide.http2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-managed-streamed-response - HTTP/2 with the RESPONSE BODY STREAMED: the handler pushes
//  bytes as it produces them and each flush becomes a DATA frame, instead of returning a finished
//  Http2Response.
//
//  That is what "/feed" shows - an endless response has no final byte, so a buffered API cannot
//  express it at all. It is also what lets a large file be served without ever holding it whole.
//
//  The flow-control story is the part HTTP/3 does not have. Every stream here shares one TCP
//  connection, so a write needs credit in BOTH the stream's window and the connection's, and
//  FlushAsync waits for a WINDOW_UPDATE rather than failing. That wait is the backpressure: a
//  peer that stops reading stops the producer instead of growing a queue behind it.
//
//      dotnet run -c Release --project Playground/Http2/ManagedStreamedResponse
//      curl --http2-prior-knowledge http://127.0.0.1:8080/         # chunked
//      curl --http2-prior-knowledge -N http://127.0.0.1:8080/feed  # never ends
//
//  Needs: ioxide, ioxide.http2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort port      = 8080;
int    reactors  = Environment.ProcessorCount;
int    bodyBytes = 2;   // unused here: the body is produced chunk by chunk

Env.Override(ref port, ref reactors, ref bodyBytes);

// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor. The
// handler code is identical either way; this only changes how recv buffers are handed out.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);

// Chunks written per response on "/", and the size of each. Their product is never held at once.
int chunkCount = 64;
int chunkBytes = 16 * 1024;

Env.Override(ref chunkCount, "PLAYGROUND_CHUNKS");
Env.Override(ref chunkBytes, "PLAYGROUND_CHUNK_BYTES");
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

byte[] chunk = Encoding.ASCII.GetBytes(new string('x', chunkBytes - 1) + "\n");

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            await new Http2Connection(conn).RunAsync(async (request, writer) =>
            {
                bool endless = request.Path.Span.SequenceEqual("/feed"u8);

                // Headers first and once. No content-length: the length is not known yet, and for
                // /feed never will be - END_STREAM is what marks the end instead.
                var response = new Http2Response { Status = 200 };
                response.Headers.Add("content-type"u8.ToArray(),
                    endless ? "text/event-stream"u8.ToArray() : "text/plain"u8.ToArray());
                writer.WriteHeaders(response);

                for (int n = 0; endless || n < chunkCount; n++)
                {
                    chunk.CopyTo(writer.GetSpan(chunk.Length));
                    writer.Advance(chunk.Length);

                    // Waits when either window is exhausted, and resumes on the WINDOW_UPDATE.
                    await writer.FlushAsync();
                }
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

Console.WriteLine($"[http2-managed-streamed-response] {config.ReactorCount} reactors on :{config.Tcp!.Port} "
                + $"(pure C#), {chunkCount} x {chunkBytes}-byte chunks per response");

foreach (Thread thread in threads)
{
    thread.Join();
}
