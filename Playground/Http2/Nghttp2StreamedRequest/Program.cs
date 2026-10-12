using System.Text;
using ioxide;
using ioxide.nghttp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  nghttp2-streamed-request - HTTP/2 on the reference implementation where the REQUEST body arrives
//  a chunk at a time instead of assembled. The handler runs as soon as the headers are in, while
//  the upload is still coming.
//
//      dotnet run -c Release --project Playground/Http2/Nghttp2StreamedRequest
//      head -c 50000000 /dev/zero | curl --http2-prior-knowledge --data-binary @- \
//        http://127.0.0.1:8080/upload
//
//  The knob is one line - StreamRequestBodies - and what it changes is what bounds memory.
//  BUFFERED holds the whole body before your handler starts, so MaxRequestBytes is the only thing
//  between a hostile peer and the arena. STREAMED holds one flow-control window, because a chunk
//  credits the peer's window only as this handler READS it: fall behind and the peer runs out of
//  credit and stops sending. That is backpressure with the peer actually participating, rather
//  than a buffer you hope is big enough.
//
//  Note the response is still returned whole here - one direction at a time, so the difference is
//  the only thing on screen. Playground/Http2/ManagedStreamedRequest is the same server in pure C#.
//  Needs: ioxide, ioxide.nghttp2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port     = 8080;
int    reactors = Environment.ProcessorCount;

Env.Override(ref port, ref reactors);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,   // io_uring rings/threads - one per core
    RingEntries    = 8192,                                                        // SQ/CQ depth per ring
    DualStack      = false,                                                       // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                                                   // bytes per shared recv buffer
    RecvSlots      = 4096,                                                        // shared recv buffer-ring depth
    Udp            = null,                                                        // no raw UDP sockets (TCP-only server)
    Quic           = null,                                                        // no QUIC transport - see Http3/*
    Tcp = new TcpOptions
    {
        Port             = port,
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

var http2 = new Nghttp2Options
{
    StreamRequestBodies = true,          // the whole point: dispatch at the headers, body follows
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            await new Nghttp2Connection(conn, http2).RunBufferedAsync(async request =>
            {
                // BodyReader is set because StreamRequestBodies is on; with it off the body would
                // be in request.Body instead and this would be null.
                long total = 0;
                if (request.BodyReader is { } body)
                {
                    while (true)
                    {
                        // Empty means end of body. Each read hands back the peer's credit for the
                        // chunk it returns, which is what lets the next one arrive - and the
                        // memory it points at is recycled by the NEXT read, so anything worth
                        // keeping has to be copied out here.
                        ReadOnlyMemory<byte> chunk = await body.ReadAsync();
                        if (chunk.IsEmpty)
                        {
                            break;
                        }
                        total += chunk.Length;
                    }
                }

                return new Nghttp2Response
                {
                    Status = 200,
                    Body = Encoding.ASCII.GetBytes($"{total} bytes\n"),
                };
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

Console.WriteLine($"[nghttp2-streamed-request] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + "request bodies streamed");

foreach (Thread thread in threads)
{
    thread.Join();
}
