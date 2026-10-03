using ioxide;
using ioxide.nghttp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  nghttp2-streamed-response - HTTP/2 on the reference implementation with the RESPONSE BODY
//  produced over time instead of returned whole.
//
//      dotnet run -c Release --project Playground/Http2/Nghttp2Response
//      curl --http2-prior-knowledge http://127.0.0.1:8080/
//      curl --http2-prior-knowledge -N http://127.0.0.1:8080/feed   # never ends
//
//  /feed is why the mode exists: an endless response has no final byte, so a buffered API cannot
//  express it at all.
//
//  What differs from the pure-C# twin is underneath, not in this file. nghttp2 owns the framing,
//  so it PULLS body bytes when it is ready to send them rather than accepting them when you have
//  them: the writer buffers a chunk natively and resumes the stream, and nghttp2's read callback
//  defers whenever nothing is queued. So a flush here means "handed over", not "on the wire" -
//  where Playground/Http2/ManagedStreamedResponse writes a DATA frame the moment a chunk is staged.
//  Needs: ioxide, ioxide.nghttp2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port       = 8080;
int    reactors   = Environment.ProcessorCount;
int    chunkCount = 8;      // DATA frames per response on /
int    chunkBytes = 1024;   // bytes per chunk

Env.Override(ref port, ref reactors);
Env.Override(ref chunkCount, "PLAYGROUND_CHUNKS");
Env.Override(ref chunkBytes, "PLAYGROUND_CHUNK_BYTES");
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

byte[] chunk = [.. Enumerable.Repeat((byte)'x', chunkBytes)];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            await new Nghttp2Connection(conn).RunAsync(async (request, writer) =>
            {
                bool endless = request.Path.Span.SequenceEqual("/feed"u8);

                // Headers first and once. No content-length: the length is not known yet, and for
                // /feed never will be - END_STREAM is what marks the end instead.
                var response = new Nghttp2Response { Status = 200 };
                response.Headers.Add("content-type"u8.ToArray(),
                    endless ? "text/event-stream"u8.ToArray() : "text/plain"u8.ToArray());
                writer.WriteHeaders(response);

                for (int n = 0; endless || n < chunkCount; n++)
                {
                    chunk.CopyTo(writer.GetSpan(chunk.Length));
                    writer.Advance(chunk.Length);
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

Console.WriteLine($"[nghttp2-streamed-response] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{chunkCount} x {chunkBytes}-byte chunks per response");

foreach (Thread thread in threads)
{
    thread.Join();
}
