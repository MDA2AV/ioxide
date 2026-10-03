using ioxide;
using ioxide.http2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-managed-streamed-both - HTTP/2 with BOTH directions streamed: the request body pulled a chunk at
//  a time, the response body pushed a chunk at a time, in the same handler.
//
//      dotnet run -c Release --project Playground/Http2/ManagedStreamedBoth
//      curl --http2-prior-knowledge -N http://127.0.0.1:8080/feed          # never ends
//      head -c 50000000 /dev/zero | curl --http2-prior-knowledge --data-binary @- \
//        http://127.0.0.1:8080/echo                                        # neither side held
//
//  /echo is the shape that needs both: read a chunk, write a chunk, and neither the upload nor
//  the download is ever held whole. That is what a proxy does, and it is why the two directions
//  are separate features rather than one "streaming" switch - they solve different problems.
//
//      REQUEST streamed  (Http2Request.BodyReader, StreamRequestBodies on)
//          bounds what an upload can make the server hold. A read returns the peer's credit, so a
//          slow handler makes the PEER slow down.
//
//      RESPONSE streamed (Http2ResponseWriter, RunAsync)
//          lets a body exist that has no length and no end - /feed has no final byte, so a
//          buffered API cannot express it at all. A flush waits when either window is exhausted
//          and resumes on the WINDOW_UPDATE.
//
//  The windows are what HTTP/2 adds over HTTP/3 here: every stream shares one TCP connection, so
//  both a per-stream and a connection window must allow a write, and a handler that stops reading
//  holds down the connection window for every other stream on it.
//  Needs: ioxide, ioxide.http2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port       = 8080;
int    reactors   = Environment.ProcessorCount;
int    chunkBytes = 1024;   // one DATA frame per flush on /feed

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

// Both halves are opt-in and independent: this one turns the REQUEST direction on, RunAsync below
// is what turns the RESPONSE direction on.
var http2 = new Http2Options { StreamRequestBodies = true };

byte[] chunk = [.. Enumerable.Repeat((byte)'x', chunkBytes)];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            await new Http2Connection(conn, http2).RunAsync(async (request, writer) =>
            {
                bool echo = request.Path.Span.SequenceEqual("/echo"u8);

                // No content-length: on /feed the length will never be known, and on /echo it is
                // not known yet. END_STREAM is what marks the end instead.
                var response = new Http2Response { Status = 200 };
                response.Headers.Add("content-type"u8.ToArray(), "text/plain"u8.ToArray());
                writer.WriteHeaders(response);

                if (echo)
                {
                    // Both directions at once. Nothing here holds more than one chunk: the read
                    // credits the peer for what it hands back, and the flush waits for room on the
                    // way out - so a fast uploader is paced by the slower of the two, not buffered.
                    while (true)
                    {
                        ReadOnlyMemory<byte> incoming = await request.BodyReader!.ReadAsync();
                        if (incoming.IsEmpty)
                        {
                            break;
                        }

                        incoming.Span.CopyTo(writer.GetSpan(incoming.Length));
                        writer.Advance(incoming.Length);
                        await writer.FlushAsync();
                    }
                    return;
                }

                // /feed: a response with no end at all. There is no final byte to wait for, which
                // is the case a buffered API has no way to express.
                while (true)
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

Console.WriteLine($"[http2-managed-streamed-both] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"request pulled and response pushed ({chunkBytes}-byte chunks on /feed)");

foreach (Thread thread in threads)
{
    thread.Join();
}
