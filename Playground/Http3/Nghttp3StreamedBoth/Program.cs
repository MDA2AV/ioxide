using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  nghttp3-streamed-both - HTTP/3 on nghttp3 with BOTH directions streamed, the fourth corner
//  the other three nghttp3 samples leave empty.
//
//  The request body arrives through Nghttp3Request.BodyReader, pulled a chunk at a time under
//  flow control; the response goes out through an Nghttp3ResponseWriter, one flush at a time.
//  One call does both: RunStreamedResponseAsync dispatches at end-of-headers, so the handler is
//  running while the upload is still on the wire.
//
//  "/echo" runs the two at once - read a chunk, write a chunk - which is what a proxy does.
//  Memory stays flat however large the exchange is, because each side blocks the other.
//
//  Diff it against Playground/Http3/ManagedStreamedBoth: same routes, same shape, and underneath
//  the opposite mechanism. nghttp3 owns the framing, so it PULLS body bytes when it is ready to
//  emit DATA - a flush here means nghttp3 has taken the chunk, not that it is on the wire.
//
//  No "/feed" here, unlike the managed twin: an endless response does not work on this stack -
//  nothing reaches the wire and the reactor stops serving. Every route below is bounded.
//
//      dotnet run -c Release --project Playground/Http3/Nghttp3StreamedBoth
//      curl --http3-only -k https://127.0.0.1:8443/          # chunked download
//      curl --http3-only -k --data-binary @big.bin https://127.0.0.1:8443/upload
//      curl --http3-only -k --data-binary @big.bin https://127.0.0.1:8443/echo    # both ways
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.nghttp3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort quicPort = 8443;
int    reactors = Environment.ProcessorCount;

Env.OverrideQuic(ref quicPort, ref reactors);

// Chunks written per response on "/", and the size of each. Their product is never held at once.
int chunkCount = 64;
int chunkBytes = 16 * 1024;

Env.Override(ref chunkCount, "PLAYGROUND_CHUNKS");
Env.Override(ref chunkBytes, "PLAYGROUND_CHUNK_BYTES");

// Multishot recv slots per reactor. QPACK capacity 4096 advertises a decode-side dynamic table;
// 0 is static-only, nghttp3's default.
int  udpRecvSlots  = 16;
long qpackCapacity = 0;

Env.OverrideH3(ref udpRecvSlots, ref qpackCapacity);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

// The last argument bounds what one connection may retain unacknowledged, which is what keeps a
// streamed response streaming instead of quietly buffering whole. See Playground/Http3/Nghttp3Buffered
// for the full QUIC/h3 knob set.
using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"], maxSendRetentionBytes: 16L << 20);

var config = new ServerConfig
{
    ReactorCount = reactors,
    Tcp = null,                                        // QUIC only: no TCP listener is bound
    Udp = new UdpOptions { RecvSlots = udpRecvSlots },
    Quic = new QuicOptions
    {
        Port = quicPort,
        LocalCidLength = 8,
        ConnectionFactory = engine.CreateFactory(),
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
        ReadTimeoutMs = 60_000,   // close a connection whose peer is silent this long; 0 = off
    },
};

var h3Options = new Nghttp3Options
{
    QpackDynamicTableCapacity = qpackCapacity,                // 0 (default) = headers stay literal
    QpackBlockedStreams       = qpackCapacity > 0 ? 100 : 0,  // raise both together for the dynamic table
};

byte[] chunk = Encoding.ASCII.GetBytes(new string('x', chunkBytes - 1) + "\n");

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = (r, conn) =>
        new Nghttp3Connection(conn, h3Options).RunStreamedResponseAsync(async (request, writer) =>
        {
            bool upload = request.Path.Span.SequenceEqual("/upload"u8);
            bool echo   = request.Path.Span.SequenceEqual("/echo"u8);

            if (echo)
            {
                // Both directions at once, which is the shape a proxy needs: read a chunk, write
                // a chunk, and never hold more than one. Neither side can run away from the other
                // - ReadAsync waits on the peer, FlushAsync waits on nghttp3 - so memory stays
                // flat however large the exchange is.
                writer.WriteHeaders(Plain());

                while (true)
                {
                    ReadOnlyMemory<byte> part = await request.BodyReader!.ReadAsync();
                    if (part.IsEmpty)
                    {
                        break;   // end of the request body
                    }

                    part.Span.CopyTo(writer.GetSpan(part.Length));
                    writer.Advance(part.Length);
                    await writer.FlushAsync();
                }

                await writer.CompleteAsync();
                return;
            }

            if (upload)
            {
                // Read side only: pull the body a chunk at a time rather than waiting for all of
                // it, so memory is bound by one chunk however large the upload is. Every read
                // credits the peer's flow-control window, which is what throttles a fast sender.
                long total = 0;
                while (true)
                {
                    ReadOnlyMemory<byte> part = await request.BodyReader!.ReadAsync();
                    if (part.IsEmpty) break;
                    total += part.Length;   // a real app would parse or store the chunk here
                }

                writer.WriteHeaders(Plain());

                byte[] count = Encoding.ASCII.GetBytes($"{total}\n");
                count.CopyTo(writer.GetSpan(count.Length));
                writer.Advance(count.Length);
                await writer.FlushAsync();
                await writer.CompleteAsync();
                return;
            }

            // Headers first and once: HTTP/3 puts HEADERS before DATA and there is no correcting
            // it later. No content-length - the length is not known when they go out. A GET
            // arrives with an already-ended body reader, so there is nothing to drain.
            writer.WriteHeaders(Plain());

            for (int n = 0; n < chunkCount; n++)
            {
                chunk.CopyTo(writer.GetSpan(chunk.Length));
                writer.Advance(chunk.Length);

                // Returns once nghttp3 has taken the chunk. That await IS the backpressure -
                // nothing queues up behind a peer that has stopped reading.
                await writer.FlushAsync();
            }

            await writer.CompleteAsync();
        });

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[nghttp3-streamed-both] {config.ReactorCount} reactors, h3 on udp :{config.Quic!.Port}, "
                + $"{chunkCount} x {chunkBytes}-byte chunks per response, cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}

static Nghttp3Response Plain()
{
    var response = new Nghttp3Response { Status = 200 };
    response.Headers.Add("content-type"u8.ToArray(), "text/plain"u8.ToArray());
    return response;
}
