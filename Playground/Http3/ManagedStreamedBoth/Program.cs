using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http3-managed-streamed-both - HTTP/3 in pure C# with BOTH directions streamed.
//
//  The request body arrives through Http3Request.BodyReader, pulled a chunk at a time under
//  flow control, so a large upload is never held whole. The response body goes out through an
//  Http3ResponseWriter, one DATA frame per flush, so a large download is never built whole.
//
//  "/echo" runs both at once - read a chunk, write a chunk - which is what a proxy does and the
//  case that shows the two halves are independent. Memory stays flat regardless of size, because
//  each side blocks the other: ReadAsync waits on the peer, FlushAsync waits on the connection.
//
//  Because ioxide.http3 owns the framing, sending is a push: build [0x00][varint len][payload]
//  and hand it to the QUIC stream. There is no data-reader callback to answer and nothing to
//  defer - which is the difference from the nghttp3 version of this in Playground/Http3/Nghttp3Response.
//
//      dotnet run -c Release --project Playground/Http3/ManagedStreamedBoth
//      curl --http3-only -k https://127.0.0.1:8443/          # chunked download
//      curl --http3-only -kN https://127.0.0.1:8443/feed     # endless; ctrl-c to stop
//      curl --http3-only -k --data-binary @big.bin https://127.0.0.1:8443/upload
//      curl --http3-only -k --data-binary @big.bin https://127.0.0.1:8443/echo    # both ways
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.http3
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

int udpRecvSlots = 16;

string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

var config = new ServerConfig
{
    ReactorCount = reactors,
    Tcp = null,
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
        SendRetentionBytes = 16L << 20,          // unacked response bytes a connection holds before a response waits for acks
        SendRetentionCeilingBytes = 32L << 20,   // a connection past this is closed: its producer ignored the wait
    },
};

byte[] chunk = Encoding.ASCII.GetBytes(new string('x', chunkBytes - 1) + "\n");

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = (r, conn) =>
        new Http3Connection(conn).RunStreamedResponseAsync(async (request, writer) =>
        {
            bool endless = request.Path.Span.SequenceEqual("/feed"u8);
            bool upload  = request.Path.Span.SequenceEqual("/upload"u8);
            bool echo    = request.Path.Span.SequenceEqual("/echo"u8);

            if (echo)
            {
                // BOTH directions at once, which is the shape a proxy actually needs: read a
                // chunk, write a chunk, and never hold more than one. Neither side can run away
                // from the other - ReadAsync waits for the peer to send, FlushAsync waits for the
                // connection to have room - so memory stays flat however large the exchange is.
                writer.WriteHeaders(Plain());

                if (request.BodyReader is { } duplex)
                {
                    while (true)
                    {
                        ReadOnlyMemory<byte> part = await duplex.ReadAsync();
                        if (part.IsEmpty)
                        {
                            break;   // end of the request body
                        }

                        part.Span.CopyTo(writer.GetSpan(part.Length));
                        writer.Advance(part.Length);
                        await writer.FlushAsync();
                    }
                }

                return;
            }

            if (upload)
            {
                // The other direction: pull the body a chunk at a time rather than waiting for
                // all of it, so memory is bound by one chunk however large the upload is.
                long total = 0;
                if (request.BodyReader is { } body)
                {
                    while (true)
                    {
                        ReadOnlyMemory<byte> part = await body.ReadAsync();
                        if (part.IsEmpty) break;
                        total += part.Length;
                    }
                }

                writer.WriteHeaders(Plain());
                Encoding.ASCII.GetBytes($"{total}\n").CopyTo(writer.GetSpan(24));
                writer.Advance(Encoding.ASCII.GetByteCount($"{total}\n"));
                await writer.FlushAsync();
                return;
            }

            writer.WriteHeaders(Plain(endless));

            for (int n = 0; endless || n < chunkCount; n++)
            {
                chunk.CopyTo(writer.GetSpan(chunk.Length));
                writer.Advance(chunk.Length);

                // Returns once the chunk is queued, and waits when the connection is at its
                // send-retention high-water. That await IS the backpressure.
                await writer.FlushAsync();
            }
        });

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[http3-managed-streamed-both] {config.ReactorCount} reactors, h3 on udp :{config.Quic!.Port} "
                + $"(pure C#), {chunkCount} x {chunkBytes}-byte chunks, cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}

static Http3Response Plain(bool eventStream = false)
{
    var response = new Http3Response { Status = 200 };
    response.Headers.Add(("content-type"u8.ToArray(),
        eventStream ? "text/event-stream"u8.ToArray() : "text/plain"u8.ToArray()));
    return response;
}
