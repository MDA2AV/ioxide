using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  nghttp3-streamed-response - HTTP/3 where the RESPONSE body is produced over time rather
//  than handed over whole. The other two nghttp3 samples differ in how the REQUEST arrives;
//  this one is about the other direction.
//
//  Buffered and streaming both end with `return new Nghttp3Response { Body = ... }` - the whole
//  body has to exist before anything can be sent. That is fine for a page and impossible for a
//  feed: an endpoint that never stops has no final byte to return. Here the handler gets a
//  WRITER, and each flush becomes DATA on the wire.
//
//      dotnet run -c Release --project Playground/Http3/Nghttp3Response
//      curl --http3-only -k https://127.0.0.1:8443/         # 64 chunks, one per flush
//      curl --http3-only -kN https://127.0.0.1:8443/feed    # never ends; ctrl-c to stop
//
//  The writer is an IBufferWriter<byte>, so anything that already writes into one - a JSON
//  serializer, a file copy, a framework's response sink - streams through it unchanged.
//  Backpressure is real: FlushAsync returns once nghttp3 has taken the chunk, so a peer that
//  stops reading stops the producer rather than growing a queue behind it.
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.nghttp3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Each Env.Override names the variable that can drive it instead, which is how the bench scripts
// run this sample; the literal is what applies otherwise.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ over UDP
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.OverrideQuic(ref quicPort, ref reactors);

// Chunks written per response on "/", and the size of each. The point of the sample is that the
// product of these two is never held in memory at once.
int chunkCount = 64;
int chunkBytes = 4 * 1024;

Env.Override(ref chunkCount, "PLAYGROUND_CHUNKS");
Env.Override(ref chunkBytes, "PLAYGROUND_CHUNK_BYTES");

// UDP receive slots per reactor: how many datagrams the ring can have outstanding at once.
int udpRecvSlots = 16;

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

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
        new Nghttp3Connection(conn).RunStreamedResponseAsync(async (request, writer) =>
        {
            bool endless = request.Path.Span.SequenceEqual("/feed"u8);

            // Headers first and once: HTTP/3 puts HEADERS before DATA and there is no correcting
            // it later. No Content-Length here - the length is not known yet, and for /feed never
            // will be.
            var response = new Nghttp3Response { Status = 200 };
            response.Headers.Add("content-type"u8.ToArray(),
                endless ? "text/event-stream"u8.ToArray() : "text/plain"u8.ToArray());
            writer.WriteHeaders(response);

            for (int n = 0; endless || n < chunkCount; n++)
            {
                chunk.CopyTo(writer.GetSpan(chunk.Length));
                writer.Advance(chunk.Length);

                // Returns once nghttp3 has taken it. That await IS the backpressure - nothing
                // queues up behind a peer that has stopped reading.
                await writer.FlushAsync();
            }

            // CompleteAsync ends the stream. The runner calls it too if a handler returns without
            // doing so, since the peer is owed an end either way.
            await writer.CompleteAsync();
        });

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[h3-streamed] {config.ReactorCount} reactors, h3 on udp :{config.Quic!.Port}, "
                + $"{chunkCount} x {chunkBytes}-byte chunks per response, cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}
