using System.Runtime.InteropServices;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  nghttp3-streamed-request - a real HTTP/3 server, whole, dispatched as the REQUEST body
//  streams in: the handler runs while the upload is still arriving, so memory is bound by one
//  flow-control window rather than by the body. ngtcp2 + picotls are bundled as one native library
//  (TLS 1.3 lives inside the transport), and nghttp3 puts HTTP/3 on top. Every reactor binds the
//  UDP port via SO_REUSEPORT and demuxes its own flows.
//
//  STREAMED dispatch: your handler runs at end-of-headers, while the body is still arriving. Each
//  chunk you read credits the peer's flow-control window, so memory is bound by one window rather
//  than by the size of the upload. See Playground/Http3/Nghttp3Buffered for the other mode.
//
//      dotnet run -c Release --project Playground/Http3/Nghttp3Request
//      curl --http3-only -k https://127.0.0.1:8443/
//      h2load --alpn-list=h3 -n 1 -c 1 -d bigfile.bin https://127.0.0.1:8443/
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.nghttp3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// An Env.Override line means the value can also be set from the environment, which is how
// bench/run.sh drives the sample; the literal is what applies otherwise. Delete those lines when
// you copy this out and the literals above them are the entire configuration.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ over UDP - h3 lives here
ushort tcpPort  = 8080;                        // the TCP listener, so the process serves both
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref tcpPort, ref reactors);
Env.OverrideQuic(ref quicPort, ref reactors);

// Multishot recv slots per reactor - datagrams the ring can hold at once. QPACK capacity 4096
// advertises a decode-side dynamic table; 0 is static-only, nghttp3's default.
int  udpRecvSlots  = 16;

// Response body size. 13 is "Hello, World!"; anything else is that many 'x'. A buffered response
// holds the whole body, so this is also what a streamed response is measured against.
int  bodyBytes     = 13;
long qpackCapacity = 0;

Env.OverrideH3(ref udpRecvSlots, ref qpackCapacity);
Env.Override(ref bodyBytes, "PLAYGROUND_BODY");

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

// One engine for the whole server. ALPN pinned to h3, so nothing else negotiates. The last arg is
// the per-connection send-retention high-water (default 16 MiB): a response larger than it streams
// out paced by acks instead of buffering whole, so h3 serves large files in bounded memory. See
// Playground/Http3/Nghttp3Buffered for the full QUIC/h3 knob set.
using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"], maxSendRetentionBytes: 16L << 20);

var config = new ServerConfig
{
    ReactorCount   = reactors,  // one ring per reactor, one reactor per core
    RingEntries    = 8192,       // io_uring SQ/CQ depth
    DualStack      = false,      // IPv4-only listeners; true binds dual-stack IPv6 (::)
    RecvBufferSize = 32 * 1024,  // bytes per slot in the shared TCP recv ring
    RecvSlots      = 4096,       // slots in that shared recv ring
    Incremental    = null,       // shared recv ring; non-null = per-connection rings (kernel 6.12+)
    Tcp = new TcpOptions
    {
        Port             = tcpPort,  // the TCP listener, so the process serves both
        ExtraPorts       = [],                          // extra listener ports, each bound by every reactor
        ListenBacklog    = 1024,                        // listen() accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                   // per-connection write slab before overflow
        PoolMax          = 1024,                        // max pooled connection objects per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,  // grow the slab; Segmented chains pooled slabs
        ZeroCopySend     = false,                       // plain SEND; SEND_ZC only wins for large responses
        RecvQueueEntries = 64,                          // per-connection SPSC recv queue depth (power of two)
    },
    Udp = new UdpOptions
    {
        RecvSlots = udpRecvSlots,  // multishot recv slots per reactor - datagrams the ring can hold at once
        Gro       = true,  // UDP_GRO: coalesce a received datagram burst into one recv
    },
    Quic = new QuicOptions
    {
        Port              = quicPort,                // https://127.0.0.1:8443/ over UDP - h3 lives here
        LocalCidLength    = 8,                       // must match the engine's cidLength
        ReadTimeoutMs     = 60_000,                  // close a connection whose peer is silent this long
        ConnectionFactory = engine.CreateFactory(),  // the engine adopts each new connection
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
    },
};

var h3Options = new Nghttp3Options
{
    QpackDynamicTableCapacity = qpackCapacity,                // 0 (default) = headers stay literal
    QpackBlockedStreams       = qpackCapacity > 0 ? 100 : 0,  // raise both together for the dynamic table
};

// THE allocation-free pattern: build the response ONCE and reuse the instance for every request.
// Legal because the h3 layer copies status, headers and body into nghttp3 synchronously at submit
// and never retains the object - unlike Nghttp3Response.Text($"..."), which encodes a fresh string
// every time. This is what a hot path should look like.
var response = new Nghttp3Response
{
    Body = bodyBytes == 13 ? "Hello, World!"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes)],
};
response.Headers.Add("content-type"u8.ToArray(), "text/plain"u8.ToArray());
response.Headers.Add("server"u8.ToArray(), "ioxide"u8.ToArray());

// A fixed TCP response for :8080, which still listens alongside the QUIC port.
byte[] tcpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"u8.ToArray();

// Live connections, so SIGTERM can GOAWAY them all. Each reactor only ever adds its own, but the
// signal handler runs OFF the reactor threads, so a plain lock keeps it honest.
List<(Reactor Reactor, Nghttp3Connection Connection)> live = [];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // ---- HTTP/3 on udp :8443 ----------------------------------------------------------------
    // Nghttp3Connection owns the connection's read loop: it feeds stream data into nghttp3,
    // assembles each request - headers, body and all - and calls your function once per request.
    // QPACK, control streams, fin and stream teardown are its problem, not yours.
    reactor.QuicHandle = (r, quicConn) =>
    {
        var h3 = new Nghttp3Connection(quicConn, h3Options);
        lock (live)
        {
            live.Add((r, h3));
        }

        return h3.RunStreamingAsync(async request =>
        {
            // Streamed dispatch, so we are running while the body is still on the wire. Read it to
            // the end: every read credits the peer's flow-control window, which is what throttles a
            // fast sender instead of buffering it. Chunks are valid until the next ReadAsync, and a
            // request with no body simply finds it empty on the first read.
            long total = 0;
            while (true)
            {
                ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
                if (chunk.IsEmpty) break;
                total += chunk.Length;   // a real app would parse or store the chunk here
            }

            // One response object, reused for every request: zero allocations on this path. To
            // route, compare request.Path.Span - it is post-QPACK bytes, so SequenceEqual against a
            // u8 literal beats decoding it to a string.
            return response;
        });
    };

    // ---- plain HTTP/1.1 on tcp :8080 ---------------------------------------------------------
    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer) conn.ReturnBuffer(in item);
                }

                conn.Write(tcpResponse);
                await conn.FlushAsync();

                if (snapshot.IsClosed) return;
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

// Graceful shutdown. Without this the process dies mid-request and clients see resets. This runs
// OFF the reactor threads, so each Shutdown is marshalled back onto its owning reactor - nghttp3
// and the send path must only be touched there.
using var drain = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
{
    context.Cancel = true;
    Console.WriteLine("[nghttp3] SIGTERM: draining connections (GOAWAY)...");

    lock (live)
    {
        foreach ((Reactor r, Nghttp3Connection h3) in live)
        {
            r.ScheduleOnReactor(static state => ((Nghttp3Connection)state!).Shutdown(), h3);
        }
        live.Clear();
    }

    Thread.Sleep(2000);   // let in-flight requests finish
    Console.WriteLine("[nghttp3] drain complete, exiting");
    Environment.Exit(0);
});

Console.WriteLine($"[nghttp3] {config.ReactorCount} reactors - tcp :{config.Tcp.Port}, "
                + $"udp :{quicPort} (ngtcp2 {QuicEngine.NativeVersion()})");

foreach (Thread thread in threads)
{
    thread.Join();
}
