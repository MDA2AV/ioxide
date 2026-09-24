using System.Runtime.InteropServices;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  nghttp3-buffered - the same HTTP/3 server as Playground/Http3/Nghttp3Request, with the
//  OTHER request dispatch mode.
//
//  BUFFERED: dispatch waits for end-of-stream, so the whole body is already in request.Body when
//  your handler runs - no BodyReader, no pacing - and the handler may still await (a PgPool query,
//  Redis, anything ioxide-native resumes inline on the reactor).
//
//  The trade: memory holds the entire body, so this suits normal-sized requests. Use Playground/Http3/Nghttp3Request
//  when uploads can be large or hostile.
//
//  It doubles as the QUIC/HTTP3 tuning reference: the Knobs block below shows every h3-path option
//  (engine, listener, UDP, QPACK) as a literal, including maxSendRetentionBytes - the knob that
//  bounds memory when serving large responses.
//
//      dotnet run -c Release --project Playground/Http3/Nghttp3Buffered
//      curl --http3-only -k https://127.0.0.1:8443/
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.nghttp3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete those lines
// when you copy this out and the literals above them are the entire configuration.

// This sample is the QUIC/HTTP3 tuning reference: every knob the h3 path exposes is here as a
// literal, grouped by the type it feeds. The defaults are the shipping defaults - shown, not
// changed - so you can see the whole surface and edit one line.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ over UDP - h3 lives here
ushort tcpPort  = 8080;                        // the TCP listener, so the process serves both
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref tcpPort, ref reactors);
Env.OverrideQuic(ref quicPort, ref reactors);

// ── QuicEngine: the per-endpoint QUIC/TLS state, shared by every connection ───────────────────
uint cidLength = 8;                            // connection-id length this endpoint mints (1..20)

// Per-connection send-retention high-water. A response larger than this is streamed out paced by
// the peer's acks instead of buffered whole, so memory stays ~this-per-connection whatever the
// response size - the knob that lets HTTP/3 serve large files. Raise for more in-flight throughput
// on fat links; lower to cap memory under many connections. Default 16 MiB.
long maxSendRetentionBytes = 16L << 20;

// ── QuicOptions: the listener ─────────────────────────────────────────────────────────────────
int readTimeoutMs = 60_000;                    // close a connection whose peer is silent this long

// ── UdpOptions: how datagrams are received ────────────────────────────────────────────────────
int  udpRecvSlots = 16;                        // multishot recv slots per reactor - datagrams the ring can hold at once
bool gro          = true;                       // UDP_GRO: coalesce received datagrams into one recv (fewer syscalls)

// ── Nghttp3Options: the HTTP/3 layer ──────────────────────────────────────────────────────────
// QPACK dynamic table. 0 keeps every header literal, which costs bytes but never blocks a stream
// on a table update; raise it and set QpackBlockedStreams to trade one for the other.
long qpackCapacity = 0;
long qpackBlockedStreams = qpackCapacity > 0 ? 100 : 0;

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

using var engine = new QuicEngine(certPath, keyPath, cidLength, alpn: ["h3"], maxSendRetentionBytes);

var config = new ServerConfig
{
    ReactorCount   = reactors,
    RingEntries    = 8192,                                  // SQ/CQ depth per ring
    DualStack      = false,                                 // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
    Tcp = new TcpOptions
    {
        Port             = tcpPort,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                          // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 64,                             // per-connection recv completion queue depth
    },
    Udp = new UdpOptions { RecvSlots = udpRecvSlots, Gro = gro },
    Quic = new QuicOptions
    {
        Port = quicPort,
        LocalCidLength = (int)cidLength,        // must match the engine's cidLength
        ReadTimeoutMs = readTimeoutMs,
        ConnectionFactory = engine.CreateFactory(),
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
    },
};

var h3Options = new Nghttp3Options
{
    QpackDynamicTableCapacity = qpackCapacity,
    QpackBlockedStreams = qpackBlockedStreams,
};

// Built once and reused for every request - the h3 layer copies it into nghttp3 at submit and never
// retains it, so this costs zero allocations per request.
var response = new Nghttp3Response { Body = "Hello, World!"u8.ToArray() };
response.Headers.Add("content-type"u8.ToArray(), "text/plain"u8.ToArray());
response.Headers.Add("server"u8.ToArray(), "ioxide"u8.ToArray());

byte[] tcpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"u8.ToArray();

List<(Reactor Reactor, Nghttp3Connection Connection)> live = [];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = (r, quicConn) =>
    {
        var h3 = new Nghttp3Connection(quicConn, h3Options);
        lock (live)
        {
            live.Add((r, h3));
        }

        // RunBufferedAsync, not RunStreamingAsync - that one call is the whole difference.
        return h3.RunBufferedAsync(request =>
        {
            // Dispatch waited for end-of-stream, so the body is ALREADY here: request.Body is
            // complete and request.Body.Length is just a property read. No BodyReader, no pacing.
            // This overload is synchronous, but the awaiting one exists too - a PgPool query or a
            // Redis command resumes inline on this reactor, so you can await it right here.
            _ = request.Body.Length;

            // One response object, reused for every request: zero allocations on this path. To
            // route, compare request.Path.Span - it is post-QPACK bytes, so SequenceEqual against a
            // u8 literal beats decoding it to a string.
            return response;
        });
    };

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

using var drain = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
{
    context.Cancel = true;
    Console.WriteLine("[nghttp3-buffered] SIGTERM: draining connections (GOAWAY)...");

    lock (live)
    {
        foreach ((Reactor r, Nghttp3Connection h3) in live)
        {
            r.ScheduleOnReactor(static state => ((Nghttp3Connection)state!).Shutdown(), h3);
        }
        live.Clear();
    }

    Thread.Sleep(2000);
    Console.WriteLine("[nghttp3-buffered] drain complete, exiting");
    Environment.Exit(0);
});

Console.WriteLine($"[nghttp3-buffered] {config.ReactorCount} reactors - tcp :{config.Tcp.Port}, "
                + $"udp :{quicPort} (ngtcp2 {QuicEngine.NativeVersion()})");

foreach (Thread thread in threads)
{
    thread.Join();
}
