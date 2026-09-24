using ioxide;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  quic-raw - QUIC on the raw ring surface: EVERY stream on the connection, not just one. A
//  delivery carries its stream id, so a multi-stream protocol demuxes right here. This is the
//  surface ioxide.nghttp3 sits on.
//
//  Compare Quic/Pipe, which wraps a single stream in an IDuplexPipe: convenient, and the reason
//  it cannot serve HTTP/3 - one PipeReader is one byte stream, and h3 needs many at once.
//
//  ngtcp2 + picotls ship as one bundled native, so TLS 1.3 lives inside the transport - there is
//  no TlsService and no ALPN plumbing, because the certificate IS the configuration.
//
//  QUIC-ONLY: ServerConfig.Tcp is null, so no TCP port is bound at all.
//
//      dotnet run -c Release --project Playground/Quic/Raw
//
//  Needs: ioxide, ioxide.ngtcp2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.OverrideQuic exists only so bench/run.sh can drive the sample from outside; delete that
// line when you copy this out and the literals above it are the entire configuration.

ushort quicPort = 8443;                        // QUIC is UDP - this is a UDP port
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.OverrideQuic(ref quicPort, ref reactors);

// UDP receive slots per reactor. Each slot pins ~64 KiB, enough for a full GRO train.
int udpRecvSlots = 16;

// Per-connection send-retention high-water. A response larger than this streams out paced by
// acks instead of being buffered whole, so QUIC serves large responses without unbounded
// per-connection memory.
long maxSendRetentionBytes = 16L << 20;

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["echo"],
                                  maxSendRetentionBytes: maxSendRetentionBytes);

var config = new ServerConfig
{
    ReactorCount = reactors,
    RingEntries  = 8192,                         // SQ/CQ depth per ring
    DualStack    = false,
    Incremental  = null,                         // per-connection recv rings (6.12+) - see Tcp/Incremental

    Tcp = null,                                  // QUIC only: no TCP listener is opened

    // QUIC rides UDP, so these are its socket tunables. Ports is for RAW datagram sockets
    // (Reactor.OnDatagram) - QUIC binds its own port and needs none listed here.
    Udp = new UdpOptions
    {
        Ports     = [],
        RecvSlots = udpRecvSlots,
        Gro       = true,
    },

    Quic = new QuicOptions
    {
        Port              = quicPort,            // every reactor binds it via SO_REUSEPORT
        LocalCidLength    = 8,                   // short headers carry no CID length on the wire
        ConnectionFactory = engine.CreateFactory(),
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
        ReadTimeoutMs     = 60_000,              // close a connection whose peer is silent this long; 0 disables
    },
};

var threads = new Thread[config.ReactorCount];

for (int id = 0; id < threads.Length; id++)
{
    var reactor = new Reactor(id, config);

    reactor.QuicHandle = async (r, conn) =>
    {
        while (true)
        {
            QuicRecvSnapshot snapshot = await conn.ReadAsync();

            // Each delivery names its stream, so echoing back on delivery.StreamId keeps every
            // stream independent - which is exactly what a multi-stream protocol needs.
            while (conn.TryGetDelivery(in snapshot, out QuicRecvRing.Delivery delivery))
            {
                conn.SendStream(delivery.StreamId, delivery.AsSpan(), fin: false);
                conn.ReturnBuffer(in delivery);
            }

            if (snapshot.IsClosed) return;
            conn.ResetRead();
        }
    };

    threads[id] = new Thread(reactor.Run) { Name = $"reactor-{id}" };
    threads[id].Start();
}

Console.WriteLine($"[quic-raw] {config.ReactorCount} reactors, QUIC on udp :{config.Quic!.Port} "
                + $"(ngtcp2 {QuicEngine.NativeVersion()}), cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}
