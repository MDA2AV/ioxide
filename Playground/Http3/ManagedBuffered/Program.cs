using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http3-managed-buffered - HTTP/3 in PURE C#, dispatched BUFFERED: the handler runs once the request
//  has fully arrived, so request.Body already holds the whole body. Frames, QPACK and Huffman
//  are all managed code, so nothing native ships but the QUIC transport underneath.
//
//  The same server as Playground/Http3/Nghttp3Request otherwise - the diff is the package and the type
//  names - which is what makes the two directly comparable:
//
//      dotnet run -c Release --project Playground/Http3/ManagedBuffered
//      curl --http3-only -k https://127.0.0.1:8443/
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.http3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Each Env.Override names the variable that can drive it instead, which is how the bench scripts
// run this sample; the literal is what applies otherwise.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ over UDP
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.OverrideQuic(ref quicPort, ref reactors);

// Response body size. 13 is "Hello, World!"; anything else is that many 'x'.
int bodyBytes = 13;

Env.Override(ref bodyBytes, "PLAYGROUND_BODY");

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
    Tcp = null,                                        // QUIC only
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

// Built once and reused: the h3 layer copies status, headers and body at submit and never retains
// the object, so a hot path should not rebuild it per request.
var response = new Http3Response
{
    Body = bodyBytes == 13 ? "Hello, World!"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes)],
};
response.Headers.Add(("content-type"u8.ToArray(), "text/plain"u8.ToArray()));
response.Headers.Add(("server"u8.ToArray(), "ioxide"u8.ToArray()));

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = (r, conn) => new Http3Connection(conn).RunAsync(_ => response);

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[http3-managed-buffered] {config.ReactorCount} reactors, h3 on udp :{config.Quic!.Port} "
                + $"(pure C#), {bodyBytes}-byte body, cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}
