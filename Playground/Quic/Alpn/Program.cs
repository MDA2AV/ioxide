using System.Buffers;
using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  quic-alpn - one QUIC listener, two protocols, picked by ALPN: connections that negotiated
//  "h3" get real HTTP/3 through ioxide.nghttp3, anything else (including no ALPN at all) gets a
//  raw stream echo through the QuicConnectionDualPipe adapters - QUIC's twin of Tcp.Pipe.
//
//  This server is also QUIC-ONLY: ServerConfig.Tcp is null, so no TCP port is bound at all.
//
//      dotnet run -c Release --project Playground/Quic/Alpn
//      curl --http3-only -ks https://127.0.0.1:8443/          # the h3 branch
//
//  The QUIC handler launches before the handshake, so the ALPN is not known at entry. The demux
//  below awaits the first read WITHOUT draining it - 1-RTT stream data implies the handshake
//  finished - peeks NegotiatedProtocol, and hands the still-queued items to whichever layer owns
//  the connection from here. Both start by reading the same queue, so nothing is lost.
//  Needs: ioxide.ngtcp2, ioxide.nghttp3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.OverrideQuic exists only so bench/run.sh can drive the sample from outside; delete that
// line when you copy this out and the literals above it are the entire configuration.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ - UDP, not TCP
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.OverrideQuic(ref quicPort, ref reactors);

// UDP receive slots per reactor: how many datagrams the ring can have outstanding at once.
int udpRecvSlots = 16;

// Per-connection send-retention high-water (default 16 MiB): a response larger than it streams out
// paced by acks instead of buffering whole. See Playground/Http3/Nghttp3Buffered for the full knob set.
long maxSendRetentionBytes = 16L << 20;

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

// Permissive ALPN (no allowlist): h3 clients negotiate "h3"; everything else still handshakes
// and falls through to the echo branch.
using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: null, maxSendRetentionBytes);

var config = new ServerConfig
{
    ReactorCount   = reactors,   // one ring per reactor, one reactor per core
    RingEntries    = 8192,       // io_uring SQ/CQ depth
    DualStack      = false,      // IPv4-only sockets; true binds dual-stack IPv6 (::)
    RecvBufferSize = 32 * 1024,  // bytes per slot in the shared TCP recv ring
    RecvSlots      = 4096,       // slots in that shared recv ring
    Incremental    = null,       // shared recv ring; non-null = per-connection rings (kernel 6.12+)
    Tcp            = null,       // QUIC-only: no TCP listener is bound
    Udp = new UdpOptions
    {
        RecvSlots = udpRecvSlots,  // multishot recv slots per reactor - datagrams the ring can hold at once
        Gro       = true,          // UDP_GRO: coalesce a received datagram burst into one recv
    },
    Quic = new QuicOptions
    {
        Port              = quicPort,                // https://127.0.0.1:8443/ - UDP, not TCP
        LocalCidLength    = 8,                       // must match the engine's cidLength
        ReadTimeoutMs     = 60_000,                  // close a connection whose peer is silent this long
        ConnectionFactory = engine.CreateFactory(),  // the engine adopts each new connection
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
    },
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = async (r, conn) =>
    {
        // Peek only - the items stay queued for whichever branch takes over.
        await conn.ReadAsync();

        if (conn.NegotiatedProtocol == "h3")
        {
            // Owns the handler ref (DecRef on exit). Routes by byte compare - no per-request
            // strings on the hot path.
            await new Nghttp3Connection(conn).RunBufferedAsync(
                static request => request.Path.Span.SequenceEqual("/plaintext"u8)
                    ? Nghttp3Response.Text("Hello, World!")
                    : Nghttp3Response.Text(
                        $"hello {Encoding.ASCII.GetString(request.Path.Span)} over HTTP/3 via io_uring\n"));
            return;
        }

        await PipeEcho(conn);
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[quic-alpn] {config.ReactorCount} reactors, quic-only on udp :{config.Quic!.Port} "
                + $"(h3 -> HTTP/3, other ALPN -> stream echo)");

foreach (Thread thread in threads)
{
    thread.Join();
}

// Raw stream echo over the dual pipe: auto-binds to the client's first stream, echoes until the
// peer's fin, then Complete() half-closes with our own fin. A connection closed before the
// handshake falls through with a completed reader and exits clean.
static async Task PipeEcho(QuicConnection conn)
{
    try
    {
        var pipe = new QuicConnectionDualPipe(conn);
        while (true)
        {
            var result = await pipe.Input.ReadAsync();
            foreach (ReadOnlyMemory<byte> segment in result.Buffer)
            {
                pipe.Output.Write(segment.Span);
            }
            await pipe.Output.FlushAsync();
            pipe.Input.AdvanceTo(result.Buffer.End);

            if (result.IsCompleted) break;
        }
        pipe.Output.Complete();
        pipe.Input.Complete();
    }
    finally
    {
        conn.DecRef();
    }
}
