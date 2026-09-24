using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-httpsclient - the OTHER direction of ioxide.tls: not terminating TLS for inbound
//  connections, but speaking it outbound so a handler can reach an https:// origin.
//
//      dotnet run -c Release --project Playground/Clients/Https
//      curl http://127.0.0.1:8080/get
//
//  The TLS context is built once and shared by the pool: it holds no per-connection state, so
//  every connection opened from it gets its own SSL. The handshake rides the reactor's ring like
//  every other I/O here, and the response resumes this handler inline on its own thread.
//
//  Unlike the server side, none of this needs kTLS - nothing is offloaded to the kernel, so it
//  runs without 'modprobe tls'. Needs: ioxide, ioxide.httpclient
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/get - cleartext IN
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The https origin this calls OUT to. Point it somewhere real: "93.184.216.34" / "example.com"
// / 443. The IP must be a literal - resolving a name would block the reactor - and the NAME is
// what goes out as SNI and what the certificate has to match.
string originIp   = "127.0.0.1";
string originName = "localhost";
ushort originPort = 443;

// Trust a private CA instead of the system store: "/path/ca.pem".
string? caFile = null;

// Skip certificate verification entirely. Read the warning at the call site before setting it.
bool insecure = false;

Env.Override(ref originIp, "PLAYGROUND_UPSTREAM_HOST");
Env.Override(ref originName, "PLAYGROUND_UPSTREAM_SNI");
Env.Override(ref originPort, "PLAYGROUND_UPSTREAM_PORT");
Env.OverrideOptional(ref caFile, "PLAYGROUND_UPSTREAM_CA");
Env.Override(ref insecure, "PLAYGROUND_UPSTREAM_INSECURE");
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,                          // io_uring rings/threads - one per core
    RingEntries    = 8192,                              // SQ/CQ depth per ring
    DualStack      = false,                             // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                         // bytes per shared recv buffer
    RecvSlots      = 4096,                              // shared recv buffer-ring depth
    Incremental    = null,                              // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                              // no raw UDP sockets (TCP-only server)
    Quic           = null,                              // no QUIC transport - see Http3/* and Quic/Alpn
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                          // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                        // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                   // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                        // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,  // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                       // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 64,                          // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                      // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                      // close a connection whose flush takes this long to go out; 0 = off
    },
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.OnStart = r =>
    {
        // One context per reactor, shared by that reactor's pool. Verification is on by default;
        // turning it off leaves the connection encrypted but UNAUTHENTICATED, so anything in the
        // path can present its own certificate and read or rewrite the whole exchange. A private
        // CA belongs in CaFile, not here.
        TlsClientContext tls = TlsClientContext.Create(new TlsClientOptions
        {
            ServerName         = originName,             // sent as SNI, checked against the cert (required)
            AlpnProtocols      = ["http/1.1"],           // offered most-preferred first; [] offers none
            CaFile             = caFile,                 // PEM trust anchors; null = system store
            VerifyCertificate  = !insecure,              // off = encrypted but UNAUTHENTICATED (tests only)
            MinimumVersion     = OpenSslVersions.Tls12,  // lowest TLS accepted; Tls13 (0x0304) = 1.3-only
            HandshakeTimeoutMs = 10_000,                 // handshake ceiling before the connect fails
        });

        HttpClientPool.Start(r, new HttpClientOptions
        {
            Host              = originIp,         // IPv4 literal - DNS would block the reactor
            Port              = originPort,       // origin port
            PoolSize          = 2,                // connections to the origin, per reactor
            MaxResponseBytes  = 8 * 1024 * 1024,  // per-request ceiling for headers + body
            SendBufferSize    = 16 * 1024,        // per-connection send buffer
            ReceiveBufferSize = 16 * 1024,        // per-connection recv buffer; grows to MaxResponseBytes
            Tls               = tls,              // TLS context for https; null = cleartext
            AcquireTimeoutMs  = 10_000,           // wait for a free connection when all are busy
        });
    };

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            HttpClientPool upstream = r.GetService<HttpClientPool>()!;

            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                string path = "/";
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        if (TryReadTarget(item.AsSpan(), out ReadOnlySpan<byte> target))
                        {
                            path = Encoding.ASCII.GetString(target);
                        }
                        conn.ReturnBuffer(in item);
                    }
                }

                try
                {
                    // Encrypted on the way out, decrypted on the way back, and neither shows up
                    // here: the pool hands back the same HttpClientResponse a cleartext origin
                    // would have produced.
                    using HttpClientResponse response = await upstream.GetAsync(path);

                    conn.Write(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Length: {response.Body.Length}\r\n\r\n"));
                    conn.Write(response.Body.Span);
                }
                catch (Exception e)
                {
                    // A refused certificate arrives here like any other upstream failure - the
                    // handshake is part of opening the connection, so the pool reports it the same
                    // way it reports a dead origin.
                    byte[] message = Encoding.ASCII.GetBytes($"upstream: {e.Message}");
                    conn.Write(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {message.Length}\r\n\r\n"));
                    conn.Write(message);
                }

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

Console.WriteLine($"[tls-httpsclient] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"origin https://{originName} ({originIp}:{originPort}), "
                + $"verify={(insecure ? "OFF" : caFile ?? "system store")}");

foreach (Thread thread in threads)
{
    thread.Join();
}

// "GET /path?query HTTP/1.1" -> "/path"
static bool TryReadTarget(ReadOnlySpan<byte> request, out ReadOnlySpan<byte> target)
{
    target = default;

    int firstSpace = request.IndexOf((byte)' ');
    if (firstSpace < 0) return false;

    ReadOnlySpan<byte> afterMethod = request[(firstSpace + 1)..];
    int secondSpace = afterMethod.IndexOf((byte)' ');
    if (secondSpace < 0) return false;

    target = afterMethod[..secondSpace];

    int query = target.IndexOf((byte)'?');
    if (query >= 0) target = target[..query];

    return true;
}
