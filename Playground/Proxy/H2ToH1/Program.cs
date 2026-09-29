using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.http2;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  proxy h2->h1 - an HTTP/2 front door for an HTTP/1.1 origin, TLS on both hops. This is the
//  classic edge shape: clients get multiplexing and header compression over a real https:// URL,
//  the origin keeps speaking the protocol it already speaks.
//
//  Browsers will not speak h2 in cleartext, so this is the only way the frontend is reachable
//  from one. ALPN is what makes it work: the server offers "h2" and the client picks it during
//  the handshake, before a single byte of HTTP exists.
//
//  Note what Http2Connection is handed - a TlsConnectionDualPipe. It never learns that TLS is
//  involved: the pipe decrypts on the way in and encrypts on the way out, so the HTTP/2 code
//  is byte-for-byte the h2c version.
//
//      # a TLS origin to forward to
//      PLAYGROUND_PORT=8444 dotnet run -c Release --project Playground/Tls/OpenSsl
//      dotnet run -c Release --project Playground/Proxy/H2ToH1
//      curl -k --http2 https://127.0.0.1:8443/
//
//  Note the asymmetry this combination creates. One h2 connection can have a hundred streams in
//  flight, and each one needs its own h1 upstream connection for the duration - h1 has no
//  multiplexing to borrow. So the pool sizes for concurrency here, unlike every h2/h3 upstream in
//  this folder. Run out and the request queues behind a waiter rather than the pool opening
//  unbounded, with the whole acquire bounded by HttpClientOptions.AcquireTimeoutMs - a saturated
//  origin surfaces as a 502 on that stream, not as an fd leak.
//
//  Needs: ioxide, ioxide.http2, ioxide.httpclient
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Each Env.Override names the variable that can drive it instead, which is how the bench scripts
// run this sample; the literal is what applies otherwise. Delete those lines when you copy this
// out and the literals above them are the entire configuration.

int     reactors         = Environment.ProcessorCount;
ushort  port             = 8443;
string  upstreamHost     = "127.0.0.1";
ushort  upstreamPort     = 8444;
string  upstreamSni      = "localhost";
int     upstreamPool     = 32;
string? upstreamCa       = null;
bool    upstreamInsecure = false;
string? certOverride     = null;   // a real PEM pair, or null to self-sign on first run
string? keyOverride      = null;

Env.Override(ref reactors, "PLAYGROUND_REACTORS");
Env.Override(ref port, "PLAYGROUND_PORT");
Env.Override(ref upstreamHost, "PLAYGROUND_UPSTREAM_HOST");
Env.Override(ref upstreamPort, "PLAYGROUND_UPSTREAM_PORT");
Env.Override(ref upstreamSni, "PLAYGROUND_UPSTREAM_SNI");
Env.Override(ref upstreamPool, "PLAYGROUND_UPSTREAM_POOL");
Env.OverrideOptional(ref upstreamCa, "PLAYGROUND_UPSTREAM_CA");
Env.Override(ref upstreamInsecure, "PLAYGROUND_UPSTREAM_INSECURE");
Env.OverrideOptional(ref certOverride, "PLAYGROUND_QUIC_CERT");
Env.OverrideOptional(ref keyOverride, "PLAYGROUND_QUIC_KEY");
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,
    RingEntries    = 8192,       // SQ/CQ depth per ring
    DualStack      = false,      // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,  // bytes per shared recv buffer
    RecvSlots      = 4096,       // shared recv buffer-ring depth
    Incremental    = null,       // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,       // no raw UDP sockets (TCP-only frontend)
    Quic           = null,       // no QUIC listener; the frontend is TLS-over-TCP
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                                 // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                               // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                          // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                               // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,         // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                              // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 64,                                 // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                             // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                             // close a connection whose flush takes this long to go out; 0 = off
    },
};
string upstreamName = upstreamSni;    // sent as SNI, checked against the cert

// The playground's origins use a self-signed cert, so trust that file rather than the system
// store. PLAYGROUND_UPSTREAM_CA points at a private CA instead; PLAYGROUND_UPSTREAM_INSECURE=1
// skips verification, which leaves the hop encrypted but UNAUTHENTICATED - anything in the path
// can present its own certificate and rewrite the whole exchange.
upstreamCa ??= certPath;

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.OnStart = r =>
    {
        // Inbound: terminate TLS and offer only h2, because that is all this frontend serves. A
        // client that cannot do h2 fails ALPN rather than silently getting something else.
        TlsService.Start(r, new TlsOptions
        {
            CertificatePath = certPath,  // PEM cert chain file (set exactly one of Path/Pem)
            CertificatePem  = null,      // in-memory PEM alternative to CertificatePath
            KeyPath         = keyPath,   // PEM private key file (set exactly one of Path/Pem)
            KeyPem          = null,      // in-memory PEM alternative to KeyPath
            Alpn            = ["h2"],    // protocols offered, most preferred first
            KernelTx        = false,     // kTLS encrypt (off = OpenSSL both ways)
            KernelRx        = false,     // kTLS decrypt; requires KernelTx, experimental
        });

        // Outbound: one context per reactor, shared by that reactor's pool - it holds no
        // per-connection state, so every connection opened from it gets its own SSL.
        HttpClientPool.Start(r, new HttpClientOptions
        {
            Host              = upstreamHost,     // origin address (IPv4 literal; DNS would block the reactor)
            Port              = upstreamPort,     // origin port
            PoolSize          = upstreamPool,     // connections kept open; round-robin, one request each
            MaxResponseBytes  = 8 * 1024 * 1024,  // per-request ceiling for headers + body
            SendBufferSize    = 16 * 1024,        // per-connection send buffer
            ReceiveBufferSize = 16 * 1024,        // per-connection recv buffer (grows to MaxResponseBytes)
            AcquireTimeoutMs  = 10_000,           // how long a request waits for a free connection
            Tls = TlsClientContext.Create(new TlsClientOptions
            {
                ServerName         = upstreamName,                          // sent as SNI, checked against the cert
                AlpnProtocols      = ["http/1.1"],                          // ALPN offer, most preferred first
                VerifyCertificate  = !upstreamInsecure,                     // off = encrypted but UNAUTHENTICATED
                CaFile             = upstreamInsecure ? null : upstreamCa,  // PEM trust anchors; null = system store
                MinimumVersion     = OpenSslVersions.Tls12,                 // lowest TLS accepted; Tls13 = 1.3 only
                HandshakeTimeoutMs = 10_000,                                // handshake deadline
            }),
        });
    };

    reactor.TcpHandle = async (r, conn) =>
    {
        HttpClientPool client = r.GetService<HttpClientPool>();
        TlsSession? tls = null;

        try
        {
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // The decrypt pump lives in the pipe, so everything below is the cleartext sample -
            // and the pipe resumes inline on this reactor, so the upstream call below does too.
            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

            // Buffered + async: each stream dispatches with its body assembled, and the handler
            // may await - the upstream round trip resumes inline on this reactor. Concurrent
            // streams interleave here, which is exactly why the h1 pool has to be deep.
            await new Http2Connection(pipe).RunBufferedAsync(async request =>
            {
                try
                {
                    // Method, path and body forward as the bytes they already are: h2 decoded
                    // them out of HPACK, and the h1 client writes them back out as a request line.
                    using HttpClientResponse response = await client.SendAsync(new HttpClientRequest(
                        request.Method, request.Path) { Body = request.Body });

                    // Copy before Dispose: the response arena is freed then, and the h2 response
                    // is framed only AFTER this handler returns. A real proxy would also
                    // drop hop-by-hop headers - Connection, Keep-Alive, Transfer-Encoding are all
                    // illegal in h2 and would be a protocol error to forward.
                    var proxied = new Http2Response
                    {
                        Status = response.Status,
                        Body = response.Body.ToArray(),
                    };
                    if (response.TryGetHeader("content-type"u8, out ReadOnlyMemory<byte> contentType))
                    {
                        proxied.Headers.Add("content-type"u8.ToArray(), contentType.ToArray());
                    }
                    return proxied;
                }
                catch (Exception e)
                {
                    // Upstream down is a gateway error on this stream, not a dead h2 connection:
                    // every other stream on it keeps working. A refused certificate arrives the
                    // same way - the handshake is part of opening the upstream connection.
                    return new Http2Response
                    {
                        Status = 502,
                        Body = Encoding.ASCII.GetBytes($"upstream failed: {e.Message}\n"),
                    };
                }
            });
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[proxy h2->h1] connection failed: {e.Message}");
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[proxy h2->h1] {config.ReactorCount} reactors, h2 over TLS on :{config.Tcp!.Port} "
                + $"-> https://{upstreamName} ({upstreamHost}:{upstreamPort}), "
                + $"{upstreamPool} connections each, "
                + $"verify={(upstreamInsecure ? "OFF" : upstreamCa ?? "system store")}");

foreach (Thread thread in threads)
{
    thread.Join();
}
