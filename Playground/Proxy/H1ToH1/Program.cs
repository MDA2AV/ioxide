using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.tls;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  proxy h1->h1 - a reverse proxy, whole, with TLS on BOTH hops. Every inbound connection is
//  terminated here and a fresh TLS connection is opened to the origin; both hops run on this
//  reactor's ring and resume inline, so a proxied request never leaves the thread it arrived on.
//
//  This is the shape every other sample in this folder varies. Read it first.
//
//      # a TLS origin to forward to
//      PLAYGROUND_PORT=8444 dotnet run -c Release --project Playground/Tls/OpenSsl
//      dotnet run -c Release --project Playground/Proxy/H1ToH1
//      curl -k https://127.0.0.1:8443/
//
//  Two TLS stacks are in play. INBOUND is ioxide's own termination, OpenSSL in both directions
//  by default. OUTBOUND is the client pool's: each upstream connection wraps its own
//  TlsClientStream. Neither shows up in the proxying code.
//
//  Needs: ioxide, ioxide.httpclient
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
int     upstreamPool     = 8;
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
        RecvQueueEntries = 4096,                               // per-connection recv completion queue depth
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
        // Inbound: terminate TLS for clients. ALPN is an ordered list and this proxy speaks one
        // protocol, so it offers exactly one.
        TlsService.Start(r, new TlsOptions
        {
            CertificatePath = certPath,      // PEM cert chain file (set exactly one of Path/Pem)
            CertificatePem  = null,          // in-memory PEM alternative to CertificatePath
            KeyPath         = keyPath,       // PEM private key file (set exactly one of Path/Pem)
            KeyPem          = null,          // in-memory PEM alternative to KeyPath
            Alpn            = ["http/1.1"],  // protocols offered, most preferred first
            KernelTx        = false,         // kTLS encrypt (off = OpenSSL both ways)
            KernelRx        = false,         // kTLS decrypt; requires KernelTx, experimental
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
            // The handshake reads and writes through this same connection.
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // A request can ride in with the handshake's final flight - answer it before parking
            // in ReadAsync, or the client waits on a response we never send.
            if (TryReadTarget(tls.DrainPlaintext(), out ReadOnlySpan<byte> early))
            {
                await ProxyAsync(conn, tls, client, Encoding.ASCII.GetString(early));
            }

            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                string? path = null;
                unsafe
                {
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            // Records in, plaintext out - the session decrypts what the ring got.
                            if (TryReadTarget(tls.Decrypt(item.Ptr, item.Len), out ReadOnlySpan<byte> target))
                            {
                                path = Encoding.ASCII.GetString(target);
                            }
                            conn.ReturnBuffer(in item);
                        }
                    }
                }

                if (path is not null)
                {
                    await ProxyAsync(conn, tls, client, path);
                }

                if (snapshot.IsClosed || tls.Closed) return;
                conn.ResetRead();
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[proxy h1->h1] connection failed: {e.Message}");
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

Console.WriteLine($"[proxy h1->h1] {config.ReactorCount} reactors, https on :{config.Tcp!.Port} "
                + $"-> https://{upstreamName} ({upstreamHost}:{upstreamPort}), "
                + $"{upstreamPool} connections each, "
                + $"verify={(upstreamInsecure ? "OFF" : upstreamCa ?? "system store")}");

foreach (Thread thread in threads)
{
    thread.Join();
}

// One request out, one response back. tls.Write encrypts correctly whichever backend the
// session ended up with.
static async ValueTask ProxyAsync(TcpConnection conn, TlsSession tls, HttpClientPool client, string path)
{
    try
    {
        // The outbound call. Same ring, same thread - this await resumes inline. The response
        // owns its bytes, so dispose it when you're done with them.
        using HttpClientResponse response = await client.GetAsync(path);

        tls.Write(conn, Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {response.Status} OK\r\nContent-Length: {response.Body.Length}\r\n\r\n"));
        tls.Write(conn, response.Body.Span);   // bytes straight through, no decode
    }
    catch (Exception e)
    {
        // A dead origin surfaces here rather than hanging: the pool bounds the whole acquire. A
        // REFUSED CERTIFICATE arrives the same way - the handshake is part of opening the
        // connection, so a name mismatch reads like any other upstream failure.
        byte[] message = Encoding.ASCII.GetBytes($"upstream: {e.Message}");
        tls.Write(conn, Encoding.ASCII.GetBytes(
            $"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {message.Length}\r\n\r\n"));
        tls.Write(conn, message);
    }

    await conn.FlushAsync();
}

// "GET /sleep?x=1 HTTP/1.1" -> "/sleep". Your framework of choice would do this for you; ioxide
// deliberately doesn't, so here it is in full.
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
