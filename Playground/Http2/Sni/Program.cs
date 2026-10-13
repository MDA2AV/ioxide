using ioxide;
using ioxide.http2;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-sni - one port, several hosts, a different certificate for each, with HTTP/2 above it.
//  The client says which host it wants in the TLS handshake (Server Name Indication) and the
//  server answers with that host's certificate, before a single HTTP/2 frame exists.
//
//      dotnet run -c Release --project Playground/Http2/Sni
//      curl -k --http2 --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//      curl -k --http2 --resolve beta.test:8443:127.0.0.1  https://beta.test:8443/
//
//  --resolve is how you reach a name with no DNS entry: curl sends "alpha.test" as the name it
//  wants but connects to 127.0.0.1. To see WHICH certificate came back, drop the -k and hand curl
//  the one you expect:
//
//      curl -s --http2 --cacert /tmp/ioxide-playground-quic/sni-alpha_test.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//
//  That succeeds for alpha.test and fails for beta.test, which is the feature working. The
//  response body cannot tell you this - it reports the name the REQUEST carried, and those are
//  two different names at two different layers.
//
//  Which is the thing worth taking from this sample. Two independent choices happen here:
//
//      SNI, in the handshake  -> which CERTIFICATE this connection is served
//      :authority, per request -> which SITE the request is for
//
//  Nothing makes them agree. A client is free to open one connection to alpha.test and send
//  requests for beta.test on it - HTTP/2 reuses a connection for any origin the certificate
//  covers, and that is legal. So authorization belongs on :authority, which is per request, and
//  never on the name that picked the certificate.
//
//  HTTP/1.1 rides this exact path: TCP, then TLS, then a protocol. ALPN below is the whole
//  difference, and Tls/Sni is the same feature with a hand-rolled h1 loop instead of this one.
//  For the QUIC side of SNI - where TLS is inside the transport rather than layered on it - see
//  Http3/Sni. Needs: ioxide, ioxide.http2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port     = 8443;                        // https://127.0.0.1:8443/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// A real PEM pair for the DEFAULT certificate, or null to generate a self-signed localhost one.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);

// The names this port answers for, beside the default. Add a line and it is served.
string[] hosts = ["alpha.test", "beta.test"];
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var byHost = new Dictionary<string, TlsCertificate>();
foreach (string host in hosts)
{
    (string hostCert, string hostKey) = QuicCert.EnsureNamed(host);
    byHost[host] = new TlsCertificate { CertificatePath = hostCert, KeyPath = hostKey };
}

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/Sni for that side
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                          // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 64,                             // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // the DEFAULT: no name asked for, or a name not below
    KeyPath         = keyPath,
    Alpn            = ["h2"],                              // h2 only here; add "http/1.1" to serve both, as Http2/Tls does

    // The table. One entry per host name, and the certificate to answer it with; an entry may
    // give PEM text instead of paths (CertificatePem/KeyPem) for material kept off the filesystem.
    // Two entries for the same name, in any casing, are refused at startup rather than one of them
    // silently never being served. Names are ASCII host names in full - SNI carries no port, an IP
    // address is not a legal value, and an international name belongs here in its xn-- form.
    CertificatesByHost = byHost,

    KernelTx = false,                                      // kernel TLS transmit - see Tls/Ktls
    KernelRx = false,                                      // kTLS receive (experimental; requires KernelTx)
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // One TlsService per reactor. It owns the contexts - the default and one per name - and picks
    // between them during each handshake on this ring. Each entry costs one OpenSSL context, built
    // once at startup; choosing one per handshake is a lookup that allocates nothing, so serving
    // ten names costs what serving one does.
    reactor.OnStart = r => TlsService.Start(r, tlsOptions);

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;

        try
        {
            // The certificate is chosen inside this call, from the name the client sent. Nothing
            // after it changes: the HTTP/2 code below is what the h2c sample runs.
            tls = await r.GetService<TlsService>()!.AcceptAsync(conn);

            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

            await new Http2Connection(pipe).RunBufferedAsync(request =>
            {
                // :authority is HTTP/2's Host header, and this is where site routing belongs -
                // per request, not per connection. It is NOT proof of which certificate was
                // served; pin one with --cacert for that.
                string authority = System.Text.Encoding.ASCII.GetString(request.Authority.Span);

                return Http2Response.Text(authority.Length == 0
                    ? "no :authority\n"
                    : $"site: {authority}\n");
            });
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[http2-sni] connection failed: {e.Message}");
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

Console.WriteLine($"[http2-sni] {config.ReactorCount} reactors on :{port}, ALPN h2, "
                + $"default {certPath} + {string.Join(", ", hosts)}");

foreach (Thread thread in threads)
{
    thread.Join();
}
