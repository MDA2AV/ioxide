using System.Text;
using ioxide;
using ioxide.tls;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-sni - one port, several hosts, a different certificate for each. The client says which
//  host it wants in the TLS handshake (Server Name Indication) and the server answers with that
//  host's certificate.
//
//      dotnet run -c Release --project Playground/Tls/Sni
//      curl -ks --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//      curl -ks --resolve beta.test:8443:127.0.0.1  https://beta.test:8443/
//
//  --resolve is how you reach a name that has no DNS entry: curl sends "alpha.test" as the name
//  it wants but connects to 127.0.0.1. To see WHICH certificate came back, drop the -k and point
//  curl at the certificate you expect:
//
//      curl -s --cacert /tmp/ioxide-playground-quic/sni-alpha_test.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//
//  That succeeds for alpha.test and fails for beta.test, which is the whole feature working.
//
//  The certificate below stays the DEFAULT. A client that sends no name - anything connecting by
//  IP address - or asks for a name that is not in the table gets it, rather than being refused.
//  A server that aborted instead could not be reached by address at all, and the client would see
//  a dead connection rather than a certificate it can reason about.
//
//  Names are matched case-insensitively and in full. A wildcard certificate still covers its own
//  names, but it does so through the certificate, not through this table - register the exact
//  names you want to answer for. Keys are ASCII host names only: SNI carries no port, an IP
//  address is not a legal value, and an international name belongs here in its xn-- form.
//
//  Each entry costs one OpenSSL context, built once at startup. Choosing one per handshake is a
//  lookup on the reactor thread and allocates nothing, so the cost of serving ten names is the
//  same as serving one.
//
//  PLAYGROUND_TLS_CERT/_KEY point at a real PEM pair for the default; otherwise a self-signed
//  localhost cert is generated, and the per-host certificates alongside it. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 8 * 1024;                    // response size

Env.Override(ref port, ref reactors, ref bodyBytes);

// A real PEM pair for the DEFAULT certificate, or null to generate a self-signed localhost one.
string? certOverride = null;
string? keyOverride  = null;

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
    Quic           = null,                                 // no QUIC transport - see Http3/Sni for the QUIC side
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
    Alpn            = ["http/1.1"],                        // protocols this port serves, most-preferred first

    // The table. Each entry is one host name and the certificate to answer it with; a host may
    // give PEM text instead of paths (CertificatePem/KeyPem) for material kept out of the
    // filesystem. Two entries for the same name, in any casing, are refused at startup rather
    // than one of them silently never being served.
    CertificatesByHost = byHost,

    KernelTx        = false,                               // kernel TLS transmit - see Tls/Ktls
    KernelRx        = false,                               // kTLS receive (experimental; requires KernelTx)
};

byte[] body = new byte[bodyBytes];
ReadOnlySpan<byte> fill = "ioxide-sni-payload "u8;
for (int i = 0; i < bodyBytes; i++)
{
    body[i] = fill[i % fill.Length];
}
byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {bodyBytes}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    // One TlsService per reactor: it owns the contexts - the default and one per name - and drives
    // handshakes on this ring.
    reactor.OnStart = r => TlsService.Start(r, tlsOptions);

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;

        try
        {
            // The certificate is chosen inside this handshake, from the name the client sent.
            // Nothing after it changes: the session reads and writes the same either way.
            tls = await r.GetService<TlsService>()!.AcceptAsync(conn);

            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }

                tls.Write(conn, response);
                await conn.FlushAsync();
                conn.ResetRead();
            }
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { IsBackground = false, Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"tls-sni on https://127.0.0.1:{port}/  default + {string.Join(", ", hosts)}");

foreach (Thread t in threads)
{
    t.Join();
}
