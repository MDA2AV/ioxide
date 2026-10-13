using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-sslstream - TLS via the BCL's SslStream over TcpConnectionStream: fully managed,
//  portable, full-featured (TLS 1.2/1.3, client certs, resumption), and with no kTLS or native
//  dependency - every byte is encrypted in userspace, which is also why it is the slower path.
//  Run it against Tls.Ktls to see what the kernel offload buys.
//
//      dotnet run -c Release --project Playground/Tls/SslStream
//      curl -ks https://127.0.0.1:8443/ | head -c 40
//
//  TcpConnectionStream adapts the ioxide connection to a Stream, so anything stream-shaped from
//  the BCL slots on top - SslStream is just the most useful example. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 8 * 1024;                    // same body as Tls.Ktls, so the two compare directly

Env.Override(ref port, ref reactors, ref bodyBytes);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);
var certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/* and Quic/Alpn
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

int bodySize = bodyBytes;
byte[] body = new byte[bodySize];
ReadOnlySpan<byte> fill = "ioxide-sslstream-payload "u8;
for (int i = 0; i < bodySize; i++)
{
    body[i] = fill[i % fill.Length];
}
byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {bodySize}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        SslStream? ssl = null;
        try
        {
            // The stream adapter reads from the ring and writes into the slab; SslStream never
            // knows it isn't a NetworkStream.
            ssl = new SslStream(new TcpConnectionStream(conn), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            });

            var request = new byte[8192];
            while (true)
            {
                int n = await ssl.ReadAsync(request);
                if (n == 0) return;                    // peer closed

                await ssl.WriteAsync(response);        // encrypted in userspace
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[tls-sslstream] connection failed: {e.Message}");
        }
        finally
        {
            ssl?.Dispose();
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[tls-sslstream] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{bodySize}-byte body, cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}
