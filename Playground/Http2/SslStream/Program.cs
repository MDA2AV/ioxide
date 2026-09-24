using System.IO.Pipelines;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using ioxide;
using ioxide.http2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-sslstream - HTTP/2 over the BCL's SslStream instead of ioxide's own termination. Fully
//  managed, portable, and slower - the bytes cross a Stream both ways.
//
//      dotnet run -c Release --project Playground/Http2/SslStream
//      curl -k --http2 https://127.0.0.1:8443/
//
//  The point of this sample is what it demonstrates about the shape: Http2Connection takes an
//  IDuplexPipe, and a Stream can be one in about ten lines (below). So the same HTTP/2 code runs
//  over the ring directly, over kTLS, or over SslStream, without knowing which - the transport is
//  a constructor argument, not a branch inside the protocol.
//
//  Compare with Playground/Http2/Tls for the ioxide.tls version. Needs: ioxide, ioxide.http2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port     = 8443;                        // https://127.0.0.1:8443/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);
var certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);
certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);

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
    },
};

byte[] body = "ok"u8.ToArray();
var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        SslStream? ssl = null;
        try
        {
            ssl = new SslStream(new TcpConnectionStream(conn), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,

                // Same ordered preference as the kTLS sample: h2 wins when the client offers both.
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            });

            if (ssl.NegotiatedApplicationProtocol != SslApplicationProtocol.Http2)
            {
                return;   // this sample only serves h2; see Playground/Http2/Tls for the fallback
            }

            await new Http2Connection(new StreamDuplexPipe(ssl)).RunBufferedAsync(
                _ => new Http2Response { Status = 200, Body = body });
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[http2-sslstream] connection failed: {e.Message}");
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

Console.WriteLine($"[http2-sslstream] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"h2 over SslStream (userspace both ways), cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}

/// <summary>
/// Any Stream as an IDuplexPipe. The BCL already has the two halves - this only pairs them, which
/// is the whole adapter needed to run ioxide's HTTP/2 over something that is not a ring connection.
/// </summary>
internal sealed class StreamDuplexPipe(Stream stream) : IDuplexPipe
{
    public PipeReader Input { get; } = PipeReader.Create(stream, new StreamPipeReaderOptions(leaveOpen: true));
    public PipeWriter Output { get; } = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
}
