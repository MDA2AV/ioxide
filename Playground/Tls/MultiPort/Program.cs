using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-multiport - one server, two doors: plaintext on :8080, TLS on :8081, and ONE serve loop
//  for both. The TLS door terminates with the default backend (OpenSSL both ways, no kernel
//  module) and serves through a TlsConnectionDualPipe; the plaintext door pairs the connection's
//  own pipe halves. The loop reads an IDuplexPipe and cannot tell which door it got - that is
//  the point.
//
//      dotnet run -c Release --project Playground/Tls/MultiPort
//      curl  http://127.0.0.1:8080/
//      curl -ks https://127.0.0.1:8081/
//
//  A self-signed localhost cert is generated on first run. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/  - the plaintext door
ushort tlsPort  = 8081;                        // https://127.0.0.1:8081/ - the TLS door
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

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
        ExtraPorts       = [tlsPort],                      // every reactor listens on both; ListenerPort says which one accepted
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                          // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 4096,                           // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

// Default backend: OpenSSL in both directions. Only connections on the TLS door go near this.
var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // PEM chain file (or CertificatePem for in-memory)
    KeyPath         = keyPath,                             // PEM key file (or KeyPem for in-memory)
    Alpn            = ["http/1.1"],                        // protocols this port serves, most-preferred first
    KernelTx        = false,                               // kTLS transmit offload (kernel makes the records)
    KernelRx        = false,                               // kTLS receive (experimental; requires KernelTx)
};

const string bodyText = "multiport-ok\n";
byte[] response = Encoding.ASCII.GetBytes(
    $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {bodyText.Length}\r\n\r\n{bodyText}");

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.OnStart = r => TlsService.Start(r, tlsOptions);

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;
        try
        {
            // Which door? This branch is the entire difference between the two.
            if (conn.ListenerPort == tlsPort)
            {
                tls = await r.GetService<TlsService>().AcceptAsync(conn);
                await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);
                await ServeAsync(pipe, response);
            }
            else
            {
                var pipe = new PlainPipe(new TcpConnectionPipeReader(conn), new TcpConnectionPipeWriter(conn));
                try
                {
                    await ServeAsync(pipe, response);
                }
                finally
                {
                    pipe.Input.Complete();
                    pipe.Output.Complete();
                }
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[tls-multiport] connection failed: {e.Message}");
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

Console.WriteLine($"[tls-multiport] {config.ReactorCount} reactors, "
                + $"plaintext :{config.Tcp!.Port}, tls :{tlsPort} (openssl both ways), cert {certPath}");

foreach (Thread thread in threads)
{
    thread.Join();
}

// One loop for both doors. It reads an IDuplexPipe and nothing else - whether the bytes were
// decrypted on the way in, or will be encrypted on the way out, is not visible from here.
static async Task ServeAsync(IDuplexPipe pipe, ReadOnlyMemory<byte> response)
{
    while (true)
    {
        ReadResult read = await pipe.Input.ReadAsync();

        // Answer per REQUEST, not per read - a request split across reads must not draw two
        // responses, and two requests in one read must not draw one.
        int answered = 0;
        SequencePosition consumed = read.Buffer.Start;

        var reader = new SequenceReader<byte>(read.Buffer);
        while (reader.TryReadTo(out ReadOnlySequence<byte> _, "\r\n\r\n"u8, advancePastDelimiter: true))
        {
            consumed = reader.Position;
            answered++;
        }

        // Consumed only whole requests; examined everything, so a partial head parks until more
        // arrives instead of spinning on the same bytes.
        pipe.Input.AdvanceTo(consumed, read.Buffer.End);

        for (int n = 0; n < answered; n++)
        {
            pipe.Output.Write(response.Span);
        }

        if (answered > 0)
        {
            await pipe.Output.FlushAsync();
        }

        if (read.IsCompleted || read.IsCanceled)
        {
            return;
        }
    }
}

// The plaintext door's IDuplexPipe: the connection's own reader and writer, paired.
sealed record PlainPipe(PipeReader Input, PipeWriter Output) : IDuplexPipe;
