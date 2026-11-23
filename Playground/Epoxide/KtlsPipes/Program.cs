using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using epoxide;
using epoxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  ktls-pipes on epoll - Playground/Tls/KtlsPipes line for line, on epoxide instead of ioxide:
//  full kernel TLS served through an IDuplexPipe, both directions in the kernel (experimental);
//  drop the KernelRx line for the hybrid. Run the two against each other to price epoll against
//  io_uring under kTLS with everything else held equal.
//
//      sudo modprobe tls        # kTLS needs the module
//      dotnet run -c Release --project Playground/Epoxide/KtlsPipes
//      curl -ks https://127.0.0.1:8443/ | head -c 40
//
//  The read/serve loop below is byte-for-byte identical to Playground/Epoxide/TlsPipes - diff them
//  and the only functional difference is the two Kernel* lines, the rest being the banner and the
//  log tag.
//
//  TlsConnectionDualPipe composes rather than implements. Each direction has two possible halves:
//
//              kernel                       BoringSSL
//    read      TcpConnectionPipeReader      TlsDecryptingPipeReader
//              (plaintext is already in     (decrypts into a Pipe
//               the recv buffers)            it owns)
//    write     TcpConnectionPipeWriter      TlsEncryptingPipeWriter
//              (plaintext into the slab,    (SSL_write, then the records
//               kernel makes records)        go into the slab)
//
//  It picks them from the SESSION, not from configuration - TlsOptions is intent, and TlsSession
//  reports what the handshake actually achieved for this connection.
//
//  What epoxide adds: the handler below may move to the thread pool at any point and keep using
//  the pipe there, reader and writer on different threads if it likes - each session serializes
//  its own crypto, so nothing is handed back to the reactor. This one stays on the reactor, like
//  its ioxide twin, so the two measure the same thing. Needs: epoxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. An Env.Override line means the value can also be set from the environment, which is
// how bench/any.sh drives the sample; the literal is what applies otherwise.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one epoll set per reactor, one reactor per core
int    bodyBytes = 8 * 1024;                    // TLS cost is per-byte, so a 2-byte "ok" would hide it

Env.Override(ref port, ref reactors, ref bodyBytes);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
Env.OverrideTlsCert(ref certOverride, ref keyOverride);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // epoll sets/threads - one per core
    MaxEvents      = 1024,                                 // events one epoll_wait takes in
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per pooled recv buffer
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored sendmsg
        RecvQueueEntries = 64,                             // per-connection recv queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // PEM chain file (or CertificatePem for in-memory)
    KeyPath         = keyPath,                             // PEM key file (or KeyPem for in-memory)
    Alpn            = ["http/1.1"],                        // protocols this port serves, most-preferred first

    // NOT the default - TLS is BoringSSL both ways unless you ask for this.
    // Playground/Epoxide/TlsPipes is the same server without these two lines.
    KernelTx        = true,

    // Full kTLS: the kernel decrypts inbound too, and recv hands back plaintext. Experimental -
    // a KeyUpdate from the client ends the connection. Drop this line for the hybrid.
    KernelRx        = true,
};

byte[] body = new byte[bodyBytes];
"epoxide-tls-pipes "u8.CopyTo(body);
for (int i = "epoxide-tls-pipes "u8.Length; i < bodyBytes; i++)
{
    body[i] = (byte)('a' + (i % 26));
}

byte[] response =
[
    .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {bodyBytes}\r\n\r\n"),
    .. body,
];

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
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // From here down, nothing knows or cares which backend is in use.
            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();

                // Answer per REQUEST, not per read. TLS hands back RECORDS, so one request split
                // across two records would otherwise draw two responses.
                int answered = 0;
                SequencePosition consumed = read.Buffer.Start;

                var reader = new SequenceReader<byte>(read.Buffer);
                while (reader.TryReadTo(out ReadOnlySequence<byte> _, "\r\n\r\n"u8, advancePastDelimiter: true))
                {
                    consumed = reader.Position;
                    answered++;
                }

                // Consumed only whole requests; examined everything, so a partial head parks
                // until more arrives instead of spinning on the same bytes.
                pipe.Input.AdvanceTo(consumed, read.Buffer.End);

                for (int n = 0; n < answered; n++)
                {
                    pipe.Output.Write(response);
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
        catch (Exception e)
        {
            Console.Error.WriteLine($"[epoxide-ktls-pipes] connection failed: {e.Message}");
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

Console.WriteLine($"[epoxide-ktls-pipes] {config.ReactorCount} reactors on :{config.Tcp.Port}, "
                + $"{bodyBytes}-byte body, tx=kernel, rx=kernel (experimental)");

foreach (Thread thread in threads)
{
    thread.Join();
}
