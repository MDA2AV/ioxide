using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-openssl-pipes - TLS served through an IDuplexPipe, with OpenSSL doing the crypto in userspace.
//
//      dotnet run -c Release --project Playground/Tls/OpenSslPipes   # NO modprobe needed
//      curl -ks https://127.0.0.1:8443/ | head -c 40
//
//  The read/serve loop below is byte-for-byte identical to Playground/Tls/KtlsPipes - diff them
//  and the only functional difference is the KernelTx line, the rest being the banner and the
//  log tag.
//
//  TlsConnectionDualPipe composes rather than implements. Each direction has two possible halves:
//
//              kernel                       OpenSSL
//    read      TcpConnectionPipeReader      TlsDecryptingPipeReader
//              (plaintext is already in     (decrypts into a Pipe
//               ring memory - zero copy)     it owns)
//    write     TcpConnectionPipeWriter      TlsEncryptingPipeWriter
//              (plaintext into the slab,    (SSL_write, then the records
//               kernel makes records)        go into the slab)
//
//  It picks them from the SESSION, not from configuration - because the two are not the same
//  thing. TlsOptions is intent; TlsService decides per connection at the handoff, and a handshake
//  that left a partial record cannot hand off to kTLS RX at all, so that connection keeps the
//  userspace reader whatever the config said. TlsSession reports what actually happened.
//
//  Compare the raw-ring pair, Playground/Tls/Ktls and Playground/Tls/OpenSsl. Those two DO differ
//  in the handler, because at that level the backend is visible: kTLS writes plaintext straight to
//  the connection, OpenSSL goes through TlsSession.Write. Over a pipe it is not. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete that line
// when you copy this out and the literals above it are the entire configuration.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 8 * 1024;                    // TLS cost is per-byte, so a 2-byte "ok" would hide it

Env.Override(ref port, ref reactors, ref bodyBytes);

// A real PEM pair, or null to generate a self-signed localhost cert on first run.
string? certOverride = null;
string? keyOverride  = null;
// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor. The
// handler code is identical either way; this only changes how recv buffers are handed out.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = incrementalBuffers ? new IncrementalOptions { MaxConnections = 1024, RecvSlots = 8, RecvBufferSize = 16 * 1024 } : null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
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

var tlsOptions = new TlsOptions
{
    CertificatePath = certPath,                            // PEM chain file (or CertificatePem for in-memory)
    KeyPath         = keyPath,                             // PEM key file (or KeyPem for in-memory)
    Alpn            = ["http/1.1"],                        // protocols this port serves, most-preferred first

    // KernelTx stays false (the default). No TLS ULP on the socket, so OpenSSL encrypts and
    // decrypts and nothing here needs the 'tls' kernel module - which also keeps TLS 1.2, any
    // ciphersuite and session resumption. Playground/Tls/KtlsPipes adds the one line that
    // changes this.
    KernelTx        = false,
    KernelRx        = false,                               // kTLS receive (experimental; requires KernelTx)
};

byte[] body = new byte[bodyBytes];
"ioxide-tls-pipes "u8.CopyTo(body);
for (int i = "ioxide-tls-pipes "u8.Length; i < bodyBytes; i++)
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
            Console.Error.WriteLine($"[tls-openssl-pipes] connection failed: {e.Message}");
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

Console.WriteLine($"[tls-openssl-pipes] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"{bodyBytes}-byte body, tx={(tlsOptions.KernelTx ? "kernel" : "openssl")}");

foreach (Thread thread in threads)
{
    thread.Join();
}
