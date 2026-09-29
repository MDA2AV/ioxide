using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.tls;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  tls-mtls-openssl-pipes - TLS where the CLIENT proves who it is too, served through an
//  IDuplexPipe, with OpenSSL doing the crypto in userspace.
//
//      PLAYGROUND_CLIENT_CA=ca.crt dotnet run -c Release --project Playground/Tls/MtlsOpenSslPipes
//      curl -k --cert client.crt --key client.key https://127.0.0.1:8443/
//      curl -k https://127.0.0.1:8443/          # no certificate: answered as anonymous
//
//  Make a CA and a certificate it signs:
//
//      openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 \
//        -subj "/CN=my CA" -addext "basicConstraints=critical,CA:TRUE"
//      openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=alice"
//      printf 'extendedKeyUsage=clientAuth\n' > c.cnf
//      openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
//        -out client.crt -days 365 -extfile c.cnf
//
//  ClientCaPath is what turns this on. Leave it null and nothing is requested - the handshake is
//  exactly the one Playground/Tls/OpenSslPipes performs.
//
//  RequireClientCertificate is the interesting knob. OFF (the default) is the mixed port: anyone
//  connects, and the HANDLER decides what an unauthenticated peer may reach, which is why
//  TlsSession.PeerSubject exists. ON refuses at the handshake, before a byte of request is read -
//  cheaper, and blunter: there is no public route left.
//
//  Either way a certificate that IS offered gets verified. "Optional" governs presenting nothing,
//  not presenting anything.
//
//  Playground/Tls/MtlsKtlsPipes is this file with KernelTx = true. The client half of the same
//  handshake is Playground/Clients/Https. Needs: ioxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port      = 8443;                        // https://127.0.0.1:8443/
int    reactors  = Environment.ProcessorCount;  // one ring per reactor, one reactor per core
int    bodyBytes = 8 * 1024;                    // TLS cost is per-byte, so a 2-byte "ok" would hide it

Env.Override(ref port, ref reactors, ref bodyBytes);

// The server's own certificate and key. Null generates a self-signed pair on first run.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);

// The CA that CLIENT certificates are checked against - the switch that turns mTLS on.
string? clientCaPath = Environment.GetEnvironmentVariable("PLAYGROUND_CLIENT_CA");

// Refuse a client offering no certificate, during the handshake. Off by default: see the header.
bool requireClientCertificate = Environment.GetEnvironmentVariable("PLAYGROUND_REQUIRE_CLIENT_CERT") == "1";

// Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring per reactor.
bool incrementalBuffers = false;

Env.OverrideIncremental(ref incrementalBuffers);
// ─────────────────────────────────────────────────────────────────────────────────────────────

if (clientCaPath is null)
{
    Console.Error.WriteLine(
        "set PLAYGROUND_CLIENT_CA to a PEM bundle of the CA that signs your client certificates.");
    return 1;
}

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = incrementalBuffers ? new IncrementalOptions { MaxConnections = 1024, RecvSlots = 8, RecvBufferSize = 16 * 1024 } : null,
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/*
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

    ClientCaPath    = clientCaPath,                        // trust anchors for CLIENT certificates (or ClientCaPem)
    RequireClientCertificate = requireClientCertificate,   // refuse a client with none, at the handshake

    // KernelTx stays false (the default). OpenSSL encrypts and decrypts, so nothing here needs the
    // 'tls' kernel module. Client verification is unaffected by that choice either way - the
    // certificate is exchanged during the handshake, which OpenSSL always performs.
    KernelTx        = false,
    KernelRx        = false,                               // kTLS receive (experimental; requires KernelTx)
};

byte[] body = new byte[bodyBytes];
"ioxide-mtls "u8.CopyTo(body);
for (int i = "ioxide-mtls "u8.Length; i < bodyBytes; i++)
{
    body[i] = (byte)('a' + (i % 26));
}

// What an unauthenticated peer gets. Only reachable with RequireClientCertificate off - with it on
// that client never completed a handshake, so nothing here ever runs for it.
const string denied = "client certificate required";
byte[] forbidden = Encoding.ASCII.GetBytes(
    $"HTTP/1.1 403 Forbidden\r\nContent-Length: {denied.Length}\r\n\r\n{denied}");

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

            // Who connected. Null means the peer offered no certificate, which only happens when
            // RequireClientCertificate is off - a certificate that failed to verify never reaches
            // here, because that fails the handshake.
            //
            // This is the whole point of the feature: enforcing an identity is half of it, and a
            // server that can only enforce cannot authorise.
            byte[] response = tls.PeerSubject is { } subject
                ? [.. Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Length: {bodyBytes}\r\nX-Client: {subject}\r\n\r\n"),
                   .. body]
                : forbidden;

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
                    // The identity is a property of the CONNECTION, so it is the same for every
                    // request on it - decided once, above the loop, not per request.
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
            Console.Error.WriteLine($"[tls-mtls-openssl-pipes] connection failed: {e.Message}");
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

Console.WriteLine($"[tls-mtls-openssl-pipes] {config.ReactorCount} reactors on :{config.Tcp!.Port}, "
                + $"client CA {clientCaPath}, "
                + $"{(requireClientCertificate ? "certificate REQUIRED" : "certificate optional")}, tx=openssl");

foreach (Thread thread in threads)
{
    thread.Join();
}

return 0;
