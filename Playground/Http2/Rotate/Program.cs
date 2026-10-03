using ioxide;
using ioxide.http2;
using ioxide.tls;
using Playground.Shared;
using System.Runtime.InteropServices;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http2-rotate - replacing a certificate on a running server, without dropping a connection.
//  What renewal needs: an ACME client rewrites the PEM every couple of months, and the only
//  alternative to this is a restart.
//
//      dotnet run -c Release --project Playground/Http2/Rotate
//      kill -HUP <the pid it prints>                  # rotate now
//      kill -HUP $(pgrep -f Playground.Http2.Rotate)   # ...or find it yourself
//
//  It also rotates on its own every few seconds (see the knob) so a plain `dotnet run` shows the
//  thing happening. It alternates between two certificates for the same names, because a rotation
//  you cannot pin from outside is a rotation you have to take on trust:
//
//      curl -s --http2 --cacert /tmp/ioxide-playground-quic/sni-alpha_test.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//      curl -s --http2 --cacert /tmp/ioxide-playground-quic/sni-alpha_test-renewed.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//
//  Each is self-signed, so exactly one of those two succeeds at any moment, and which one flips
//  every rotation. The server prints the file it just published; run the matching curl.
//
//  Three things about ReplaceCertificates are worth knowing before automating it:
//
//  1. It replaces the WHOLE set, table included. Passing only the default is not "keep the names
//     and renew the default" - it is a server that answers every name with the default
//     certificate, which looks like it is working and is serving the wrong certificate. Pass the
//     names you want to keep. That is why `byHost` is rebuilt below on every rotation.
//
//  2. A TlsService belongs to ONE reactor, so a server with N reactors has N of them and every
//     one has to be rotated. They all listen on the same port through SO_REUSEPORT, so a reactor
//     that is missed serves the old certificate on its share of the connections - and which
//     reactor a client lands on is not something the client chooses. There is no instant at which
//     all N flip together; for a few microseconds two clients can get different certificates.
//     Both are valid certificates for the name, which is what makes that survivable.
//
//  3. It builds everything before publishing anything. A half-written PEM - an ACME hook caught
//     mid-write is the normal way to meet one - throws, and LEAVES THE SERVICE SERVING WHAT IT
//     WAS. A failed renewal is a server that kept working, so catch and log, and do not treat a
//     throw as a reason to stop.
//
//  Connections already up are untouched: the certificate was chosen during their handshake and
//  nothing re-reads it, so a rotation is invisible to them. Only NEW handshakes see the new set.
//  This is also why the old contexts are kept rather than freed - a handshake may be between
//  reading the set and using it. A few rotations a year costs kilobytes.
//
//  One thing does follow the disk, and it is a foot-gun: client trust anchors given as
//  TlsOptions.ClientCaPath are RE-READ from that path on every rotation. Editing the CA bundle
//  then takes effect at the next renewal rather than the next restart - which is how you revoke
//  an issuer without a restart, and how you widen who may connect without meaning to. Anchors
//  given as ClientCaPem are data and do not move.
//
//  For the QUIC side, where one shared engine covers every reactor and a single call is the whole
//  rotation, see Http3/Rotate. Needs: ioxide, ioxide.http2
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port     = 8443;                        // https://127.0.0.1:8443/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// Seconds between automatic rotations, so the sample shows its own feature. 0 = only on SIGHUP,
// which is the shape a real deployment has: the ACME hook writes the PEM, then signals.
int rotateEverySeconds = 10;

Env.Override(ref rotateEverySeconds, "PLAYGROUND_ROTATE_SECONDS");

// The names this port answers for, beside the default. Every one of them rotates.
string[] hosts = ["alpha.test", "beta.test"];
// ─────────────────────────────────────────────────────────────────────────────────────────────

// Two generations of the same identity: same subject, same SAN, different key and serial. This is
// what a renewal produces. The originals are what the server starts on.
(string certPath, string keyPath) = QuicCert.Ensure(null, null);
(string renewedCert, string renewedKey) = QuicCert.EnsureRenewed("localhost");

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/Rotate for that side
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
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

// The two sets, resolved once. Each is a whole generation - the default certificate and every
// name - and a rotation swaps one for the other. Only the PATHS are held here: ReplaceCertificates
// re-reads the files, which is what makes "same path, new contents" the normal ACME shape.
var originalTable = new Dictionary<string, TlsCertificate>();
var renewedTable = new Dictionary<string, TlsCertificate>();

foreach (string host in hosts)
{
    (string hostCert, string hostKey) = QuicCert.EnsureNamed(host);
    (string hostRenewedCert, string hostRenewedKey) = QuicCert.EnsureRenewed(host);

    originalTable[host] = new TlsCertificate { CertificatePath = hostCert, KeyPath = hostKey };
    renewedTable[host] = new TlsCertificate { CertificatePath = hostRenewedCert, KeyPath = hostRenewedKey };
}

var tlsOptions = new TlsOptions
{
    CertificatePath    = certPath,                         // the DEFAULT: no name asked for, or a name not in the table
    KeyPath            = keyPath,
    Alpn               = ["h2"],                           // what a rotation may NOT change - see below
    CertificatesByHost = originalTable,
    KernelTx           = false,                            // kernel TLS transmit - see Tls/Ktls
    KernelRx           = false,                            // kTLS receive (experimental; requires KernelTx)
};

// One service per reactor, each published by that reactor as it starts. Rotation reads this array
// from another thread, so the writes are volatile and a slot that is still null is simply skipped:
// a reactor that has not started yet has not served a handshake either.
var services = new TlsService?[config.ReactorCount];

int generation = 0;
object rotationGate = new();

void Rotate(string trigger)
{
    // SIGHUP and the timer can land together, and the pair of "which generation" and "publish it"
    // has to be atomic between them. ReplaceCertificates takes its own lock; this one is about
    // the decision, not the publish.
    lock (rotationGate)
    {
        int next = Interlocked.Increment(ref generation);
        bool renewed = next % 2 == 1;

        var certificate = renewed
            ? new TlsCertificate { CertificatePath = renewedCert, KeyPath = renewedKey }
            : new TlsCertificate { CertificatePath = certPath, KeyPath = keyPath };

        Dictionary<string, TlsCertificate> table = renewed ? renewedTable : originalTable;
        int rotated = 0;

        for (int i = 0; i < services.Length; i++)
        {
            TlsService? service = Volatile.Read(ref services[i]);
            if (service is null)
            {
                continue;   // that reactor has not started; it will start on the current set
            }

            try
            {
                // The whole set, every time. Handing this the default alone would empty the table.
                service.ReplaceCertificates(certificate, table);
                rotated++;
            }
            catch (Exception e)
            {
                // This reactor kept the certificates it had, and is still serving. Say so and
                // carry on - a renewal that half-failed must not take the server with it.
                Console.Error.WriteLine($"[http2-rotate] reactor {i} kept its certificates: {e.Message}");
            }
        }

        Console.WriteLine($"[http2-rotate] generation {next} ({trigger}): {rotated}/{services.Length} reactors "
                        + $"now serving {(renewed ? "renewed" : "original")} - pin "
                        + $"{table[hosts[0]].CertificatePath}");
    }
}

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    int id = i;
    var reactor = new Reactor(i, config);

    reactor.OnStart = r => Volatile.Write(ref services[id], TlsService.Start(r, tlsOptions));

    reactor.TcpHandle = async (r, conn) =>
    {
        TlsSession? tls = null;

        try
        {
            // Whichever generation is published at this instant. A connection that is already up
            // keeps what it handshook with.
            tls = await r.GetService<TlsService>()!.AcceptAsync(conn);

            await using var pipe = new TlsConnectionDualPipe(conn, tls, ownsSession: false);

            await new Http2Connection(pipe).RunBufferedAsync(_ =>
            {
                // What the SERVER believes it published. The client's view is the certificate it
                // just validated, and only pinning with --cacert can tell you that.
                int served = Volatile.Read(ref generation);
                return Http2Response.Text($"generation {served} ({(served % 2 == 1 ? "renewed" : "original")})\n");
            });
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[http2-rotate] connection failed: {e.Message}");
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

// SIGHUP is what an ACME hook sends after writing the PEM. Cancel = true keeps the default action
// - terminating the process - from running after the handler.
using var sighup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, context =>
{
    context.Cancel = true;
    Rotate("SIGHUP");
});

using var timer = rotateEverySeconds > 0
    ? new Timer(_ => Rotate("timer"), null, rotateEverySeconds * 1000, rotateEverySeconds * 1000)
    : null;

Console.WriteLine($"[http2-rotate] pid {Environment.ProcessId}, {config.ReactorCount} reactors on :{port}, ALPN h2, "
                + $"default + {string.Join(", ", hosts)}, "
                + $"rotating {(rotateEverySeconds > 0 ? $"every {rotateEverySeconds}s and " : "")}on SIGHUP");

foreach (Thread thread in threads)
{
    thread.Join();
}
