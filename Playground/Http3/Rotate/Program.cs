using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using Playground.Shared;
using System.Runtime.InteropServices;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http3-rotate - replacing a certificate on a running QUIC server, without dropping a
//  connection. The same operational need as Http2/Rotate - an ACME client rewrites the PEM every
//  couple of months - on the stack where TLS lives INSIDE the transport rather than on top of it.
//
//      dotnet run -c Release --project Playground/Http3/Rotate
//      kill -HUP <the pid it prints>                  # rotate now
//      kill -HUP $(pgrep -f Playground.Http3.Rotate)   # ...or find it yourself
//
//  It also rotates on its own every few seconds (see the knob), alternating between two
//  certificates for the same names so the change is provable from outside:
//
//      curl --http3-only -s --cacert /tmp/ioxide-playground-quic/sni-alpha_test.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//      curl --http3-only -s --cacert /tmp/ioxide-playground-quic/sni-alpha_test-renewed.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//
//  Each is self-signed, so exactly one of the two succeeds at any moment and which one flips
//  every rotation. Needs a curl built with HTTP/3 - a stock one has no --http3-only.
//
//  The difference from the TCP side is the one thing to take from this sample. On TCP each
//  reactor owns its own TlsService and a rotation has to visit every one of them, with no instant
//  at which they all flip. Here there is ONE QuicEngine shared by every reactor, so a rotation is
//  a single call: one store publishes the new set, and a handshake on any reactor sees either
//  every old certificate or every new one. Never a mixture, and nothing to loop over.
//
//  What carries over unchanged:
//
//  1. It replaces the WHOLE set, table included - and here the engine REFUSES to let you get that
//     wrong. Omitting the table on an engine that answers for names throws, because the obvious
//     renewal hook (rotate the default, forget the rest) published an empty table and every named
//     host was quietly answered with the default certificate. Pass the names to keep them, or an
//     empty dictionary to mean it.
//
//  2. Nothing is published unless all of it built, so a half-written PEM throws and LEAVES THE
//     ENGINE SERVING WHAT IT WAS. Catch and log; a failed renewal is a server that kept working.
//
//  3. Live connections are untouched - their certificate was chosen during the handshake - and
//     the old set is kept rather than freed, because picotls keeps reading the context for as
//     long as a connection lives and does not refcount it. It is released when the engine is
//     disposed.
//
//  What a rotation may NOT change, on either stack: the client trust anchors and whether a client
//  certificate is required. Renewing a certificate cannot quietly change who is allowed to
//  connect. Note that this is STRICTER than the TCP side, where anchors given as a path are
//  re-read from disk on every rotation.
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.http3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ over QUIC
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.OverrideQuic(ref quicPort, ref reactors);

// Seconds between automatic rotations, so the sample shows its own feature. 0 = only on SIGHUP,
// which is the shape a real deployment has: the ACME hook writes the PEM, then signals.
int rotateEverySeconds = 10;

Env.Override(ref rotateEverySeconds, "PLAYGROUND_ROTATE_SECONDS");

// The names this port answers for, beside the default. Every one of them rotates.
string[] hosts = ["alpha.test", "beta.test"];

// UDP receive slots per reactor: how many datagrams the ring can have outstanding at once.
int udpRecvSlots = 16;
// ─────────────────────────────────────────────────────────────────────────────────────────────

// Two generations of the same identity: same subject, same SAN, different key and serial. This is
// what a renewal produces. The originals are what the server starts on.
(string certPath, string keyPath) = QuicCert.Ensure(null, null);
(string renewedCert, string renewedKey) = QuicCert.EnsureRenewed("localhost");

// ONE engine, shared by every reactor - this is the whole difference from Http2/Rotate.
using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

// Names are registered before CreateFactory, as they must be: once the engine is serving, AddHost
// refuses. Rotation is the supported way to change the table afterwards, and it replaces rather
// than edits, which is why it can be safe while AddHost cannot.
var originalTable = new Dictionary<string, QuicCertificate>();
var renewedTable = new Dictionary<string, QuicCertificate>();

foreach (string host in hosts)
{
    (string hostCert, string hostKey) = QuicCert.EnsureNamed(host);
    (string hostRenewedCert, string hostRenewedKey) = QuicCert.EnsureRenewed(host);

    engine.AddHost(host, hostCert, hostKey);

    // The two sets, resolved once. Only the PATHS are held: ReplaceCertificates re-reads the
    // files, which is what makes "same path, new contents" the normal ACME shape.
    originalTable[host] = new QuicCertificate(hostCert, hostKey);
    renewedTable[host] = new QuicCertificate(hostRenewedCert, hostRenewedKey);
}

var config = new ServerConfig
{
    ReactorCount = reactors,
    Tcp = null,                                        // QUIC only
    Udp = new UdpOptions { RecvSlots = udpRecvSlots },
    Quic = new QuicOptions
    {
        Port = quicPort,
        LocalCidLength = 8,
        // From here the host table is live, and only ReplaceCertificates may change it.
        ConnectionFactory = engine.CreateFactory(),
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
        ReadTimeoutMs = 60_000,   // close a connection whose peer is silent this long; 0 = off
    },
};

int generation = 0;
object rotationGate = new();

void Rotate(string trigger)
{
    // SIGHUP and the timer can land together, so the pair of "which generation" and "publish it"
    // is taken atomically here. The engine takes its own lock around the publish.
    lock (rotationGate)
    {
        int next = Interlocked.Increment(ref generation);
        bool renewed = next % 2 == 1;

        var certificate = renewed
            ? new QuicCertificate(renewedCert, renewedKey)
            : new QuicCertificate(certPath, keyPath);

        Dictionary<string, QuicCertificate> table = renewed ? renewedTable : originalTable;

        try
        {
            // One call, every reactor. The table goes with it because the set is replaced whole.
            engine.ReplaceCertificates(certificate, table);
        }
        catch (Exception e)
        {
            // The engine is still serving the previous set, on every reactor. Nothing to undo.
            Console.Error.WriteLine($"[http3-rotate] generation {next} refused, still serving the previous set: {e.Message}");
            return;
        }

        Console.WriteLine($"[http3-rotate] generation {next} ({trigger}): serving "
                        + $"{(renewed ? "renewed" : "original")} - pin "
                        + $"{table[hosts[0]].CertificatePath}");
    }
}

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = (_, connection) =>
        new Http3Connection(connection).RunAsync(_ =>
        {
            // What the SERVER believes it published. The client's view is the certificate it just
            // validated, and only pinning with --cacert can tell you that.
            int served = Volatile.Read(ref generation);

            var response = new Http3Response
            {
                Body = Encoding.UTF8.GetBytes($"generation {served} ({(served % 2 == 1 ? "renewed" : "original")})\n"),
            };
            response.Headers.Add(("content-type"u8.ToArray(), "text/plain"u8.ToArray()));
            return response;
        });

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

Console.WriteLine($"[http3-rotate] pid {Environment.ProcessId}, {config.ReactorCount} reactors on :{quicPort}, "
                + $"default + {string.Join(", ", hosts)}, "
                + $"rotating {(rotateEverySeconds > 0 ? $"every {rotateEverySeconds}s and " : "")}on SIGHUP");

foreach (Thread thread in threads)
{
    thread.Join();
}
