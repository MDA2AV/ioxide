using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http3-sni - one UDP port, several hosts, a different certificate for each. The client says
//  which host it wants in the QUIC handshake (Server Name Indication) and the server answers with
//  that host's certificate.
//
//      dotnet run -c Release --project Playground/Http3/Sni
//      curl --http3-only -k --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//      curl --http3-only -k --resolve beta.test:8443:127.0.0.1  https://beta.test:8443/
//
//  --resolve is how you reach a name that has no DNS entry: curl sends "alpha.test" as the name it
//  wants but connects to 127.0.0.1. Drop the -k and hand curl the certificate you expect to see
//  which one actually came back:
//
//      curl --http3-only -s --cacert /tmp/ioxide-playground-quic/sni-alpha_test.crt \
//           --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/
//
//  That succeeds for alpha.test and fails for beta.test, which is the feature working. It needs a
//  curl built with HTTP/3 - a stock one has no --http3-only.
//
//  The certificate given to the constructor stays the DEFAULT: a client asking for a name that was
//  never registered gets it rather than being refused, so the port is still reachable by address.
//
//  Register every host BEFORE CreateFactory. Once the engine is serving, AddHost refuses: the
//  table is read during handshakes on whichever reactor a connection landed on, and adding to it
//  underneath those reads is not a race worth documenting.
//
//  Client verification carries over to every host, so a name cannot be a way around the mutual TLS
//  the engine was built with. Names are matched case-insensitively and in full; registering the
//  same one twice is refused rather than one of them silently never answering.
//
//  Needs: ioxide, ioxide.ngtcp2, ioxide.http3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort quicPort = 8443;                        // https://127.0.0.1:8443/ over QUIC
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

if (ushort.TryParse(Environment.GetEnvironmentVariable("PLAYGROUND_QUIC_PORT"), out ushort p))
{
    quicPort = p;
}
if (int.TryParse(Environment.GetEnvironmentVariable("PLAYGROUND_REACTORS"), out int r) && r > 0)
{
    reactors = r;
}

// A real PEM pair for the DEFAULT certificate, or null to generate a self-signed localhost one.
string? certOverride = null;
string? keyOverride  = null;

// The names this port answers for, beside the default. Add a line and it is served.
string[] hosts = ["alpha.test", "beta.test"];

// UDP receive slots per reactor: how many datagrams the ring can have outstanding at once.
int udpRecvSlots = 16;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

// PEM paths, because ngtcp2 loads certificates by path.
foreach (string host in hosts)
{
    (string hostCert, string hostKey) = QuicCert.EnsureNamed(host);
    engine.AddHost(host, hostCert, hostKey);
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
        // From here the host table is live and closed to further additions.
        ConnectionFactory = engine.CreateFactory(),
        // Where a moved client's packets go when several reactors share the port. Forward costs
        // nothing until a client actually changes address; KernelFilter has the kernel route by
        // connection id instead, which costs a little on every packet. See /how-ioxide-does-h3.
        Routing = QuicRouting.Forward,
        ReadTimeoutMs = 60_000,   // close a connection whose peer is silent this long; 0 = off
    },
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.QuicHandle = (_, connection) =>
        new Http3Connection(connection).RunAsync(_ =>
        {
            // The certificate was chosen during the handshake, before this ever runs. Routing a
            // request to the right site is a separate job, and the :authority header is where you
            // would do it - the name in the handshake picked the certificate, nothing more.
            var response = new Http3Response { Body = Encoding.UTF8.GetBytes("ok\n") };
            response.Headers.Add(("content-type"u8.ToArray(), "text/plain"u8.ToArray()));
            return response;
        });

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[http3-sni] {config.ReactorCount} reactors on :{quicPort}, "
                + $"default + {string.Join(", ", hosts)}");

foreach (Thread thread in threads)
{
    thread.Join();
}
