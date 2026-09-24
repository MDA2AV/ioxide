using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  http3-mtls - HTTP/3 where the CLIENT proves who it is too. The server verifies a client
//  certificate during the QUIC handshake and the handler is told which peer it got.
//
//      dotnet run -c Release --project Playground/Http3/MutualTls
//      curl --http3 --cacert ca.crt --cert client.crt --key client.key https://localhost:8443/
//
//  Make a CA and two certificates it signs - one for the server, one for the client:
//
//      openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 \
//        -subj "/CN=my CA" -addext "basicConstraints=critical,CA:TRUE"
//      openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=alice"
//      printf 'extendedKeyUsage=clientAuth\n' > c.cnf
//      openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
//        -out client.crt -days 365 -extfile c.cnf
//
//  QUIC settles client authentication during the handshake, and RFC 9001 4.4 forbids doing it
//  afterwards - so this is a property of the whole CONNECTION. There is no asking for a certificate
//  later because a request reached a protected route; that needs a second port.
//  Needs: ioxide, ioxide.ngtcp2, ioxide.http3
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort quicPort = 8443;
int    reactors = Environment.ProcessorCount;

Env.OverrideQuic(ref quicPort, ref reactors);

// The server's own certificate and key. Null generates a self-signed pair on first run.
string? certOverride = null;
string? keyOverride  = null;

Env.OverrideCert(ref certOverride, ref keyOverride);

// The CA that client certificates are checked against. This is what turns mTLS ON - leave both null
// and the server verifies nothing about the client, exactly as the other h3 samples do.
//
// Either the bundle's path, or the bundle itself as PEM text for a host that keeps its CA in a
// secrets store rather than on disk. Set one, not both.
string? clientCaPath = Environment.GetEnvironmentVariable("PLAYGROUND_CLIENT_CA");
string? clientCaPem  = Environment.GetEnvironmentVariable("PLAYGROUND_CLIENT_CA_PEM");

// Refuse a client that offers no certificate, during the handshake. Off, so a client without one
// still connects and the handler decides what it may see - which is the more useful default when
// only part of a site is protected.
bool requireClientCertificate = Environment.GetEnvironmentVariable("PLAYGROUND_REQUIRE_CLIENT_CERT") == "1";

// UDP receive slots per reactor: how many datagrams the ring can have outstanding at once.
int udpRecvSlots = 16;
// ─────────────────────────────────────────────────────────────────────────────────────────────

(string certPath, string keyPath) = QuicCert.Ensure(certOverride, keyOverride);

if (clientCaPath is null && clientCaPem is null)
{
    Console.Error.WriteLine("set PLAYGROUND_CLIENT_CA to a PEM bundle of the CA that signs your client "
                          + "certificates, or PLAYGROUND_CLIENT_CA_PEM to that bundle as text.");
    return 1;
}

using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"],
    clientCaPemPath: clientCaPath, requireClientCertificate: requireClientCertificate,
    clientCaPem: clientCaPem);

var config = new ServerConfig
{
    ReactorCount = reactors,
    Tcp = null,                                        // QUIC only
    Udp = new UdpOptions { RecvSlots = udpRecvSlots },
    Quic = new QuicOptions
    {
        Port = quicPort,
        LocalCidLength = 8,
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
            // Read HERE, per request - not where the connection is accepted. That callback runs
            // before the handshake finishes, so there is no identity yet at that point.
            string? peer = (connection as QuicEngineConnection)?.PeerSubject;

            var response = new Http3Response
            {
                Body = Encoding.UTF8.GetBytes(peer is null
                    ? "anonymous\n"
                    : $"authenticated as {peer}\n"),
            };
            response.Headers.Add(("content-type"u8.ToArray(), "text/plain"u8.ToArray()));
            return response;
        });

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[http3-mtls] {config.ReactorCount} reactors on :{quicPort}, "
                + $"client CA {clientCaPath ?? "from PEM text"}, "
                + $"client certificate {(requireClientCertificate ? "REQUIRED" : "optional")}");

foreach (Thread thread in threads)
{
    thread.Join();
}

return 0;
