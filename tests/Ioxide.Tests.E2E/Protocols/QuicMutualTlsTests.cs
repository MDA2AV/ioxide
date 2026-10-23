using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Client certificates over QUIC. Three things have to hold together or the feature is theatre: a
/// certificate the server trusts gets in, one it does not is turned away, and the handler can say
/// WHICH client it got - a server that only knows "some valid certificate" has a gate, not an
/// identity.
/// </summary>
internal static class QuicMutualTlsTests
{
    public static void Register(Runner runner)
    {
        runner.Test("mtls: a client with a trusted certificate connects, and is named", () =>
        {
            (string ca, string serverCert, string serverKey,
             string clientCert, string clientKey, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                // Read inside the REQUEST handler, not at accept: the connection callback fires
                // before the handshake finishes, so the identity does not exist yet there.
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    _ => new Nghttp3Response
                    {
                        Body = Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerSubject ?? "anonymous"),
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alice"), $"the handler should see the client's subject, got: {body}");
        });

        runner.Test("mtls: a client with no certificate is refused", () =>
        {
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => new Nghttp3Response { Body = "should never be reached"u8.ToArray() }));

            // The stock client offers nothing, which is the whole point of requiring one.
            //
            // Asserted on the REQUEST, not the handshake: in TLS 1.3 the client finishes its own
            // side before it can learn the server rejected its certificate, so the client thinking
            // it is established proves nothing. Being answered does.
            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 3000);

            (int status, _) = client.Get("/", timeoutMs: 3000);
            Assert.True(status != 200, $"a client with no certificate was served anyway (status {status})");
        });

        runner.Test("mtls: a certificate from another CA is refused", () =>
        {
            (string ca, string serverCert, string serverKey, _, _,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => new Nghttp3Response { Body = "should never be reached"u8.ToArray() }));

            // Well-formed and correctly signed - by a CA this server has never heard of.
            using var client = new H3TestClient("127.0.0.1", udpPort, rogueCert, rogueKey);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 3000);

            (int status, _) = client.Get("/", timeoutMs: 3000);
            Assert.True(status != 200, $"an untrusted certificate was served anyway (status {status})");
        });

        runner.Test("mtls: the trust anchors can be PEM text rather than a file", () =>
        {
            (string ca, string serverCert, string serverKey,
             string clientCert, string clientKey, _, _) = TestCert.EnsureMutualTls();

            // The same anchors as the first test, handed over as data instead of as a path - what a
            // host keeping its bundle in a secrets store holds, without writing it out to read back.
            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                requireClientCertificate: true, clientCaPem: File.ReadAllText(ca));

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    _ => new Nghttp3Response
                    {
                        Body = Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerSubject ?? "anonymous"),
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alice"), $"the handler should see the client's subject, got: {body}");
        });

        runner.Test("mtls: PEM text anchors refuse a certificate from another CA", () =>
        {
            // The other half of the one above: anchors read from text have to turn a stranger away
            // as well as let the trusted one in. A store that verified nothing would pass that test
            // just as happily, so admitting alice proves only half of it.
            (string ca, string serverCert, string serverKey, _, _,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                requireClientCertificate: true, clientCaPem: File.ReadAllText(ca));

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => new Nghttp3Response { Body = "should never be reached"u8.ToArray() }));

            using var client = new H3TestClient("127.0.0.1", udpPort, rogueCert, rogueKey);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 3000);

            (int status, _) = client.Get("/", timeoutMs: 3000);
            Assert.True(status != 200, $"an untrusted certificate was served anyway (status {status})");
        });

        runner.Test("mtls: naming both a CA file and CA text is refused", () =>
        {
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            // Two sources for one answer: silently picking either would make the other look applied.
            bool refused = false;

            try
            {
                using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                    clientCaPemPath: ca, requireClientCertificate: true, clientCaPem: File.ReadAllText(ca));
            }
            catch (ArgumentException)
            {
                refused = true;
            }

            Assert.True(refused, "two client CA sources should be refused, not quietly resolved to one");
        });

        runner.Test("mtls: off by default - no client CA means no certificate is asked for", () =>
        {
            // The regression guard for everyone not using mTLS: the handshake must be untouched.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                // Read inside the REQUEST handler, not at accept: the connection callback fires
                // before the handshake finishes, so the identity does not exist yet there.
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    _ => new Nghttp3Response
                    {
                        Body = Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerSubject ?? "anonymous"),
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("anonymous", body);
        });

        // Optional mTLS: anchors configured, but a client offering nothing is still let in. The
        // point of the pair below is that BOTH halves have to hold. Only refusing the empty case
        // is easy; still identifying the clients that DO have a certificate is what makes the
        // setting mean "optional" rather than "off".
        runner.Test("mtls optional: a client with a certificate is still asked, and is named", () =>
        {
            (string ca, string serverCert, string serverKey,
             string clientCert, string clientKey, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: false);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    _ => new Nghttp3Response
                    {
                        Body = Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerCommonName ?? "anonymous"),
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alice"),
                $"an optional-mTLS server must still ASK, or a client with a certificate is never "
                + $"identified and optional means never; got: {body}");
        });

        runner.Test("mtls optional: a client with no certificate still gets in, unnamed", () =>
        {
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: false);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    _ => new Nghttp3Response
                    {
                        Body = Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerCommonName ?? "anonymous"),
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("anonymous", body);
        });

        runner.Test("mtls optional: a certificate from another CA is still refused", () =>
        {
            // The half that must NOT be relaxed. "Optional" forgives an empty answer and nothing
            // else - a certificate that was offered and does not validate is a refusal either way.
            (string ca, string serverCert, string serverKey, _, _,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: false);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => new Nghttp3Response { Body = "should never be reached"u8.ToArray() }));

            using var client = new H3TestClient("127.0.0.1", udpPort, rogueCert, rogueKey);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 3000);

            (int status, _) = client.Get("/", timeoutMs: 3000);
            Assert.True(status != 200, $"an untrusted certificate was served anyway (status {status})");
        });

        runner.Test("mtls: a refused client is TOLD, not left waiting", () =>
        {
            // Without a CONNECTION_CLOSE the client learns nothing and sits until its own idle
            // timeout, which is indistinguishable from a server that has gone away.
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                    static _ => new Nghttp3Response { Body = "should never be reached"u8.ToArray() }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            client.CompleteHandshake(timeoutMs: 3000);
            client.Get("/", timeoutMs: 3000);

            Assert.True(client.PeerClosed, "the server refused the handshake but never said so");
        });

        runner.Test("quic: a connection ID length the wire cannot carry is refused", () =>
        {
            // 20 bytes is the QUIC maximum and ngtcp2_cid is sized to exactly that, so a longer
            // one would be written past the end of a stack struct while minting the server's CID.
            (string certPath, string keyPath) = TestCert.Ensure();

            Assert.Throws<ArgumentOutOfRangeException>(
                () => new QuicEngine(certPath, keyPath, cidLength: 21).Dispose(),
                "1..20");

            Assert.Throws<ArgumentOutOfRangeException>(
                () => new QuicEngine(certPath, keyPath, cidLength: 0).Dispose(),
                "1..20");
        });

        RegisterRefusedCertificates(runner);
    }

    /// <summary>
    /// Client certificates that chain to the trusted anchor and must be refused anyway - the TCP
    /// group of the same purpose (MutualTlsTests, RegisterBadClientCertificates), run against QUIC's
    /// own verifier: picotls over the shim's X509_STORE, not BoringSSL's SSL_VERIFY_PEER. Everything
    /// above is a clean, in-date, correctly purposed leaf, so it held the engine only to the chain,
    /// while QuicEngine promises that the signatures verify and the certificate is inside its
    /// validity window as well.
    /// </summary>
    /// <remarks>
    /// Each refusal runs the clean client on the same engine first, so "refused" is about that one
    /// certificate and not an engine that serves nobody. The shim closes every TLS failure with the
    /// same transport error (see QuicSniHostileTests), so what is asserted is the refusal and that
    /// the client is told, not which alert it was.
    /// </remarks>
    private static void RegisterRefusedCertificates(Runner runner)
    {
        (string Label, TestCert.ClientCertSpec Spec, string Why)[] rejects =
        [
            ("an expired client certificate", new TestCert.ClientCertSpec
            {
                Subject = "CN=expired-alice",
                // Inside the CA's own window: .NET refuses to issue a leaf that predates its
                // issuer, and the CA here starts a day ago.
                NotBefore = TimeSpan.FromHours(-23),
                NotAfter = TimeSpan.FromHours(-1),
            }, "validity is checked, not just the signature"),

            ("a client certificate that is not valid yet", new TestCert.ClientCertSpec
            {
                Subject = "CN=future-alice",
                NotBefore = TimeSpan.FromDays(1),
                NotAfter = TimeSpan.FromDays(30),
            }, "notBefore is checked as well as notAfter"),

            ("a client certificate for the wrong purpose", new TestCert.ClientCertSpec
            {
                Subject = "CN=server-alice",
                ExtendedKeyUsage = "1.3.6.1.5.5.7.3.1",   // serverAuth only
            }, "the extended key usage decides what a certificate may be USED for"),

            ("a client certificate that names the trusted CA but was not signed by it", new TestCert.ClientCertSpec
            {
                Subject = "CN=forged-alice",
                ForgedSignature = true,
            }, "the signature is verified, not just the issuer's name - a stranger's CA fails earlier, at the name"),
        ];

        foreach ((string label, TestCert.ClientCertSpec spec, string why) in rejects)
        {
            runner.Test($"mtls/quic: {label} is refused", () =>
            {
                (string ca, string cert, string key) = TestCert.EnsureClientCert(spec);
                (_, string serverCert, string serverKey, string goodCert, string goodKey, _, _) = TestCert.EnsureMutualTls();

                using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                    clientCaPemPath: ca, requireClientCertificate: true);
                int udpPort = ServeCommonName(engine);

                (int goodStatus, string goodName) = Ask(udpPort, goodCert, goodKey);
                Assert.Equal(200, goodStatus);
                Assert.Equal("alice", goodName);

                using var client = new H3TestClient("127.0.0.1", udpPort, cert, key);
                client.Connect();
                client.CompleteHandshake(timeoutMs: 3000);

                (int status, _) = client.Get("/", timeoutMs: 3000);
                Assert.True(status != 200, $"{label} was SERVED - {why}");
                Assert.True(client.PeerClosed, $"{label} was not refused with a close; the server went quiet instead");
            });
        }

        runner.Test("mtls/quic: a client certificate that chains through an intermediate is accepted", () =>
        {
            // Every other fixture is signed DIRECTLY by the anchor, so a server that never built a
            // chain at all would pass all of them. Here the anchors are the root and the intermediate,
            // and the client presents the leaf alone.
            (string anchors, _, string cert, string key) = TestCert.EnsureChainedClientCert();
            (_, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: anchors, requireClientCertificate: true);
            int udpPort = ServeCommonName(engine);

            (int status, string name) = Ask(udpPort, cert, key);
            Assert.Equal(200, status);
            Assert.Equal("chained-alice", name);
        });

        runner.Test("mtls/quic: an EC client certificate is accepted", () =>
        {
            // Every other fixture is RSA, so nothing would notice a server that only took RSA
            // client keys - a different CertificateVerify signature on the wire.
            (string ca, string cert, string key) = TestCert.EnsureClientCert(new TestCert.ClientCertSpec
            {
                Subject = "CN=ec-alice",
                EllipticCurve = true,
            });
            (_, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);
            int udpPort = ServeCommonName(engine);

            (int status, string name) = Ask(udpPort, cert, key);
            Assert.Equal(200, status);
            Assert.Equal("ec-alice", name);
        });
    }

    private static int ServeCommonName(QuicEngine engine)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                _ => new Nghttp3Response
                {
                    Body = Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerCommonName ?? "anonymous"),
                }));

        return udpPort;
    }

    private static (int Status, string Body) Ask(int udpPort, string certPath, string keyPath)
    {
        using var client = new H3TestClient("127.0.0.1", udpPort, certPath, keyPath);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client.Get("/", timeoutMs: 5000);
    }
}
