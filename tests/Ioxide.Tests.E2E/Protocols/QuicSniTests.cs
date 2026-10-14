using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Server Name Indication over QUIC: one UDP port answering for several hosts, each with its own
/// certificate.
/// </summary>
/// <remarks>
/// The assertion is always the SUBJECT of the certificate the server served, because that is the
/// whole observable effect of the selection - an engine that ignored the name and answered with its
/// default every time would pass anything weaker and fails these.
///
/// Unlike TLS over TCP there is no "client sent no name" case to drive: a QUIC client offers one
/// (RFC 9001), so the default certificate is reached here through a name nobody registered.
/// </remarks>
internal static class QuicSniTests
{
    public static void Register(Runner runner)
    {
        runner.Test("sni/quic: a named host is answered with its own certificate", () =>
        {
            using var engine = NewEngine(out _);
            int udpPort = Serve(engine);

            // Both names, over separate connections to the same port - which is the point.
            (string alpha, int alphaStatus) = Ask(udpPort, "alpha.test");
            Assert.Equal(200, alphaStatus);
            Assert.True(alpha.Contains("alpha.test"),
                $"asking for alpha.test should be answered with alpha.test's certificate, got: {alpha}");

            (string beta, int betaStatus) = Ask(udpPort, "beta.test");
            Assert.Equal(200, betaStatus);
            Assert.True(beta.Contains("beta.test"),
                $"asking for beta.test should be answered with beta.test's certificate, got: {beta}");
        });

        runner.Test("sni/quic: an unknown name gets the default rather than a refusal", () =>
        {
            using var engine = NewEngine(out _);
            int udpPort = Serve(engine);

            // Answering is deliberate: refusing a name this engine does not hold would surface as a
            // dead connection, which tells a client nothing about why.
            (string subject, int status) = Ask(udpPort, "nobody.test");
            Assert.Equal(200, status);
            Assert.True(subject.Contains("localhost"),
                $"an unregistered name should fall back to the default certificate, got: {subject}");
        });

        runner.Test("sni/quic: the name is matched case-insensitively", () =>
        {
            using var engine = NewEngine(out _);
            int udpPort = Serve(engine);

            // DNS names have no case, so a client shouting asks for the same host.
            (string subject, _) = Ask(udpPort, "ALPHA.test");
            Assert.True(subject.Contains("alpha.test"),
                $"ALPHA.test and alpha.test are the same host, got: {subject}");
        });

        runner.Test("sni/quic: a host registered by its uppercase name is still matched", () =>
        {
            // The other direction: the name given to AddHost is folded too, not just the client's.
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            engine.AddHost("ALPHA.TEST", alphaCert, alphaKey);

            int udpPort = Serve(engine);

            (string subject, _) = Ask(udpPort, "alpha.test");
            Assert.True(subject.Contains("alpha.test"),
                $"a host registered as ALPHA.TEST should answer for alpha.test, got: {subject}");
        });

        runner.Test("sni/quic: with no host registered the default certificate answers everything", () =>
        {
            // The regression guard for everyone not using SNI: the client-hello callback leaves the
            // context alone, and a named request is answered exactly as it was before.
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            int udpPort = Serve(engine);

            (string subject, int status) = Ask(udpPort, "alpha.test");
            Assert.Equal(200, status);
            Assert.True(subject.Contains("localhost"),
                $"without a registered host the default certificate answers every name, got: {subject}");
        });

        runner.Test("sni/quic: an unreadable certificate is refused when the host is added", () =>
        {
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);

            string refusal = "";

            try
            {
                engine.AddHost("alpha.test", "/nonexistent/alpha.crt", "/nonexistent/alpha.key");
            }
            catch (InvalidOperationException e)
            {
                refusal = e.Message;
            }

            // Refused where the paths are given, not at some later handshake that would report a
            // missing file as a client-side connection failure.
            Assert.True(refusal.Contains("alpha.test"),
                $"a host whose certificate cannot be loaded should be refused by AddHost; got: {refusal}");
        });

        // Mutual TLS and SNI together. The pair that matters: a named host is served from its own
        // picotls context, and unlike the TCP side - where OpenSSL keeps the verify mode on the
        // connection whatever context it swaps to - picotls takes EVERYTHING from the swapped
        // context. So the client-verification settings are carried over by hand in the shim, and
        // if that carry-over were ever dropped, asking for a host name by itself would be a way
        // past the certificate this engine demands. These are the tests that notice.
        runner.Test("sni/quic: selecting a named host still demands a client certificate", () =>
        {
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);
            engine.AddHost("alpha.test", alphaCert, alphaKey);

            int udpPort = Serve(engine);

            // A named host, and nothing to prove who is asking. Asserted on the REQUEST rather than
            // the handshake: a TLS 1.3 client finishes its own side before it can learn the server
            // rejected it, so only being answered proves anything.
            using var client = new H3TestClient("127.0.0.1", udpPort) { ServerName = "alpha.test" };
            client.Connect();
            client.CompleteHandshake(timeoutMs: 3000);

            (int status, _) = client.Get("/", timeoutMs: 3000);
            Assert.True(status != 200,
                $"asking for a host by name must not be a way around the client certificate the engine requires (status {status})");
        });

        runner.Test("sni/quic: a named host verifies the client against the same anchors", () =>
        {
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);
            engine.AddHost("alpha.test", alphaCert, alphaKey);

            int udpPort = ServeIdentity(engine);

            // Trusted client asking for the named host: gets in, and is still NAMED - the identity
            // survives the context swap rather than the connection merely surviving it.
            using (var good = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey) { ServerName = "alpha.test" })
            {
                good.Connect();
                Assert.True(good.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

                (int status, string body) = good.Get("/", timeoutMs: 5000);
                Assert.Equal(200, status);
                Assert.True(body.Contains("alice"), $"the handler should see the client's subject, got: {body}");
            }

            // Same named host, a certificate from a CA this engine never trusted: still turned away.
            using var rogue = new H3TestClient("127.0.0.1", udpPort, rogueCert, rogueKey) { ServerName = "alpha.test" };
            rogue.Connect();
            rogue.CompleteHandshake(timeoutMs: 3000);

            (int rogueStatus, _) = rogue.Get("/", timeoutMs: 3000);
            Assert.True(rogueStatus != 200,
                $"a named host must validate client certificates against the same anchors as the default (status {rogueStatus})");
        });

        runner.Test("sni/quic: a name that merely starts with a registered one gets the default", () =>
        {
            using var engine = NewEngine(out _);
            int udpPort = Serve(engine);

            // The matcher compares lengths first, so this cannot match - but an "optimisation" to
            // a prefix compare would serve alpha.test's certificate to whoever asked for this.
            (string subject, _) = Ask(udpPort, "alpha.test.evil.example");
            Assert.True(subject.Contains("localhost"),
                $"a longer name that starts with a registered one must not match it, got: {subject}");
        });

        runner.Test("sni/quic: the right host answers out of a table of many", () =>
        {
            // Two entries never exercise a scan. Twelve do, and h1/h11 share a prefix, so an
            // off-by-one at either end of the table shows up as the wrong certificate.
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);

            for (int i = 1; i <= 12; i++)
            {
                (string hostCert, string hostKey) = TestCert.EnsureNamed($"h{i}.test");
                engine.AddHost($"h{i}.test", hostCert, hostKey);
            }

            int udpPort = Serve(engine);

            // Asserted with the CN= prefix so that h1 cannot be satisfied by h11's certificate.
            (string first, _) = Ask(udpPort, "h1.test");
            Assert.True(first.Contains("CN=h1.test"), $"h1.test should get its own certificate, got: {first}");

            (string last, _) = Ask(udpPort, "h12.test");
            Assert.True(last.Contains("CN=h12.test"), $"the last entry should be reachable, got: {last}");

            (string middle, _) = Ask(udpPort, "h11.test");
            Assert.True(middle.Contains("CN=h11.test"), $"h11.test should get its own certificate, got: {middle}");
        });

        // Driven by curl rather than by the in-tree client, because curl VALIDATES. Everything
        // above proves which certificate came back; these prove the answer is one a real client
        // will take - chain built to an anchor, name matched against what was asked for. That is
        // the assertion the in-tree client cannot make, since it authenticates nothing.
        runner.Test("sni/quic: a validating client accepts the certificate for the name it asked for", () =>
        {
            (string ca, string alphaCert, string alphaKey) = TestCert.EnsureNamedFromCa("alpha.test");
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            engine.AddHost("alpha.test", alphaCert, alphaKey);

            int udpPort = Serve(engine);

            (int exit, string body, string stderr) = CurlH3.Get("alpha.test", udpPort, ca);

            Assert.Equal(0, exit);
            Assert.True(body.Contains("ok"), $"curl should have been served the page, got: {body} {stderr}");
        }, skip: !CurlH3.Available);

        runner.Test("sni/quic: a validating client rejects the default certificate for an unknown name", () =>
        {
            // The other half, and the one that makes the test above mean something: the fallback is
            // deliberately the default certificate, which does NOT cover this name. A client that
            // checks must refuse it. If this passed, the test above would prove nothing - the
            // server could be handing the same certificate to everyone.
            (string ca, string alphaCert, string alphaKey) = TestCert.EnsureNamedFromCa("alpha.test");
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            engine.AddHost("alpha.test", alphaCert, alphaKey);

            int udpPort = Serve(engine);

            (int exit, _, string stderr) = CurlH3.Get("nobody.test", udpPort, ca);

            Assert.True(exit != 0,
                "a name this server does not hold is answered with the default certificate, which does not " +
                "cover it - a client that validates must refuse the connection");
            Assert.True(stderr.Length > 0, "curl should have said why it refused");
        }, skip: !CurlH3.Available);

        runner.Test("sni/quic: a validating client is served the right certificate out of several", () =>
        {
            // Two named hosts from one port, both verified end to end. The case the feature exists
            // for, asserted the way a browser would experience it.
            (string ca, string alphaCert, string alphaKey) = TestCert.EnsureNamedFromCa("alpha.test");
            (_, string betaCert, string betaKey) = TestCert.EnsureNamedFromCa("beta.test");
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            engine.AddHost("alpha.test", alphaCert, alphaKey);
            engine.AddHost("beta.test", betaCert, betaKey);

            int udpPort = Serve(engine);

            (int alphaExit, _, string alphaErr) = CurlH3.Get("alpha.test", udpPort, ca);
            Assert.True(alphaExit == 0, $"alpha.test should verify: {alphaErr}");

            (int betaExit, _, string betaErr) = CurlH3.Get("beta.test", udpPort, ca);
            Assert.True(betaExit == 0, $"beta.test should verify: {betaErr}");
        }, skip: !CurlH3.Available);

        runner.Test("sni/quic: a host cannot be added once the engine is serving", () =>
        {
            // Not a style rule. The table is read from the handshake on reactor threads with no
            // lock, so a late write is beside those reads: the array can move under a reader mid
            // scan, and a half-published entry hands picotls a wild pointer it will call through.
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            _ = engine.CreateFactory();

            string refusal = "";

            try
            {
                engine.AddHost("alpha.test", alphaCert, alphaKey);
            }
            catch (InvalidOperationException e)
            {
                refusal = e.Message;
            }

            Assert.True(refusal.Contains("once the engine is serving"),
                $"adding a host after the engine is serving should be refused, not raced; got: {refusal}");
        });

        runner.Test("sni/quic: registering the same host twice is refused", () =>
        {
            // The first registration is the one that would answer, so a second certificate for the
            // same name would sit in the table and never be served.
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            engine.AddHost("alpha.test", alphaCert, alphaKey);

            bool refused = false;

            try
            {
                // Different spelling, same host.
                engine.AddHost("ALPHA.test", cert, key);
            }
            catch (InvalidOperationException)
            {
                refused = true;
            }

            Assert.True(refused, "a name already registered should be refused rather than silently shadowed");
        });

        runner.Test("sni/quic: a blank host name is refused", () =>
        {
            (string cert, string key) = TestCert.Ensure();

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            bool refused = false;

            try
            {
                engine.AddHost("   ", alphaCert, alphaKey);
            }
            catch (ArgumentException)
            {
                refused = true;
            }

            Assert.True(refused, "a blank name cannot be asked for by SNI and should be refused");
        });

        // The shim matches names exactly, so each of these was built and never served (#207).
        runner.Test("sni/quic: a host name no client can ask for is refused, naming it", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);

            // Both ways a name reaches the table: added before serving, and in a rotation.
            foreach ((string host, string reason) in Unservable)
            {
                Assert.Throws<ArgumentException>(() => engine.AddHost(host, alphaCert, alphaKey),
                    $"the host '{host}' cannot be asked for by SNI: {reason}");

                Assert.Throws<ArgumentException>(() => engine.ReplaceCertificates(new QuicCertificate(cert, key),
                    new Dictionary<string, QuicCertificate> { [host] = new(alphaCert, alphaKey) }),
                    $"the host '{host}' cannot be asked for by SNI: {reason}");
            }
        });

        // The control: refused for what they are, not for looking unusual.
        runner.Test("sni/quic: control: an A-label name and a name of exactly 255 bytes are accepted", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            using var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
            engine.AddHost("xn--bcher-kva.test", alphaCert, alphaKey);
            engine.AddHost(Longest, alphaCert, alphaKey);
            int udpPort = Serve(engine);

            (string subject, int status) = Ask(udpPort, "xn--bcher-kva.test");
            Assert.True(subject.Contains("alpha.test"), $"the A-label name was answered with {subject}");
            Assert.Equal(200, status);
        });
    }

    /// <summary>Four 63-byte labels: 255 bytes, the longest name the TCP side's OpenSSL accepts.</summary>
    private static readonly string Longest = string.Join('.', Enumerable.Repeat(new string('a', 63), 4));

    /// <summary>Keys no client can ask for, each with the start of the reason it is refused for.</summary>
    private static readonly (string Host, string Reason)[] Unservable =
    [
        ("*.alpha.test", "a wildcard"),
        ("127.0.0.1", "an IP address"),
        ("::1", "an IP address"),
        ("b\u00fccher.test", "a non-ASCII name"),
        (Longest + "a", "a name over 255 bytes"),
    ];

    /// <summary>Default localhost certificate, plus alpha.test and beta.test by name.</summary>
    private static QuicEngine NewEngine(out string defaultCert)
    {
        (string cert, string key) = TestCert.Ensure();
        (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");
        (string betaCert, string betaKey) = TestCert.EnsureNamed("beta.test");

        defaultCert = cert;

        var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
        engine.AddHost("alpha.test", alphaCert, alphaKey);
        engine.AddHost("beta.test", betaCert, betaKey);
        return engine;
    }

    /// <summary>
    /// Serves h3 on a fresh port. What it answers with does not matter - that it answers at all is
    /// what proves a swapped context still carries the connection.
    /// </summary>
    private static int Serve(QuicEngine engine)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                static _ => new Nghttp3Response { Body = "ok"u8.ToArray() }));

        return udpPort;
    }

    /// <summary>
    /// Like <see cref="Serve"/>, but answering with the client's verified identity, so a test can
    /// tell "some certificate got in" from "the one we trusted got in".
    /// </summary>
    private static int ServeIdentity(QuicEngine engine)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(
                _ => new Nghttp3Response
                {
                    Body = System.Text.Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerSubject ?? "anonymous"),
                }));

        return udpPort;
    }

    /// <summary>
    /// Handshakes asking for one name, and reports the certificate that came back along with the
    /// status of a request over the same connection.
    /// </summary>
    private static (string Subject, int Status) Ask(int udpPort, string serverName)
    {
        using var client = new H3TestClient("127.0.0.1", udpPort)
        {
            ServerName = serverName,
            RecordServerCertificate = true,
        };

        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), $"handshake for '{serverName}' did not complete");

        (int status, _) = client.Get("/", timeoutMs: 5000);
        return (client.ServerCertificateSubject(), status);
    }
}
