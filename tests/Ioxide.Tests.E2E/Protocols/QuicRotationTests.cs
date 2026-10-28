using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Replacing certificates on a running QUIC engine - the renewal case, where restarting to pick up
/// a reissued PEM would be an outage.
/// </summary>
/// <remarks>
/// Harder than the TCP side and tested more carefully for it: BoringSSL refcounts a context, so a
/// connection holding one keeps it alive. picotls does not - it reads the context for as long as
/// the connection lives - so a generation is published whole and the one it replaced is kept rather
/// than freed. The load test below is the one that would crash if that were wrong.
/// </remarks>
internal static class QuicRotationTests
{
    public static void Register(Runner runner)
    {
        runner.Test("rotate/quic: the default certificate is replaced for new connections", () =>
        {
            (string first, string firstKey) = TestCert.EnsureNamed("first.test");
            (string second, string secondKey) = TestCert.EnsureNamed("second.test");

            var engine = TestServer.Own(new QuicEngine(first, firstKey, cidLength: 8, alpn: ["h3"]));
            int udpPort = Serve(engine);

            Assert.True(Ask(udpPort, "first.test").Contains("first.test"),
                "the engine should start on the certificate it was given");

            engine.ReplaceCertificates(new QuicCertificate(second, secondKey));

            Assert.True(Ask(udpPort, "first.test").Contains("second.test"),
                "a connection made after the rotation should get the new certificate");
        });

        runner.Test("rotate/quic: a host certificate is replaced", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string beta, string betaKey) = TestCert.EnsureNamed("beta.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("named.test", alpha, alphaKey);

            int udpPort = Serve(engine);

            Assert.True(Ask(udpPort, "named.test").Contains("alpha.test"),
                "the name should start on the certificate it was registered with");

            engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
            {
                ["named.test"] = new(beta, betaKey),
            });

            Assert.True(Ask(udpPort, "named.test").Contains("beta.test"),
                "the name should be answered with the certificate the rotation installed");
        });

        runner.Test("rotate/quic: renewing without the host table is refused, not silently applied", () =>
        {
            // The shape a renewal hook is written in: the default certificate expired, so rotate
            // the default certificate. Omitting the table published a generation with NO names in
            // it, so every registered host was answered with the default certificate from then on -
            // no exception, no log line, and a name mismatch at each client. Both readings of the
            // omission are plausible, which is exactly why it has to be stated.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("named.test", alpha, alphaKey);

            int udpPort = Serve(engine);
            Assert.True(Ask(udpPort, "named.test").Contains("alpha.test"), "the name should start on its own certificate");

            Assert.Throws<ArgumentNullException>(
                () => engine.ReplaceCertificates(new QuicCertificate(cert, key)),
                "named host");

            // Refused means unchanged: the engine still answers for the name it was serving.
            Assert.True(Ask(udpPort, "named.test").Contains("alpha.test"),
                "a refused rotation must leave the table exactly as it was");

            // And stating the table - even to keep it identical - is accepted.
            engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
            {
                ["named.test"] = new(alpha, alphaKey),
            });

            Assert.True(Ask(udpPort, "named.test").Contains("alpha.test"),
                "restating the table should keep the name served");
        });

        runner.Test("rotate/quic: an empty host table is how you ASK to serve only the default", () =>
        {
            // The other half of the refusal above: dropping every name is a legitimate thing to
            // want, so it has to remain expressible - it just has to be said out loud.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("named.test", alpha, alphaKey);

            int udpPort = Serve(engine);
            Assert.True(Ask(udpPort, "named.test").Contains("alpha.test"), "the name should start on its own certificate");

            engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>());

            Assert.True(Ask(udpPort, "named.test").Contains("localhost"),
                "with the table emptied on purpose, the name falls back to the default certificate");
        });

        runner.Test("rotate/quic: a name can be added to a serving engine", () =>
        {
            // AddHost refuses once the engine is serving, because it edits the generation in force.
            // This is the supported way to get the same result, and the reason that refusal is not
            // a dead end.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            int udpPort = Serve(engine);

            Assert.True(Ask(udpPort, "alpha.test").Contains("localhost"),
                "before the rotation the name is unknown and gets the default");

            engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
            {
                ["alpha.test"] = new(alpha, alphaKey),
            });

            Assert.True(Ask(udpPort, "alpha.test").Contains("alpha.test"),
                "a name added by a rotation should be served");
        });

        runner.Test("rotate/quic: a rotation that cannot be built leaves the old certificates serving", () =>
        {
            (string cert, string key) = TestCert.Ensure();

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            int udpPort = Serve(engine);

            Assert.Throws<InvalidOperationException>(
                () => engine.ReplaceCertificates(new QuicCertificate("/nonexistent/new.crt", "/nonexistent/new.key")),
                "could not replace the certificates");

            Assert.True(Ask(udpPort, "localhost").Contains("localhost"),
                "and the engine should still serve the certificate it had");
        });

        runner.Test("rotate/quic: one bad host leaves the whole rotation unapplied", () =>
        {
            // All or nothing on purpose: half a renewal is a server serving a mixture nobody chose.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string beta, string betaKey) = TestCert.EnsureNamed("beta.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("alpha.test", alpha, alphaKey);

            int udpPort = Serve(engine);

            bool threw = false;

            try
            {
                engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
                {
                    ["alpha.test"] = new(beta, betaKey),
                    ["broken.test"] = new("/nonexistent/b.crt", "/nonexistent/b.key"),
                });
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            Assert.True(threw, "a rotation with an unreadable host should throw");

            Assert.True(Ask(udpPort, "alpha.test").Contains("alpha.test"),
                "and no part of it should have been applied");
        });

        runner.Test("rotate/quic: a key that does not match its certificate is refused", () =>
        {
            // BoringSSL cross-checks the pair when the key is installed, so the TCP side has always
            // refused this; picotls does not, so QUIC used to load it happily and then fail every
            // real client's handshake. That is the state a half-finished renewal leaves on disk,
            // and it is invisible to the in-tree client, which never checks a signature.
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string beta, string betaKey) = TestCert.EnsureNamed("beta.test");

            Assert.Throws<InvalidOperationException>(
                () => new QuicEngine(alpha, betaKey, cidLength: 8, alpn: ["h3"]).Dispose(),
                "engine init failed");

            var engine = TestServer.Own(new QuicEngine(alpha, alphaKey, cidLength: 8, alpn: ["h3"]));

            // Before serving, so the refusal is about the mismatched pair and not about the engine
            // already being live - which is what this asserted by accident until the reason was named.
            Assert.Throws<InvalidOperationException>(() => engine.AddHost("beta.test", beta, alphaKey),
                "could not serve 'beta.test'");

            int udpPort = Serve(engine);

            Assert.Throws<InvalidOperationException>(
                () => engine.ReplaceCertificates(new QuicCertificate(beta, alphaKey)),
                "could not replace the certificates");

            Assert.True(Ask(udpPort, "alpha.test").Contains("alpha.test"),
                "and the engine should still serve the pair it had");
        });

        runner.Test("rotate/quic: connections keep working across rotations under load", () =>
        {
            // The test that matters. Handshakes are running on the reactor while generations are
            // replaced underneath them; if a retired generation were freed while a handshake still
            // referenced it, this crashes the process rather than failing an assertion.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string beta, string betaKey) = TestCert.EnsureNamed("beta.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("alpha.test", alpha, alphaKey);

            int udpPort = Serve(engine);

            using var stop = new CancellationTokenSource();
            int completed = 0;
            Exception? failure = null;

            var load = Task.Run(() =>
            {
                try
                {
                    while (!stop.IsCancellationRequested)
                    {
                        using var client = new H3TestClient("127.0.0.1", udpPort) { ServerName = "alpha.test" };

                        client.Connect();
                        if (!client.CompleteHandshake(timeoutMs: 3000))
                        {
                            continue;
                        }

                        (int status, _) = client.Get("/", timeoutMs: 3000);
                        if (status == 200)
                        {
                            Interlocked.Increment(ref completed);
                        }
                    }
                }
                catch (Exception e)
                {
                    failure = e;
                }
            });

            for (int i = 0; i < 12; i++)
            {
                engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
                {
                    ["alpha.test"] = i % 2 == 0 ? new(beta, betaKey) : new(alpha, alphaKey),
                });

                Thread.Sleep(40);
            }

            stop.Cancel();
            load.Wait(TimeSpan.FromSeconds(15));

            Assert.True(failure is null, $"a handshake failed while certificates were being replaced: {failure}");
            Assert.True(completed > 0, "no request completed during the rotations");
        });

        runner.Test("rotate/quic: renewing a certificate does not drop mutual TLS", () =>
        {
            // The carry-over of the client verifier into each new generation is the most
            // security-critical line of the rotation path: get it wrong and renewing a certificate
            // quietly opens the port. Nothing exercised it until this.
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string beta, string betaKey) = TestCert.EnsureNamed("beta.test");

            var engine = TestServer.Own(new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true));
            engine.AddHost("alpha.test", alpha, alphaKey);

            int udpPort = ServeIdentity(engine);

            engine.ReplaceCertificates(new QuicCertificate(serverCert, serverKey), new Dictionary<string, QuicCertificate>
            {
                ["alpha.test"] = new(beta, betaKey),
            });

            // Still demanded, on the default and on the named host.
            Assert.True(Status(udpPort, null, null, "localhost") != 200,
                "a client with no certificate must still be refused after a rotation");
            Assert.True(Status(udpPort, null, null, "alpha.test") != 200,
                "and refused on a named host too");

            // Still validated against the same anchors.
            Assert.True(Status(udpPort, rogueCert, rogueKey, "alpha.test") != 200,
                "a certificate from another CA must still be refused after a rotation");

            // And the trusted client still gets in, and is still named.
            using var good = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey) { ServerName = "alpha.test" };
            good.Connect();
            Assert.True(good.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = good.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alice"), $"the identity should survive a rotation, got: {body}");
        });

        runner.Test("rotate/quic: trust anchors are re-read, so who may connect can be changed", () =>
        {
            // The TCP side's "rotate: trust anchors are re-read", on the same fixture: the client,
            // the server certificate and the CA stay exactly the same, and the only thing that
            // changes is whether the anchor file names the intermediate the chain needs.
            (string anchorsWithIntermediate, _, string clientCert, string clientKey) = TestCert.EnsureChainedClientCert();
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            string anchors = Path.Combine(Path.GetTempPath(), $"ioxide-quic-rotate-anchors-{Environment.ProcessId}.pem");
            File.WriteAllText(anchors, File.ReadAllText(ca));   // the root alone

            try
            {
                var engine = TestServer.Own(new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                    clientCaPemPath: anchors, requireClientCertificate: true));
                int udpPort = ServeIdentity(engine);

                Assert.True(Status(udpPort, clientCert, clientKey, "localhost") != 200,
                    "a leaf whose issuer is not anchored should not be served");

                File.WriteAllText(anchors, File.ReadAllText(anchorsWithIntermediate));
                engine.ReplaceCertificates(new QuicCertificate(serverCert, serverKey));

                Assert.Equal(200, Status(udpPort, clientCert, clientKey, "localhost"));
            }
            finally
            {
                File.Delete(anchors);
            }
        });

        runner.Test("rotate/quic: an anchor file emptied under a rotation stops admitting anyone", () =>
        {
            // The direction revocation needs: the anchor file loses the CA that issued the client,
            // and the rotation has to apply that rather than keep serving whoever was admissible
            // when the engine was built.
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey, _, _)
                = TestCert.EnsureMutualTls();
            (string unrelated, _) = TestCert.EnsureNamed("not-the-client-ca.test");

            string anchors = Path.Combine(Path.GetTempPath(), $"ioxide-quic-revoke-anchors-{Environment.ProcessId}.pem");
            File.WriteAllText(anchors, File.ReadAllText(ca));

            try
            {
                var engine = TestServer.Own(new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                    clientCaPemPath: anchors, requireClientCertificate: true));
                int udpPort = ServeIdentity(engine);

                Assert.Equal(200, Status(udpPort, clientCert, clientKey, "localhost"));

                // Still a valid anchor file, just not one that admits this client.
                File.WriteAllText(anchors, File.ReadAllText(unrelated));
                engine.ReplaceCertificates(new QuicCertificate(serverCert, serverKey));

                Assert.True(Status(udpPort, clientCert, clientKey, "localhost") != 200,
                    "the client's issuer was removed from the anchors and the rotation should have applied it");
            }
            finally
            {
                File.Delete(anchors);
            }
        });

        runner.Test("rotate/quic: an anchor file that no longer loads fails the rotation and keeps the anchors", () =>
        {
            // Read again means it can fail again. A bundle a rotation cannot load must fail that
            // rotation the way a bad certificate does - not publish a generation with no anchors.
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();

            string anchors = Path.Combine(Path.GetTempPath(), $"ioxide-quic-broken-anchors-{Environment.ProcessId}.pem");
            File.WriteAllText(anchors, File.ReadAllText(ca));

            try
            {
                var engine = TestServer.Own(new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                    clientCaPemPath: anchors, requireClientCertificate: true));
                int udpPort = ServeIdentity(engine);

                File.WriteAllText(anchors, "not a certificate\n");
                Assert.Throws<InvalidOperationException>(
                    () => engine.ReplaceCertificates(new QuicCertificate(serverCert, serverKey)),
                    "client CA");

                Assert.Equal(200, Status(udpPort, clientCert, clientKey, "localhost"));
                Assert.True(Status(udpPort, rogueCert, rogueKey, "localhost") != 200,
                    "the anchors kept after a failed rotation must still refuse a stranger");
            }
            finally
            {
                File.Delete(anchors);
            }
        });

        runner.Test("rotate/quic: anchors given as PEM text survive a rotation unchanged", () =>
        {
            // Text is data: every generation reads the same anchors from it, so a rotation neither
            // drops nor changes them.
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey,
             string rogueCert, string rogueKey) = TestCert.EnsureMutualTls();

            var engine = TestServer.Own(new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                requireClientCertificate: true, clientCaPem: File.ReadAllText(ca)));
            int udpPort = ServeIdentity(engine);

            engine.ReplaceCertificates(new QuicCertificate(serverCert, serverKey));

            Assert.Equal(200, Status(udpPort, clientCert, clientKey, "localhost"));
            Assert.True(Status(udpPort, rogueCert, rogueKey, "localhost") != 200,
                "a certificate from another CA must still be refused after a rotation");
        });

        runner.Test("rotate/quic: requiring a client certificate without anchors is refused", () =>
        {
            // Otherwise the engine asks every client for a certificate, turns away the ones that
            // have none, and accepts whatever the rest send - a port that looks authenticated and
            // is not. The TCP side has always refused this combination.
            (string cert, string key) = TestCert.Ensure();

            bool refused = false;

            try
            {
                var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"],
                    requireClientCertificate: true));
            }
            catch (ArgumentException)
            {
                refused = true;
            }

            Assert.True(refused,
                "requiring a client certificate with nothing to validate it against should be refused");
        });

        runner.Test("rotate/quic: rotations from several threads all take effect", () =>
        {
            // Two rotations racing each other used to be able to publish generations pointing at
            // the same predecessor, which dropped one of them: its certificates were never freed
            // and one of the two renewals silently did nothing.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string beta, string betaKey) = TestCert.EnsureNamed("beta.test");

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("alpha.test", alpha, alphaKey);

            int udpPort = Serve(engine);

            Exception? failure = null;

            Parallel.For(0, 4, i =>
            {
                try
                {
                    for (int n = 0; n < 15; n++)
                    {
                        engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
                        {
                            ["alpha.test"] = i % 2 == 0 ? new(beta, betaKey) : new(alpha, alphaKey),
                        });
                    }
                }
                catch (Exception e)
                {
                    failure = e;
                }
            });

            Assert.True(failure is null, $"a concurrent rotation failed: {failure}");

            // Whatever the last writer installed, the engine still serves one of the two and works.
            string subject = Ask(udpPort, "alpha.test");
            Assert.True(subject.Contains("alpha.test") || subject.Contains("beta.test"),
                $"the engine should still serve a certificate for the name, got: {subject}");
        });

        runner.Test("rotate/quic: a validating client accepts the renewed certificate", () =>
        {
            // Driven by curl, which checks the chain and the name - so this says the renewed
            // certificate is one a real client will take, not merely that the bytes changed.
            (string ca, string alphaCert, string alphaKey) = TestCert.EnsureNamedFromCa("alpha.test");
            (_, string betaCert, string betaKey) = TestCert.EnsureNamedFromCa("beta.test");
            (string cert, string key) = TestCert.Ensure();

            var engine = TestServer.Own(new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]));
            engine.AddHost("alpha.test", alphaCert, alphaKey);

            int udpPort = Serve(engine);

            (int before, _, string beforeErr) = CurlH3.Get("alpha.test", udpPort, ca);
            Assert.True(before == 0, $"alpha.test should verify before the rotation: {beforeErr}");

            // Renew alpha onto beta's material: the name is no longer covered, so a client that
            // checks must now refuse it - which is what proves the swap actually took effect.
            engine.ReplaceCertificates(new QuicCertificate(cert, key), new Dictionary<string, QuicCertificate>
            {
                ["alpha.test"] = new(betaCert, betaKey),
            });

            (int after, _, _) = CurlH3.Get("alpha.test", udpPort, ca);
            Assert.True(after != 0,
                "after the rotation alpha.test is served beta's certificate, which does not cover that name - a validating client must refuse it");

            // beta.test was never registered, so the default certificate answers it - and the
            // default does not cover that name, so a client that validates must refuse.
            (int beta, _, _) = CurlH3.Get("beta.test", udpPort, ca);
            Assert.True(beta != 0, "an unregistered name is answered with the default certificate, which a validating client must refuse");
        }, skip: !CurlH3.Available);
    }

    private static int Serve(QuicEngine engine)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static _ => new Nghttp3Response { Body = "ok"u8.ToArray() }));

        return udpPort;
    }

    /// <summary>Serves the client's verified identity, so "some certificate got in" can be told
    /// apart from "the one we trusted got in".</summary>
    private static int ServeIdentity(QuicEngine engine)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                _ => new Nghttp3Response
                {
                    Body = System.Text.Encoding.ASCII.GetBytes((conn as QuicEngineConnection)?.PeerSubject ?? "anonymous"),
                }));

        return udpPort;
    }

    /// <summary>The status a client gets, presenting the given certificate (or none) for a name.</summary>
    private static int Status(int udpPort, string? certPath, string? keyPath, string serverName)
    {
        using H3TestClient client = certPath is null
            ? new H3TestClient("127.0.0.1", udpPort) { ServerName = serverName }
            : new H3TestClient("127.0.0.1", udpPort, certPath, keyPath!) { ServerName = serverName };

        client.Connect();
        client.CompleteHandshake(timeoutMs: 3000);

        (int status, _) = client.Get("/", timeoutMs: 3000);
        return status;
    }

    /// <summary>The subject of the certificate served for one name.</summary>
    private static string Ask(int udpPort, string serverName)
    {
        using var client = new H3TestClient("127.0.0.1", udpPort)
        {
            ServerName = serverName,
            RecordServerCertificate = true,
        };

        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), $"handshake for '{serverName}' did not complete");

        client.Get("/", timeoutMs: 5000);
        return client.ServerCertificateSubject();
    }
}
