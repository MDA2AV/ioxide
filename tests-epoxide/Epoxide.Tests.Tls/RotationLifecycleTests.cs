using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using epoxide;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// Rotation as an operation on a RUNNING server, rather than as a call that returns.
/// </summary>
/// <remarks>
/// The cases here come from haproxy's <c>reg-tests/ssl</c> and nginx's <c>ssl_cache_reload.t</c>,
/// which are worth mining because both projects ship runtime certificate replacement and their
/// regression suites are a catalogue of the ways it goes wrong in production - including two
/// haproxy files named after escaped bugs.
///
/// What separates these from <c>RotationTests</c> is time. Those establish that a rotation changes
/// what the next handshake is served, which is the easy half; every one of them connects AFTER the
/// call returned. These ask what happens to a connection that was already up, to a file rewritten
/// underneath the server, and to a fleet of reactors where a rotation reached only some of them -
/// the situations a renewal actually lands in.
/// </remarks>
internal static class RotationLifecycleTests
{
    public static void Register(Runner runner)
    {
        RegisterLiveConnections(runner);
        RegisterFileShapes(runner);
        RegisterFleet(runner);
    }

    // ---- a connection that was already up ------------------------------------------------------

    private static void RegisterLiveConnections(Runner runner)
    {
        runner.Test("rotate: a connection established before a rotation keeps serving on what it authenticated", () =>
        {
            // The case the design's central promise is FOR. ReplaceCertificates keeps the contexts
            // it replaces rather than freeing them, and says why: a handshake may be between
            // reading a set and using what it found. Nothing tested the other half of that - a
            // connection that finished its handshake on the old certificate and is still sending
            // requests on it. Every existing rotation test connects after the call returned, so
            // the retained contexts were never actually depended upon by anything.
            (string cert, string key) = TestCert.Ensure();
            (_, string renewed, string renewedKey) = TestCert.EnsureRenewedFromCa("rotate-live.test");

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.Tls, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
            }));

            using var socket = new TcpClient();
            socket.Connect("127.0.0.1", port);
            socket.ReceiveTimeout = 6_000;
            socket.SendTimeout = 6_000;

            X509Certificate? presented = null;
            using var ssl = new SslStream(socket.GetStream(), false, (_, c, _, _) =>
            {
                presented = c;
                return true;
            });
            ssl.AuthenticateAsClient("localhost");

            Client.Send(ssl, "/before");
            (int firstStatus, _) = Client.ReadResponse(ssl);
            Assert.Equal(200, firstStatus);

            string before = presented?.Subject ?? "";
            Assert.True(before.Contains("localhost"), $"the connection should have authenticated the default certificate, got: {before}");

            service!.ReplaceCertificates(new TlsCertificate { CertificatePath = renewed, KeyPath = renewedKey });

            // The rotation landed - a NEW connection sees the new certificate. Without this the
            // test below would also pass against a rotation that silently did nothing.
            Assert.True(Client.ServerCertificateSubject(port, null).Contains("rotate-live.test"),
                "the rotation did not take effect for new connections, so nothing was rotated across");

            // And the connection that was already up is unaffected: same session, same certificate,
            // still answering. A rotation that tore this down would be an outage per renewal.
            Client.Send(ssl, "/after");
            (int secondStatus, string body) = Client.ReadResponse(ssl);

            Assert.Equal(200, secondStatus);
            Assert.Equal("tls-ok", body);
        });
    }

    // ---- the file underneath the server --------------------------------------------------------

    private static void RegisterFileShapes(Runner runner)
    {
        runner.Test("rotate: the same paths are re-read when the files are rewritten in place", () =>
        {
            // How renewal actually happens. certbot writes fullchain.pem and privkey.pem to the
            // SAME paths - often preserving the inode, and nginx's ssl_cache_reload.t goes out of
            // its way to preserve the mtime too - then signals. Every rotation test in this repo
            // hands ReplaceCertificates a DIFFERENT path, so nothing pins that passing the same
            // TlsCertificate twice re-reads it. A "skip unchanged paths" optimisation would break
            // exactly this and no test would notice.
            (string firstCert, string firstKey) = TestCert.EnsureNamed("inplace-one.test");
            (string secondCert, string secondKey) = TestCert.EnsureNamed("inplace-two.test");

            string dir = Path.Combine(Path.GetTempPath(), "epoxide-rotate-inplace");
            Directory.CreateDirectory(dir);
            string livePath = Path.Combine(dir, "live.crt");
            string liveKey = Path.Combine(dir, "live.key");

            File.Copy(firstCert, livePath, overwrite: true);
            File.Copy(firstKey, liveKey, overwrite: true);
            DateTime stamp = new(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(livePath, stamp);
            File.SetLastWriteTimeUtc(liveKey, stamp);

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.TlsSendFirst, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = livePath,
                KeyPath = liveKey,
            }));

            Assert.True(Client.ServerCertificateSubject(port, null).Contains("inplace-one.test"),
                "the server should start on the first certificate");

            // Rewritten in place, mtime pinned to the same value it already had.
            File.Copy(secondCert, livePath, overwrite: true);
            File.Copy(secondKey, liveKey, overwrite: true);
            File.SetLastWriteTimeUtc(livePath, stamp);
            File.SetLastWriteTimeUtc(liveKey, stamp);

            // The SAME TlsCertificate values - only the bytes behind them changed.
            service!.ReplaceCertificates(new TlsCertificate { CertificatePath = livePath, KeyPath = liveKey });

            Assert.True(Client.ServerCertificateSubject(port, null).Contains("inplace-two.test"),
                "a rotation given the same paths must re-read them: the file was rewritten in place "
                + "and the server is still serving the certificate it started with");
        });

        runner.Test("rotate: every PEM shape that starts a service also rotates into one", () =>
        {
            // haproxy issue #2265: a certificate shape the STARTUP loader accepted was refused by
            // the RUNTIME one, so a server that had booted for months could not be renewed - and
            // the operator saw a half-applied set rather than a clean failure. ioxide is
            // structurally immune, because BuildCertificates is the single builder for both paths,
            // but nothing pinned that property and a fast path added to ReplaceCertificates would
            // break it silently. FormatTests proves these shapes start; this proves they rotate.
            (string cert, string key) = TestCert.Ensure();

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.TlsSendFirst, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
            }));

            foreach (TestCert.PemShape shape in Enum.GetValues<TestCert.PemShape>())
            {
                (string shapeCert, string shapeKey) = TestCert.EnsureServerCert(shape);

                service!.ReplaceCertificates(new TlsCertificate
                {
                    CertificatePath = shapeCert,
                    KeyPath = shapeKey,
                });

                // Rotated AND serving: a set that built but cannot handshake is the failure this
                // is looking for, so the check has to reach the wire rather than stop at "no throw".
                string subject = Client.ServerCertificateSubject(port, null);
                Assert.True(subject.Length > 0,
                    $"the {shape} shape rotated in but the port then served nobody");
            }
        });

        runner.Test("rotate: a host entry whose key does not match its certificate is refused", () =>
        {
            // The QUIC engine refuses this at its constructor, AddHost and ReplaceCertificates
            // alike ("rotate/quic: a key that does not match its certificate is refused"). On TCP
            // the equivalent is reached only through the default certificate, by way of the
            // reversed-bundle case - a host ENTRY carrying a mismatched pair was never covered,
            // and SNI entries are built by a different function from the default.
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");
            (string betaCert, string betaKey) = TestCert.EnsureNamed("beta.test");

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.TlsSendFirst, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["alpha.test"] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
                },
            }));

            Assert.True(Client.ServerCertificateSubject(port, "alpha.test").Contains("alpha.test"),
                "the host should start on its own certificate");

            // alpha's certificate against beta's key: both valid, and not a pair.
            Assert.Throws<IOException>(
                () => service!.ReplaceCertificates(
                    new TlsCertificate { CertificatePath = cert, KeyPath = key },
                    new Dictionary<string, TlsCertificate>
                    {
                        ["alpha.test"] = new() { CertificatePath = alphaCert, KeyPath = betaKey },
                    }),
                // Named by the HOST, which is the part an operator needs: a fleet rotating twenty
                // names wants to know which entry is the bad pair, not merely that one of them is.
                "alpha.test");

            // Refused means unchanged, which is the half that keeps the check from being a way to
            // break a running server.
            Assert.True(Client.ServerCertificateSubject(port, "alpha.test").Contains("alpha.test"),
                "a refused rotation must leave the host serving what it was");
        });
    }

    // ---- more than one reactor -----------------------------------------------------------------

    private static void RegisterFleet(Runner runner)
    {
        runner.Test("rotate: a rotation that reaches only some reactors serves two certificates at once", () =>
        {
            // A TlsService belongs to ONE reactor, so a server with N of them holds N services and
            // a renewal has to visit every one. They share a port through SO_REUSEPORT, so which
            // reactor a client lands on is the kernel's choice - and a rotation that missed some
            // means the SAME name answers with two different certificates depending on where the
            // connection landed, with nothing to tell the operator.
            //
            // This is the production shape, and until now no TLS test ran more than one reactor:
            // every entry point in the harness pinned ReactorCount = 1. What is asserted is the
            // consequence rather than the mechanism - both certificates observed on one port.
            const int reactors = 4;

            (string cert, string key) = TestCert.Ensure();
            (_, string renewed, string renewedKey) = TestCert.EnsureRenewedFromCa("fleet-rotate.test");

            var services = new TlsService[reactors];
            var options = new TlsOptions { CertificatePath = cert, KeyPath = key };

            int port = TestServer.StartSharded(reactors,
                (_, r, conn) => TlsHandlers.TlsSendFirst(r, conn),
                (shard, r) => services[shard] = TlsService.Start(r, options));

            // Rotate ONE of the four, as a renewal script that iterated the wrong collection would.
            services[0].ReplaceCertificates(new TlsCertificate
            {
                CertificatePath = renewed,
                KeyPath = renewedKey,
            });

            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < 60 && seen.Count < 2; i++)
            {
                string subject = Client.ServerCertificateSubject(port, null);
                if (subject.Length > 0)
                {
                    seen.Add(subject.Contains("fleet-rotate.test") ? "renewed" : "original");
                }
            }

            Assert.True(seen.Contains("original") && seen.Contains("renewed"),
                "one port served only " + string.Join("/", seen) + " across 60 connections: a "
                + "partial rotation should be observable as two certificates on one name, and if "
                + "this stops being true the per-reactor model has changed");
        });

        runner.Test("control: rotating every reactor leaves only the new certificate", () =>
        {
            // The other half. Without this, the test above is satisfied by a fleet that always
            // serves two certificates - which would be a far worse bug and a green test.
            const int reactors = 4;

            (string cert, string key) = TestCert.Ensure();
            (_, string renewed, string renewedKey) = TestCert.EnsureRenewedFromCa("fleet-rotate.test");

            var services = new TlsService[reactors];
            var options = new TlsOptions { CertificatePath = cert, KeyPath = key };

            int port = TestServer.StartSharded(reactors,
                (_, r, conn) => TlsHandlers.TlsSendFirst(r, conn),
                (shard, r) => services[shard] = TlsService.Start(r, options));

            foreach (TlsService service in services)
            {
                service.ReplaceCertificates(new TlsCertificate
                {
                    CertificatePath = renewed,
                    KeyPath = renewedKey,
                });
            }

            for (int i = 0; i < 40; i++)
            {
                string subject = Client.ServerCertificateSubject(port, null);
                Assert.True(subject.Length == 0 || subject.Contains("fleet-rotate.test"),
                    $"a fully rotated fleet served the old certificate on connection {i}: {subject}");
            }
        });
    }
}
