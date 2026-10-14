using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// The PEM dialects a real deployment actually hands the library. Every other fixture in the suite
/// is written by the same few lines of .NET - PKCS#8, LF endings, no preamble - so nothing here
/// said whether ioxide accepts a key exported by openssl, a file that has been through Windows, or
/// a certificate pasted out of a tool that prints the human-readable form above it.
///
/// These are compatibility questions, not correctness ones: each asserts what the library DOES, so
/// that a change to it is a decision rather than an accident.
/// </summary>
internal static class FormatTests
{
    public static void Register(Runner runner)
    {
        // Shapes that must simply work. All of them are ordinary output from ordinary tools.
        (TestCert.PemShape Shape, string What)[] served =
        [
            (TestCert.PemShape.Pkcs1Key, "a PKCS#1 key - \"BEGIN RSA PRIVATE KEY\", what openssl genrsa still writes"),
            (TestCert.PemShape.CrlfEndings, "CRLF line endings - a file that has been through Windows"),
            (TestCert.PemShape.LeadingText, "a certificate with the human-readable dump above it, as openssl x509 -text prints"),
            (TestCert.PemShape.EcKey, "an EC certificate and key rather than RSA"),
        ];

        foreach ((TestCert.PemShape shape, string what) in served)
        {
            runner.Test($"format: {what}", () =>
            {
                (string certPath, string keyPath) = TestCert.EnsureServerCert(shape);

                int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = certPath,
                    KeyPath = keyPath,
                }));

                (int status, string body) = Client.GetTls(port, "/");
                Assert.Equal(200, status);
                Assert.Equal("tls-ok", body);
            });
        }

        runner.Test("format: a UTF-8 BOM ahead of the PEM is accepted", () =>
        {
            // Editors and secret stores add one silently, and it is invisible in every tool that
            // shows the file. Measured rather than assumed: OpenSSL's PEM reader skips it and the
            // certificate loads, so this records that as the behaviour. If a future version stops
            // skipping it, this test turns the change into a decision instead of a support ticket.
            (string certPath, string keyPath) = TestCert.EnsureServerCert(TestCert.PemShape.Utf8Bom);

            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath = keyPath,
            }));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        });

        runner.Test("format: the same certificate served from memory behaves as it does from a path", () =>
        {
            // TlsOptions documents the two sources as equivalent, and one of them had already
            // drifted: the PEM-text trust-anchor route silently truncated a bundle the file route
            // refused. This pins the server-certificate pair the same way.
            (string certPath, string keyPath) = TestCert.EnsureServerCert(TestCert.PemShape.Plain);

            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePem = File.ReadAllText(certPath),
                KeyPem = File.ReadAllText(keyPath),
            }));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        });

        runner.Test("format: a key of a different ALGORITHM to the certificate is refused at startup", () =>
        {
            // OpenSSL let an EC key land beside an RSA certificate without complaint: the server
            // started, and every handshake afterwards failed with no shared cipher. That is what an
            // operator moving a server from RSA to EC and updating one of the two files produces.
            (string certPath, _) = TestCert.EnsureServerCert(TestCert.PemShape.Plain);
            (_, string ecKey) = TestCert.EnsureServerCert(TestCert.PemShape.EcKey);

            Assert.Throws<Exception>(
                () => TestServer.Start(Handlers.Tls, r => TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = certPath,
                    KeyPath = ecKey,
                })),
                "do not go together");
        });

        runner.Test("format: two unrelated RSA halves are refused too", () =>
        {
            // Same algorithm, different key: refused with the same reason as the case above.
            (string certPath, _) = TestCert.EnsureServerCert(TestCert.PemShape.Plain);
            (_, string otherKey) = TestCert.EnsureNamed("mismatch.test");

            Assert.Throws<Exception>(
                () => TestServer.Start(Handlers.Tls, r => TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = certPath,
                    KeyPath = otherKey,
                })),
                "do not go together");
        });

    }
}
