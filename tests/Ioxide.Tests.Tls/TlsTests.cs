using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// TLS over the raw ring: the BoringSSL handshake, then the default BoringSSL write path - plus the
/// kTLS TX opt-in, so the handoff keeps coverage now that no test hits it by default.
/// </summary>
internal static class TlsTests
{
    public static void Register(Runner runner, bool ktls)
    {
        runner.Test("tls: handshake + request (default, BoringSSL both ways)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options));
            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        });

        runner.Test("tls: in-memory PEM options serve a request", () =>
        {
            // The same material the path route loads, handed over as text - the route a host takes
            // when its certificate lives in a store or an X509Certificate2, not on disk.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions
            {
                CertificatePem = File.ReadAllText(certPath),
                KeyPem = File.ReadAllText(keyPath),
            };
            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options));
            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        });

        // The opt-in path: EnableTx programs the keys, Write switches to bare slab writes, the
        // MSG_WAITALL flag is cleared, close_notify goes out as a kTLS control send. None of that
        // executes under the default any more, so this round-trip is its entire coverage.
        runner.Test("tls: kTLS TX opt-in round-trip", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = true };
            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options));
            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        }, skip: !ktls);

        runner.Test("tls: kTLS TX fragmented request gets exactly one response", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = true };

            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options));

            int responses = Client.CountTlsResponsesForSplitRequest(port, "/", chunk: 1);
            Assert.Equal(1, responses);
        }, skip: !ktls);

        runner.Test("tls raw: a fragmented request gets exactly one response", () =>
        {
            // The raw decrypt loop answers on "any plaintext arrived", not on "a request arrived".
            // TLS reassembly is fine either way - BoringSSL's BIO holds the partial record - but the
            // HTTP framing above it is the handler's job, and answering per decrypt means one
            // request split across recvs draws several responses.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options));

            int responses = Client.CountTlsResponsesForSplitRequest(port, "/", chunk: 1);
            Assert.Equal(1, responses);
        });

        runner.Test("tls raw: a request split across 3 TLS records still gets one response", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options));

            int responses = Client.CountTlsResponsesForMultiRecordRequest(port, "/", records: 3);
            Assert.Equal(1, responses);
        });

        // The handshake stages a whole flight before it flushes, so a flight past the slab grows it or spills.
        foreach (WriteOverflowStrategy overflow in new[] { WriteOverflowStrategy.Grow, WriteOverflowStrategy.Segmented })
        {
            runner.Test($"tls: a handshake flight larger than the write slab completes ({overflow})", () =>
            {
                TlsOptions options = LargeCertificate();
                var config = new ServerConfig
                {
                    RecvBufferSize = 4096,
                    RecvSlots = 256,
                    Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 8, RecvQueueEntries = 64, WriteOverflow = overflow },
                };

                int port = TestServer.StartConfigured(Handlers.Tls, config, r => TlsService.Start(r, options)).Port;

                (int status, string body) = Client.GetTls(port, "/");
                Assert.Equal(200, status);
                Assert.Equal("tls-ok", body);
            });
        }
    }

    // Enough subject alternative names to put the certificate alone past the 16 KiB slab.
    private static TlsOptions LargeCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        for (int i = 0; i < 1000; i++)
        {
            names.AddDnsName($"name-{i:D4}.large-flight.test");
        }
        request.CertificateExtensions.Add(names.Build());

        using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        Assert.True(cert.RawData.Length > 16 * 1024, $"the certificate is {cert.RawData.Length} bytes, not past the slab");

        return new TlsOptions { CertificatePem = cert.ExportCertificatePem(), KeyPem = rsa.ExportPkcs8PrivateKeyPem() };
    }
}
