using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// TLS over the raw connection: the BoringSSL handshake, then the default BoringSSL write path -
/// plus the kTLS TX opt-in, so the handoff keeps coverage now that no test hits it by default.
/// </summary>
internal static class TlsTests
{
    public static void Register(Runner runner, bool ktls)
    {
        runner.Test("tls: handshake + request (default, BoringSSL both ways)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
            int port = TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));
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
            int port = TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));
            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        });

        // The opt-in path: EnableTx programs the keys, Write switches to bare slab writes, and
        // close_notify goes out as a kTLS control send. None of that executes under the default,
        // so this round-trip is its entire coverage.
        runner.Test("tls: kTLS TX opt-in round-trip", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = true };
            int port = TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));
            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("tls-ok", body);
        }, skip: !ktls);

        runner.Test("tls: kTLS TX fragmented request gets exactly one response", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = true };

            int port = TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));

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

            int port = TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));

            int responses = Client.CountTlsResponsesForSplitRequest(port, "/", chunk: 1);
            Assert.Equal(1, responses);
        });

        runner.Test("tls raw: a request split across 3 TLS records still gets one response", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));

            int responses = Client.CountTlsResponsesForMultiRecordRequest(port, "/", records: 3);
            Assert.Equal(1, responses);
        });
    }
}
