using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The verified client certificate itself, for whatever a name does not answer - a SAN, an
/// extension, a fingerprint. TCP's <c>TlsSession.PeerCertificateDer</c> hands it over; these hold
/// <see cref="QuicEngineConnection.PeerCertificateDer"/> to the same terms: the certificate the
/// client presented, only once it verified, and as a snapshot that outlives the connection.
/// </summary>
internal static class QuicPeerCertificateTests
{
    public static void Register(Runner runner)
    {
        runner.Test("mtls/quic: the handler can read the client's certificate, and it is the one presented", () =>
        {
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey, _, _)
                = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);
            int udpPort = Serve(engine);

            (int status, string body) = Get(udpPort, clientCert, clientKey);
            Assert.Equal(200, status);

            // Byte for byte the presented certificate, and one .NET reads the same name from.
            Assert.Equal($"{Thumbprint(clientCert)} alice", body);
        });

        runner.Test("mtls/quic optional: a client that presents no certificate has none to read", () =>
        {
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: false);
            int udpPort = Serve(engine);

            (int status, string body) = Get(udpPort, null, null);
            Assert.Equal(200, status);
            Assert.Equal("none", body);
        });

        runner.Test("mtls/quic: without client anchors no certificate is read, even one the client has", () =>
        {
            // Nothing asks for it, so nothing verified it - and only a verified certificate counts.
            (string serverCert, string serverKey) = TestCert.Ensure();
            (_, _, _, string clientCert, string clientKey, _, _) = TestCert.EnsureMutualTls();

            using var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"]);
            int udpPort = Serve(engine);

            (int status, string body) = Get(udpPort, clientCert, clientKey);
            Assert.Equal(200, status);
            Assert.Equal("none", body);
        });

        runner.Test("mtls/quic: the certificate is a snapshot that outlives the connection", () =>
        {
            // TCP's PeerCertificateDer is captured at the handshake and kept; PeerSubject on QUIC
            // reads through the native connection and goes null with it. This one must be TCP's kind.
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey, _, _)
                = TestCert.EnsureMutualTls();

            QuicEngineConnection? served = null;
            var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true);

            try
            {
                int udpPort = Serve(engine, conn => served = conn);
                Assert.Equal(200, Get(udpPort, clientCert, clientKey).Status);
            }
            finally
            {
                // Stopping the reactor tears its connections down and joins its thread, so what is
                // read below is the connection after its native half was freed.
                TestServer.StopAll();
                engine.Dispose();
            }

            Assert.True(served is not null, "the handler never saw the connection");
            Assert.True(served!.PeerSubject is null,
                "the native connection should be gone, or this proves nothing about outliving it");
            Assert.Equal($"{Thumbprint(clientCert)} alice", Describe(served.PeerCertificateDer));
        });
    }

    private static int Serve(QuicEngine engine, Action<QuicEngineConnection>? onAccept = null)
    {
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) =>
            {
                var quic = (QuicEngineConnection)conn;
                onAccept?.Invoke(quic);

                // Read inside the REQUEST handler, not at accept: the connection callback fires
                // before the handshake finishes, so the certificate is not there yet.
                return new Nghttp3Connection(conn).RunBufferedAsync(
                    _ => new Nghttp3Response { Body = Encoding.ASCII.GetBytes(Describe(quic.PeerCertificateDer)) });
            });

        return udpPort;
    }

    private static (int Status, string Body) Get(int udpPort, string? certPath, string? keyPath)
    {
        using H3TestClient client = certPath is null
            ? new H3TestClient("127.0.0.1", udpPort)
            : new H3TestClient("127.0.0.1", udpPort, certPath, keyPath!);

        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client.Get("/", timeoutMs: 5000);
    }

    // The certificate's SHA-256 and the simple name .NET reads from it, or "none".
    private static string Describe(byte[]? der)
    {
        if (der is null)
        {
            return "none";
        }

        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
        return $"{Convert.ToHexString(SHA256.HashData(der))} {certificate.GetNameInfo(X509NameType.SimpleName, false)}";
    }

    private static string Thumbprint(string certPath)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificateFromFile(certPath);
        return Convert.ToHexString(SHA256.HashData(certificate.RawData));
    }
}
