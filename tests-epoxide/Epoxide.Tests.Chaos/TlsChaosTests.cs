using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// TLS chaos: the assaults that only exist once a handshake sits under the HTTP - a corrupted record
/// after a good handshake, cleartext sprayed at a TLS port, handshakes that die halfway, and records
/// fragmented across TCP. The server is the shared <see cref="TlsHandlers.Tls"/> (BoringSSL both
/// ways, the default); every test ends by proving a clean TLS request still returns "tls-ok".
/// </summary>
internal static class TlsChaosTests
{
    private static int StartTls()
    {
        (string cert, string key) = TestCert.Ensure();
        var options = new TlsOptions { CertificatePath = cert, KeyPath = key };
        return TestServer.Start(TlsHandlers.Tls, r => TlsService.Start(r, options));
    }

    private static void AssertHealthy(int port)
    {
        (int status, string body) = Client.GetTls(port, "/");
        Assert.Equal(200, status);
        Assert.Equal("tls-ok", body);
    }

    public static void Register(Runner runner)
    {
        runner.Test("tls: garbage after a valid handshake faults cleanly, server keeps serving", () =>
        {
            int port = StartTls();
            Client.SendTlsGarbageAfterHandshake(port);
            AssertHealthy(port);
        });

        runner.Test("tls: cleartext sprayed at a TLS port is rejected, server survives", () =>
        {
            int port = StartTls();

            using (var c = new TcpClient())
            {
                c.Connect("127.0.0.1", port);
                // A plaintext HTTP request reads as a bogus TLS record (content type 'G' = 0x47):
                // the handshake must fail, not crash the reactor.
                c.GetStream().Write("GET / HTTP/1.1\r\nHost: chaos\r\n\r\n"u8);
                c.GetStream().Flush();
                Thread.Sleep(200);
            }

            AssertHealthy(port);
        });

        runner.Test("tls: handshakes that die halfway don't wedge the server", () =>
        {
            int port = StartTls();

            // A TLS handshake record header (type 22, TLS 1.0 record version) claiming 0x2a bytes,
            // then truncated and closed - the accept loop must recover, not leak or stall.
            byte[] partialHello = [0x16, 0x03, 0x01, 0x00, 0x2a, .. Enumerable.Repeat((byte)0x00, 10)];
            for (int i = 0; i < 20; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                c.GetStream().Write(partialHello);
                c.GetStream().Flush();
            }

            AssertHealthy(port);
        });

        runner.Test("tls: full handshake then immediate close (no request)", () =>
        {
            int port = StartTls();

            for (int i = 0; i < 10; i++)
            {
                using var client = new TcpClient();
                client.Connect("127.0.0.1", port);
                using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
                ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    EnabledSslProtocols = SslProtocols.Tls13,
                });
                // Handshake done; drop the connection without ever sending a request.
            }

            AssertHealthy(port);
        });

        runner.Test("tls: a byte-split TLS record still yields exactly one response", () =>
        {
            int port = StartTls();
            Assert.Equal(1, Client.CountTlsResponsesForSplitRequest(port, "/", chunk: 1));
            AssertHealthy(port);
        });

        runner.Test("tls: a request split across many TLS records yields one response", () =>
        {
            int port = StartTls();
            Assert.Equal(1, Client.CountTlsResponsesForMultiRecordRequest(port, "/", records: 5));
            AssertHealthy(port);
        });
    }
}
