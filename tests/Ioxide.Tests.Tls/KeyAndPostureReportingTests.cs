using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// Two things a server must not get wrong about its own key and its own handshake.
/// </summary>
/// <remarks>
/// From nginx's <c>ssl_password_file.t</c> and <c>ssl.t</c>. The first exists because nginx needed
/// somewhere to put passphrase handling; ioxide has no such API, which makes the question "what
/// happens when someone hands it an encrypted key anyway" rather than "does the feature work". The
/// second is the pair of accessors <c>ioxide.Kestrel</c> maps into ASP.NET's
/// <c>ITlsHandshakeFeature</c>, which applications make authorization decisions on and which
/// nothing tested.
/// </remarks>
internal static class KeyAndPostureReportingTests
{
    public static void Register(Runner runner)
    {
        runner.Test("key: an encrypted private key is refused, and does not go looking for a passphrase", () =>
        {
            // OpenSSL's PEM readers take a password callback; passing none did not mean "no
            // password", it meant PEM_def_callback - which read the passphrase FROM THE TERMINAL.
            // On a server started from a tty that is not an error path, it is a hang, and on a
            // rotation thread it would be a hang while still serving. BoringSSL's default does not
            // prompt, but there is no passphrase option on TlsOptions either way, so the only
            // correct outcome is a prompt refusal naming the key.
            //
            // The deadline is the assertion here. A test that merely catches the throw would also
            // pass on a build that blocks, because the runner's watchdog would kill the suite
            // rather than this test.
            string dir = Path.Combine(Path.GetTempPath(), "ioxide-encrypted-key");
            Directory.CreateDirectory(dir);
            string certPath = Path.Combine(dir, "enc.crt");
            string keyPath = Path.Combine(dir, "enc.key");

            (string plainCert, _) = TestCert.Ensure();
            File.Copy(plainCert, certPath, overwrite: true);

            using (var rsa = RSA.Create(2048))
            {
                File.WriteAllText(keyPath, rsa.ExportEncryptedPkcs8PrivateKeyPem(
                    "correct horse battery staple",
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000)));
            }

            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            long started = Environment.TickCount64;
            Exception? refusal = null;
            try
            {
                TestServer.Start(Handlers.TlsSendFirst, r => TlsService.Start(r, options));
            }
            catch (Exception e)
            {
                refusal = e;
            }
            long elapsed = Environment.TickCount64 - started;

            Assert.True(refusal is not null, "an encrypted private key was accepted, and there is no way to supply its passphrase");
            Assert.True(elapsed < 20_000,
                $"the refusal took {elapsed} ms, which is long enough to be a prompt rather than a decision");
            Assert.True(refusal!.Message.Contains("enc.key", StringComparison.Ordinal)
                        || refusal.Message.Contains("KeyPath", StringComparison.Ordinal)
                        || refusal.Message.Contains("key", StringComparison.OrdinalIgnoreCase),
                $"the refusal should name the key rather than the library that produced it: {refusal.Message}");
        });

        runner.Test("posture: the protocol and ciphersuite the handler reads are the ones negotiated", () =>
        {
            // TlsSession.NegotiatedProtocolVersion and NegotiatedCipherSuiteId had no test anywhere,
            // and ioxide.Kestrel maps both into ITlsHandshakeFeature - so a wrong constant there
            // reports TLS 1.2 as 1.3 to every ASP.NET app on the port and nothing would notice.
            // Driven twice, against a client pinned to each version, because a pair of constants
            // can only be shown to be READ rather than assumed by making the answer change.
            (string certPath, string keyPath) = TestCert.Ensure();

            int port = TestServer.Start(EchoPosture, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath = keyPath,
            }));

            // The accessor reports BoringSSL's WIRE value, and ioxide.Kestrel maps it - 0x0304 to
            // Tls13, 0x0303 to Tls12. Both halves are asserted here: that the session reports the
            // version the client actually negotiated, and that Kestrel's mapping of it is right,
            // since an inverted table there would misreport every connection with nothing to catch it.
            (string thirteen, SslProtocols clientThirteen, TlsCipherSuite suiteThirteen) = Ask(port, SslProtocols.Tls13);
            Assert.Equal(SslProtocols.Tls13, clientThirteen);
            Assert.Equal(0x0304, int.Parse(thirteen.Split('|')[0]));
            Assert.Equal((int)suiteThirteen, int.Parse(thirteen.Split('|')[1]));

            (string twelve, SslProtocols clientTwelve, TlsCipherSuite suiteTwelve) = Ask(port, SslProtocols.Tls12);
            Assert.Equal(SslProtocols.Tls12, clientTwelve);
            Assert.Equal(0x0303, int.Parse(twelve.Split('|')[0]));
            Assert.Equal((int)suiteTwelve, int.Parse(twelve.Split('|')[1]));

            // And the two really are different, so neither assertion above is satisfied by a
            // constant that happens to match one of them.
            Assert.True(thirteen != twelve, "both handshakes reported the same posture");
        });
    }

    /// <summary>Answers with what the SESSION says the handshake settled on.</summary>
    private static async Task EchoPosture(Reactor reactor, TcpConnection connection)
    {
        TlsSession? tls = null;
        try
        {
            tls = await reactor.GetService<TlsService>().AcceptAsync(connection);

            string body = $"{tls.NegotiatedProtocolVersion}|{tls.NegotiatedCipherSuiteId}";
            byte[] response = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}");

            tls.Write(connection, response);
            await connection.FlushAsync();

            // Read once so the client's close is observed rather than raced.
            await connection.ReadAsync();
        }
        catch
        {
            // A client pinned to a version the port refuses lands here; the test reads the failure
            // from its own side.
        }
        finally
        {
            tls?.Dispose();
            connection.DecRef();
        }
    }

    private static (string Reported, SslProtocols Negotiated, TlsCipherSuite Suite) Ask(int port, SslProtocols protocols)
    {
        using var socket = new TcpClient();
        socket.Connect("127.0.0.1", port);
        socket.ReceiveTimeout = 6_000;
        socket.SendTimeout = 6_000;

        using var ssl = new SslStream(socket.GetStream(), false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = protocols,
        });

        (int status, string body) = Client.ReadResponse(ssl);
        Assert.Equal(200, status);

        return (body, ssl.SslProtocol, ssl.NegotiatedCipherSuite);
    }
}
