using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// SNI configurations that must be REFUSED when the service starts, rather than accepted into a
/// server that then behaves in some unintended way.
/// </summary>
/// <remarks>
/// Split from <see cref="SniTests"/>, which is about which certificate a name is answered with.
/// These are about a table that should never have been built: a blank name, an entry naming no
/// certificate or two, a file that cannot be read, the same host twice. The failure mode they guard
/// is the one this library treats as the worst kind - a configuration accepted at startup whose
/// effect only shows up as a client being served the wrong certificate, or none.
///
/// Each asserts on the REASON in the message, not merely that starting threw: without that, a port
/// already in use or a reactor that died on the way up reports as the refusal being tested.
/// </remarks>
internal static class SniConfigTests
{
    public static void Register(Runner runner)
    {
        runner.Test("sni: a blank host name is refused", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["  "] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
                },
            }, "A blank host cannot be asked for by SNI"), "a blank name cannot be asked for and should be refused");
        });

        runner.Test("sni: a host entry naming no certificate source is refused", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (_, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            // Neither source is as wrong as both, and reads as an entry someone forgot to finish.
            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["alpha.test"] = new() { KeyPath = alphaKey },
                },
            }, "Exactly one certificate source for 'alpha.test'"), "a host entry with no certificate should be refused");
        });

        runner.Test("sni: a host entry naming two key sources is refused", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["alpha.test"] = new()
                    {
                        CertificatePath = alphaCert,
                        KeyPath = alphaKey,
                        KeyPem = File.ReadAllText(alphaKey),
                    },
                },
            }, "Exactly one key source for 'alpha.test'"), "two key sources for one host should be refused");
        });

        runner.Test("sni: an unreadable host certificate fails at startup", () =>
        {
            (string cert, string key) = TestCert.Ensure();

            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["alpha.test"] = new() { CertificatePath = "/nonexistent/alpha.crt", KeyPath = key },
                },
            }, "alpha.test"), "a host certificate that cannot be read should fail at startup, not at a handshake");
        });

        runner.Test("sni: two entries for the same host are refused", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            string refusal = "";

            try
            {
                TestServer.Start(Handlers.TlsSendFirst, r => TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = cert,
                    KeyPath = key,
                    CertificatesByHost = new Dictionary<string, TlsCertificate>
                    {
                        // Distinct keys to the dictionary, the same host to the handshake. Only the
                        // first would ever be served, so the second is a certificate that silently
                        // never answers - refused rather than shadowed.
                        ["alpha.test"] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
                        ["ALPHA.test"] = new() { CertificatePath = cert, KeyPath = key },
                    },
                }));
            }
            catch (Exception e)
            {
                refusal = e.Message;
            }

            Assert.True(refusal.Contains("Two certificates for the same host"),
                $"two entries folding to one name should be refused at startup; got: {refusal}");
        });

        runner.Test("sni: a host entry naming two certificate sources is refused", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            string refusal = "";

            try
            {
                TestServer.Start(Handlers.TlsSendFirst, r => TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = cert,
                    KeyPath = key,
                    CertificatesByHost = new Dictionary<string, TlsCertificate>
                    {
                        // Both a path and text: two answers to one question.
                        ["alpha.test"] = new()
                        {
                            CertificatePath = alphaCert,
                            CertificatePem = File.ReadAllText(alphaCert),
                            KeyPath = alphaKey,
                        },
                    },
                }));
            }
            catch (Exception e)
            {
                // The reactor raises it on its own thread and the harness reports the failure to
                // start, so what is asserted is the reason rather than the exception type.
                refusal = e.Message;
            }

            Assert.True(refusal.Contains("Exactly one certificate source for 'alpha.test'"),
                $"naming two certificate sources for one host should be refused at startup; got: {refusal}");
        });

        // The table is matched exactly, so each of these was built, reported in ServerNames, and
        // never served (#207).
        runner.Test("sni: a host name no client can ask for is refused, naming it", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            foreach ((string host, string reason) in Unservable)
            {
                Assert.True(StartFails(new TlsOptions
                {
                    CertificatePath = cert,
                    KeyPath = key,
                    CertificatesByHost = new Dictionary<string, TlsCertificate>
                    {
                        [host] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
                    },
                }, $"The host '{host}' cannot be asked for by SNI: {reason}"),
                    $"'{host}' cannot be asked for by SNI ({reason}) and should be refused at startup");
            }
        });

        // The control: refused for what they are, not for looking unusual. Starting at all is the
        // assertion for the 255-byte name, which SslStream will not send (its IDN mapping stops at 253).
        runner.Test("sni: control: an A-label name and a name of exactly 255 bytes are accepted", () =>
        {
            (string cert, string key) = TestCert.Ensure();
            (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            int port = TestServer.Start(Handlers.TlsSendFirst, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["xn--bcher-kva.test"] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
                    [Longest] = new() { CertificatePath = alphaCert, KeyPath = alphaKey },
                },
            }));

            string subject = Client.ServerCertificateSubject(port, "xn--bcher-kva.test");
            Assert.True(subject.Contains("alpha.test"), $"the A-label name was answered with {subject}");
        });
    }

    /// <summary>Four 63-byte labels: 255 bytes, the longest server name BoringSSL accepts.</summary>
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

    /// <summary>
    /// Whether starting with these options was refused for the stated reason. The reactor raises on
    /// its own thread and the harness reports the failure to start, so the assertion is on the
    /// reason rather than on the exception type.
    /// </summary>
    private static bool StartFails(TlsOptions options, string because)
    {
        try
        {
            TestServer.Start(Handlers.TlsSendFirst, r => TlsService.Start(r, options));
            return false;
        }
        catch (Exception e)
        {
            return e.Message.Contains(because);
        }
    }
}
