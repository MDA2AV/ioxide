using epoxide;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// Mutual-TLS configurations that must be REFUSED when the service starts.
/// </summary>
/// <remarks>
/// Split from <see cref="MutualTlsTests"/>, which is about which clients get in. These are about a
/// service that should never have started: requiring a client certificate with nothing to validate
/// it against, naming two anchor sources, an anchor file that cannot be read, a bundle with a
/// corrupt block in the middle.
///
/// They matter more than the count suggests, because the failure they prevent is silent and points
/// the wrong way. A port that asks every client for a certificate and then accepts whatever it is
/// sent looks authenticated in every log and is not; a trust bundle that stopped loading halfway
/// refuses clients whose only fault is being issued by an anchor further down the file. Each test
/// asserts on the REASON in the message, because a port already in use or a reactor that died on
/// the way up would otherwise report as the refusal being tested.
/// </remarks>
internal static class MutualTlsConfigTests
{
    public static void Register(Runner runner)
    {
        RegisterConfigurationErrors(runner);
    }

    private static void RegisterConfigurationErrors(Runner runner)
    {
        runner.Test("mtls: a trust bundle with a corrupt block is refused, not silently truncated", () =>
        {
            // ClientCaPath and ClientCaPem are documented as equivalent in what they trust. They
            // were not: the file route refuses such a bundle outright, while the PEM-text route
            // read until it stopped and kept whatever came BEFORE the bad block - so every client
            // issued by a later anchor was refused, with nothing said server-side. Failing closed
            // is not the same as failing loudly, and an operator has no way to see the difference.
            (string ca, _, _, _, _, _, _) = TestCert.EnsureMutualTls();

            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = TestCert.Ensure().CertPath,
                KeyPath = TestCert.Ensure().KeyPath,
                ClientCaPem = BundleWithCorruptMiddle(ca),
                RequireClientCertificate = true,
            }, "malformed"), "a bundle with a corrupt block should be refused at startup");
        });

        runner.Test("mtls: requiring a certificate without anchors is refused", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();

            // Nothing to validate against: this would refuse every client sending none and accept
            // anything from one that sends something - the opposite of what it reads as.
            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath = keyPath,
                RequireClientCertificate = true,
            }, "RequireClientCertificate needs trust anchors"),
                "RequireClientCertificate without anchors must be rejected");
        });

        runner.Test("mtls: two client CA sources are refused", () =>
        {
            (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = serverCert,
                KeyPath = serverKey,
                ClientCaPath = ca,
                ClientCaPem = File.ReadAllText(ca),
            }, "At most one client CA source"),
                "ClientCaPath and ClientCaPem together must be rejected");
        });

        runner.Test("mtls: the common name is reported exactly, not as part of a rendered subject", () =>
        {
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey, _, _)
                = TestCert.EnsureMutualTls();

            int port = TestServer.Start(TlsHandlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = serverCert,
                KeyPath = serverKey,
                ClientCaPath = ca,
                RequireClientCertificate = true,
            }));

            (int status, string body) = Client.GetTlsClientCert(port, "/who", clientCert, clientKey);

            Assert.Equal(200, status);
            // Equality, not Contains: the value is meant to be compared whole.
            Assert.Equal("alice", body);
        });

        runner.Test("mtls: a subject crafted to look like another identity does not become one", () =>
        {
            // The reason PeerCommonName exists. The rendered subject escapes a literal '/' as
            // "\\/", which still CONTAINS '/', so this legitimately-issued certificate renders as
            //     /O=Acme\\/CN=admin.internal/CN=mallory
            // and satisfies Contains("/CN=admin.internal") while being an entirely different
            // principal. The structural CN is unmoved by any of that.
            (_, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();
            (string ca, string certPath, string keyPath) =
                TestCert.EnsureClientCertFromCa("O=Acme/CN=admin.internal, CN=mallory");

            int port = TestServer.Start(TlsHandlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = serverCert,
                KeyPath = serverKey,
                ClientCaPath = ca,
                RequireClientCertificate = true,
            }));

            (int status, string body) = Client.GetTlsClientCert(port, "/who", certPath, keyPath);

            Assert.Equal(200, status);
            Assert.Equal("mallory", body);
        });

        runner.Test("mtls: the rendered subject is the one that IS confusable", () =>
        {
            // The other half of the pair, asserted so the trap is a recorded fact rather than a
            // remark in a doc comment. If a future change makes the rendered form unambiguous this
            // test fails, and that is the moment to revisit what the docs promise.
            (_, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();
            (string ca, string certPath, string keyPath) =
                TestCert.EnsureClientCertFromCa("O=Acme/CN=admin.internal, CN=mallory");

            int port = TestServer.Start(TlsHandlers.TlsIdentity, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = serverCert,
                KeyPath = serverKey,
                ClientCaPath = ca,
                RequireClientCertificate = true,
            }));

            (int status, string body) = Client.GetTlsClientCert(port, "/who", certPath, keyPath);

            Assert.Equal(200, status);
            Assert.True(body.Contains("/CN=admin.internal"),
                $"expected the rendered subject to be substring-confusable, got: {body}");
        });

        runner.Test("mtls: an unreadable client CA fails at startup", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();

            Assert.True(StartFails(new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath = keyPath,
                ClientCaPath = "/nonexistent/ca.pem",
            }, "/nonexistent/ca.pem"),
                "a missing CA file must be reported at startup");
        });
    }

    /// <summary>
    /// A trust bundle whose MIDDLE block is corrupt: a real anchor, then a well-formed PEM envelope
    /// around bytes that are not a certificate, then a second real anchor. The shape a secrets
    /// store or a partial write produces, and the one where "read until the reader stops" quietly
    /// trusts a narrower set than the operator wrote.
    /// </summary>
    private static string BundleWithCorruptMiddle(string caPath)
    {
        string anchor = File.ReadAllText(caPath).Trim();
        return anchor + "\n"
            + "-----BEGIN CERTIFICATE-----\n"
            + "bm90IGEgY2VydGlmaWNhdGU=\n"
            + "-----END CERTIFICATE-----\n"
            + anchor + "\n";
    }

    /// <summary>
    /// Whether starting with these options was refused FOR THE STATED REASON. The reason matters:
    /// without it this also passes when the port was already bound or the reactor died on the way
    /// up, and reports that as the configuration refusal it was looking for.
    /// </summary>
    private static bool StartFails(TlsOptions options, string because)
    {
        try
        {
            TestServer.Start(EmptyHandler, r => TlsService.Start(r, options));
            return false;
        }
        catch (Exception e)
        {
            return e.Message.Contains(because);
        }
    }

    private static Task EmptyHandler(Reactor reactor, TcpConnection connection)
    {
        connection.DecRef();
        return Task.CompletedTask;
    }
}
