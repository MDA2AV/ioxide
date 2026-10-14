using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// What a rotation accepts. A renewal races a writer, so half-written and structurally odd PEMs are
/// the ordinary input, not the exotic one.
/// </summary>
/// <remarks>
/// Every test here drives a client that VALIDATES - a private one, minting its own root so it can
/// trust exactly that and nothing else. That is the whole point of the file: <see cref="TlsService"/>
/// promises that "nothing is published unless all of it built... a failed renewal is a server that
/// kept working", and only a client that builds a path to a root can tell a published set that
/// works from one that merely handshakes. A test that accepts any certificate would pass on every
/// case below, including the one that is broken.
///
/// The material is a real two-link chain (root -> intermediate -> leaf) because that is what the
/// interesting inputs need: a bundle can only be torn between two blocks if it has two.
/// </remarks>
internal static class RotationIntegrityTests
{
    private const string Host = "torn.rotate.test";

    /// <summary>Minted once: four RSA keys per chain, and every test wants the same chain.</summary>
    private static readonly Lazy<Fixture> Material = new(Mint, LazyThreadSafetyMode.ExecutionAndPublication);

    public static void Register(Runner runner)
    {
        RegisterTornBundle(runner);
        RegisterOtherOddShapes(runner);
    }

    private static void RegisterTornBundle(Runner runner)
    {
        runner.Test("control: a rotation given the whole bundle serves a chain a validating client accepts", () =>
        {
            // The control for everything below, and it earns its place twice over: it proves the
            // minted chain is one a real client will build a path through, and it proves the
            // validating client used by the rest of the file says yes to something.
            Fixture material = Material.Value;
            (TlsService service, int port) = Serve(material.Leaf + material.Intermediate, material.Key);

            Verdict before = Validate(port, material);
            Assert.True(before.Served, $"the full bundle should be served as it stands: {before.Why}");

            service.ReplaceCertificates(new TlsCertificate
            {
                CertificatePem = material.Leaf + material.Intermediate,
                KeyPem = material.Key,
            });

            Verdict after = Validate(port, material);
            Assert.True(after.Served, $"the same bundle rotated in should still be served: {after.Why}");
            Assert.True(after.Subject.Contains(Host),
                $"the certificate served should be the minted leaf, got [{after.Subject}]");
            Assert.True(after.Body.Contains("ok"), $"the connection should answer a request: [{after.Body}]");
        });

        runner.Test("rotate: a bundle torn mid-block is refused when it comes from a path", () =>
        {
            // The same bytes as the pending test below, handed over as a file. OpenSSL's own chain
            // loader stops on the unterminated block and says so, which is what the guarantee reads
            // like when it holds: the rotation throws, and the old certificates keep serving.
            Fixture material = Material.Value;
            (TlsService service, int port) = Serve(material.Leaf + material.Intermediate, material.Key);

            RefusedRotationKeepsServing(service, port, material, new TlsCertificate
            {
                CertificatePath = material.TornPath,
                KeyPath = material.KeyPath,
            }, because: "BAD_END_LINE");
        });

        runner.Test("rotate: a bundle torn mid-block is refused as PEM text too, not published as its leaf alone", () =>
        {
            // A renewal caught mid-write: the leaf is complete, the intermediate has a BEGIN and no
            // END. Handed over as a path this is refused (the test above). Handed over as PEM text,
            // the chain loop reads the leaf, fails on the torn block, treats that failure as the end
            // of the data, and publishes a set with no chain in it at all.
            //
            // Nothing says so. ReplaceCertificates returns, the server handshakes, and every client
            // that checks gets as far as the leaf and has nothing to reach its issuer with - which
            // is the failure mode a renewal is least able to survive, because the operator's own
            // check ("did the rotation throw?") says it went fine.
            Fixture material = Material.Value;
            (TlsService service, int port) = Serve(material.Leaf + material.Intermediate, material.Key);

            Verdict before = Validate(port, material);
            Assert.True(before.Served, $"the full bundle should be served before anything is rotated: {before.Why}");

            try
            {
                service.ReplaceCertificates(new TlsCertificate
                {
                    CertificatePem = material.Leaf + Tear(material.Intermediate),
                    KeyPem = material.Key,
                });
            }
            catch (Exception)
            {
                // The guarantee kept: nothing was published, so the old set is still what answers.
                // Deliberately any exception - what this asserts is the end state, not the wording.
            }

            // Not a dead port and not the wrong server: whatever is there is still handing out this
            // leaf. So what the validating client is about to object to can only be the chain.
            Assert.True(Client.ServerCertificateSubject(port, Host).Contains(Host),
                "the server should still be serving the minted leaf after the rotation attempt");

            Verdict after = Validate(port, material);
            Assert.True(after.Served,
                "a rotation given a bundle torn mid-block must leave the server serving a chain a "
                + $"validating client accepts, but that client now gets: {after.Why}");
        });
    }

    private static void RegisterOtherOddShapes(Runner runner)
    {
        runner.Test("rotate: an empty certificate file is refused", () =>
        {
            // The other half of the race: the writer has created the file and written nothing yet.
            Fixture material = Material.Value;
            (TlsService service, int port) = Serve(material.Leaf + material.Intermediate, material.Key);

            RefusedRotationKeepsServing(service, port, material, new TlsCertificate
            {
                CertificatePath = material.EmptyPath,
                KeyPath = material.KeyPath,
            }, because: "NO_START_LINE");
        });

        runner.Test("rotate: a certificate file that is valid PEM but holds only a key is refused", () =>
        {
            // Structurally fine, and the two paths swapped by hand. Nothing in it is a certificate,
            // so it must not be taken for one.
            Fixture material = Material.Value;
            (TlsService service, int port) = Serve(material.Leaf + material.Intermediate, material.Key);

            RefusedRotationKeepsServing(service, port, material, new TlsCertificate
            {
                CertificatePath = material.KeyPath,
                KeyPath = material.KeyPath,
            }, because: "NO_START_LINE");
        });

        runner.Test("rotate: a bundle in the wrong order is refused, because the key does not match the block that leads it", () =>
        {
            // Intermediate first, leaf second - a bundle assembled the wrong way round. It is caught
            // by the key check rather than by anything reading the chain, which is worth stating: it
            // holds only because the leading block belongs to a different key.
            Fixture material = Material.Value;
            (TlsService service, int port) = Serve(material.Leaf + material.Intermediate, material.Key);

            RefusedRotationKeepsServing(service, port, material, new TlsCertificate
            {
                CertificatePem = material.Intermediate + material.Leaf,
                KeyPem = material.Key,
            }, because: "do not go together");
        });
    }

    /// <summary>
    /// A rotation that must throw, followed by the half of the guarantee that is easy to forget:
    /// the service is still serving what it was, to a client that checks.
    /// </summary>
    private static void RefusedRotationKeepsServing(TlsService service, int port, Fixture material,
        TlsCertificate candidate, string because)
    {
        Verdict before = Validate(port, material);
        Assert.True(before.Served, $"the full bundle should be served before anything is rotated: {before.Why}");

        Assert.Throws<IOException>(() => service.ReplaceCertificates(candidate), because);

        Verdict after = Validate(port, material);
        Assert.True(after.Served,
            $"a refused rotation must leave the old certificates serving, but a validating client got: {after.Why}");
    }

    private static (TlsService Service, int Port) Serve(string certificatePem, string keyPem)
    {
        TlsService? service = null;
        int port = TestServer.Start(Handlers.TlsSendFirst, r => service = TlsService.Start(r, new TlsOptions
        {
            CertificatePem = certificatePem,
            KeyPem = keyPem,
        }));

        return (service!, port);
    }

    /// <summary>What a client that validates makes of this server.</summary>
    /// <param name="ChainSent">
    /// How many certificates the server sent beside the leaf, for the message when this goes wrong -
    /// zero is the whole symptom of a bundle that lost its chain.
    /// </param>
    private readonly record struct Verdict(bool Served, string Why, string Subject, string Body, int ChainSent);

    /// <summary>
    /// One request, from a client that trusts the fixture's root and NOTHING else - no machine
    /// store, so the only way this connection can succeed is the server sending a chain that
    /// reaches that root, and the name on the leaf matching the one asked for.
    /// </summary>
    private static Verdict Validate(int port, Fixture material, int timeoutMs = 6000)
    {
        using X509Certificate2 root = X509Certificate2.CreateFromPem(material.Root);
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        SslPolicyErrors errors = SslPolicyErrors.None;
        X509ChainStatusFlags status = 0;
        int sent = -1;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, chain, policyErrors) =>
        {
            errors = policyErrors;

            if (chain is not null)
            {
                // What the peer put on the wire, which SslStream stages here before it builds.
                sent = chain.ChainPolicy.ExtraStore.Count;

                foreach (X509ChainStatus entry in chain.ChainStatus)
                {
                    status |= entry.Status;
                }
            }

            return policyErrors == SslPolicyErrors.None;
        });

        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        policy.CustomTrustStore.Add(root);

        try
        {
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = Host,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateChainPolicy = policy,
            });
        }
        catch (Exception e)
        {
            return new Verdict(false, $"{errors} / {status} ({e.GetType().Name}, {sent} chain certs sent)",
                "<none>", "", sent);
        }

        // Handshaking is not being served. The request is what proves the connection the rotation
        // published is usable, rather than merely openable.
        Client.Send(ssl, "/");
        (int statusCode, string body) = Client.ReadResponse(ssl);

        return new Verdict(statusCode == 200, $"HTTP {statusCode}", ssl.RemoteCertificate?.Subject ?? "<none>",
            body, sent);
    }

    /// <summary>The chain and the files cut from it, all minted for this file alone.</summary>
    private sealed record Fixture(string Root, string Intermediate, string Leaf, string Key,
        string KeyPath, string TornPath, string EmptyPath);

    /// <summary>
    /// root -> intermediate -> leaf, so that dropping the intermediate is something a client can
    /// actually notice. Private rather than a shared fixture: nothing else needs this shape, and a
    /// chain that only this file uses cannot be quietly changed by a test in another suite.
    /// </summary>
    private static Fixture Mint()
    {
        // One window for the whole chain: a leaf issued a second after its issuer can outlive it,
        // which .NET refuses outright.
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);

        using RSA rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=ioxide rotation-integrity root", rootKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notBefore.AddYears(3));

        using RSA intermediateKey = RSA.Create(2048);
        var intermediateRequest = new CertificateRequest("CN=ioxide rotation-integrity intermediate",
            intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intermediateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 intermediate = intermediateRequest.Create(root, notBefore, notBefore.AddYears(2), Serial());
        using X509Certificate2 issuer = intermediate.CopyWithPrivateKey(intermediateKey);

        using RSA leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest($"CN={Host}", leafKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var alternativeNames = new SubjectAlternativeNameBuilder();
        alternativeNames.AddDnsName(Host);
        leafRequest.CertificateExtensions.Add(alternativeNames.Build());
        leafRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));   // serverAuth
        using X509Certificate2 leaf = leafRequest.Create(issuer, notBefore, notBefore.AddYears(1), Serial());

        string rootPem = root.ExportCertificatePem() + "\n";
        string intermediatePem = intermediate.ExportCertificatePem() + "\n";
        string leafPem = leaf.ExportCertificatePem() + "\n";
        string keyPem = leafKey.ExportPkcs8PrivateKeyPem() + "\n";

        // Per process, because two suites running side by side must not write each other's files.
        string dir = Path.Combine(Path.GetTempPath(), $"ioxide-rotation-integrity-{Environment.ProcessId}");
        Directory.CreateDirectory(dir);

        string keyPath = Path.Combine(dir, "leaf.key");
        string tornPath = Path.Combine(dir, "torn.pem");
        string emptyPath = Path.Combine(dir, "empty.pem");

        File.WriteAllText(keyPath, keyPem);
        File.WriteAllText(tornPath, leafPem + Tear(intermediatePem));
        File.WriteAllText(emptyPath, "");

        return new Fixture(rootPem, intermediatePem, leafPem, keyPem, keyPath, tornPath, emptyPath);
    }

    private static byte[] Serial()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;   // a positive DER integer
        return serial;
    }

    /// <summary>
    /// A PEM block cut off part way through: a BEGIN line, some of the base64, and no END - which
    /// is what a reader sees of a block the renewal process is still writing.
    /// </summary>
    private static string Tear(string pem)
    {
        string[] lines = pem.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return string.Join('\n', lines.Take(Math.Max(2, lines.Length / 2))) + "\n";
    }
}
