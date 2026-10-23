using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Ioxide.Tests;

/// <summary>A throwaway self-signed cert for the TLS test, written to PEM (ioxide.tls wants paths).</summary>
public static class TestCert
{
    // ---- fixture plumbing -----------------------------------------------------------------------
    //
    // Five suites share these directories and nothing stopped two of them minting the same fixture
    // at the same time. Two processes interleaving their writes to ca.crt and ca.key leaves a
    // certificate from one generation beside a key from another: every handshake using them fails,
    // and it looks like a bug in whatever was under test rather than in the fixture. Writes were
    // not atomic either, so a reader could see a half-written PEM. And the cache never expired,
    // while leaves are minted for a year - so a checkout older than that fails every positive test
    // and passes every negative one, which is the worse direction.

    /// <summary>
    /// Serialises fixture creation across processes. Held for the whole check-and-mint, so the
    /// check cannot be won by one process while another is still writing the files it is checking.
    /// </summary>
    private static FileStream Lock(string dir, string name)
    {
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, $".{name}.lock");

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (attempt < 1_200)
            {
                Thread.Sleep(50);   // another suite is minting the same fixture
            }
        }
    }

    /// <summary>Publishes a file in one step, so no reader ever sees a partial PEM.</summary>
    private static void WriteAtomic(string path, string contents)
    {
        string temp = $"{path}.{Environment.ProcessId}.tmp";
        File.WriteAllText(temp, contents);
        File.Move(temp, path, overwrite: true);   // same directory, so this is a rename
    }

    /// <summary>
    /// Whether a cached fixture can still be used: every file present, and the certificate inside
    /// its validity window. Expiry matters because these are cached indefinitely - without the
    /// check, a machine that ran the suite over a year ago fails every test that expects a
    /// handshake to succeed, and passes every test that expects one to fail.
    /// </summary>
    private static bool Fresh(string certPath, params string[] alsoRequired)
    {
        if (!File.Exists(certPath) || alsoRequired.Any(path => !File.Exists(path)))
        {
            return false;
        }

        try
        {
            using X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            DateTime now = DateTime.Now;
            return cert.NotBefore <= now && now < cert.NotAfter;
        }
        catch
        {
            return false;   // truncated or not a certificate at all: mint it again
        }
    }

    /// <summary>
    /// Whether a cached spec fixture still has the validity state it was minted for.
    ///
    /// These are cached by spec rather than freshness, since most are deliberately invalid. That is
    /// safe one way only: an EXPIRED certificate stays expired, but a NOT YET VALID one becomes
    /// valid when its notBefore arrives - so a "not valid yet" fixture starts being served the next
    /// day and the test reports a product bug that does not exist.
    /// </summary>
    private static bool StillMatchesSpec(string certPath, ClientCertSpec spec)
    {
        try
        {
            using X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            DateTime now = DateTime.Now;

            bool shouldBeStarted = spec.NotBefore <= TimeSpan.Zero;
            bool shouldBeUnexpired = spec.NotAfter > TimeSpan.Zero;

            return cert.NotBefore <= now == shouldBeStarted
                && now < cert.NotAfter == shouldBeUnexpired;
        }
        catch
        {
            return false;   // truncated or not a certificate at all: mint it again
        }
    }

    /// <summary>
    /// A CA, a server certificate and two client certificates - one the CA signed, one a DIFFERENT
    /// CA signed. mTLS cannot be tested without all four: proving a good certificate is let in says
    /// nothing unless a bad one is turned away.
    /// </summary>
    public static (string CaPath, string ServerCert, string ServerKey,
                   string ClientCert, string ClientKey,
                   string RogueCert, string RogueKey) EnsureMutualTls()
    {
        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-mtls");
        Directory.CreateDirectory(dir);

        string ca = Path.Combine(dir, "ca.crt");
        string serverCert = Path.Combine(dir, "server.crt");
        string serverKey = Path.Combine(dir, "server.key");
        string clientCert = Path.Combine(dir, "client.crt");
        string clientKey = Path.Combine(dir, "client.key");
        string rogueCert = Path.Combine(dir, "rogue.crt");
        string rogueKey = Path.Combine(dir, "rogue.key");

        using FileStream guard = Lock(dir, "mtls");

        // Every file, not a sample of them. The old check tested four of the eight, so a partially
        // evicted cache returned paths to files that were not there.
        if (Fresh(serverCert, ca, Path.Combine(dir, "ca.key"), serverKey, clientCert, clientKey, rogueCert, rogueKey))
        {
            return (ca, serverCert, serverKey, clientCert, clientKey, rogueCert, rogueKey);
        }

        // ONE window for the whole set. Taking UtcNow per certificate lets a leaf be issued a
        // second after its CA and therefore outlive it, which .NET refuses outright - a flake that
        // only fires when the two calls straddle a second boundary.
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset caNotAfter = notBefore.AddYears(2);
        DateTimeOffset leafNotAfter = notBefore.AddYears(1);   // strictly inside the CA's window

        using var caKey = System.Security.Cryptography.RSA.Create(2048);
        var caRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=ioxide test CA", caKey, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
        using var caCert = caRequest.CreateSelfSigned(notBefore, caNotAfter);
        WriteAtomic(ca, caCert.ExportCertificatePem());

        // The CA's key too, so a test can issue a certificate for a name of its own later -
        // EnsureNamedFromCa signs with it, and a chain needs the issuer that a client will anchor to.
        WriteAtomic(Path.Combine(dir, "ca.key"), caKey.ExportPkcs8PrivateKeyPem());

        Sign(caCert, "CN=localhost", serverCert, serverKey, server: true, notBefore, leafNotAfter);
        Sign(caCert, "CN=alice", clientCert, clientKey, server: false, notBefore, leafNotAfter);

        // A second CA the server has never heard of, so its certificates must be refused.
        using var rogueKeyPair = System.Security.Cryptography.RSA.Create(2048);
        var rogueCa = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=rogue CA", rogueKeyPair, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        rogueCa.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
        using var rogueCaCert = rogueCa.CreateSelfSigned(notBefore, caNotAfter);
        Sign(rogueCaCert, "CN=mallory", rogueCert, rogueKey, server: false, notBefore, leafNotAfter);

        return (ca, serverCert, serverKey, clientCert, clientKey, rogueCert, rogueKey);

        static void Sign(System.Security.Cryptography.X509Certificates.X509Certificate2 issuer,
            string subject, string certPath, string keyPath, bool server,
            DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            using var key = System.Security.Cryptography.RSA.Create(2048);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                subject, key, System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);

            if (server)
            {
                var names = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
                names.AddDnsName("localhost");
                names.AddIpAddress(System.Net.IPAddress.Loopback);
                request.CertificateExtensions.Add(names.Build());
            }

            request.CertificateExtensions.Add(
                new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
                    [new System.Security.Cryptography.Oid(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")], false));

            byte[] serial = new byte[8];
            System.Security.Cryptography.RandomNumberGenerator.Fill(serial);
            using var signed = request.Create(issuer, notBefore, notAfter, serial);

            WriteAtomic(certPath, signed.ExportCertificatePem());
            WriteAtomic(keyPath, key.ExportPkcs8PrivateKeyPem());
        }
    }

    /// <summary>
    /// A self-signed certificate for one name, so SNI selection has something to tell apart. The
    /// subject carries the name, which is what a test asserts on after the handshake.
    /// </summary>
    public static (string CertPath, string KeyPath) EnsureNamed(string host)
    {
        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-tls");
        Directory.CreateDirectory(dir);

        // Distinct hosts must not share a filename. Substituting the awkward characters alone maps
        // alpha.test and alpha_test onto one pair of files, and whichever is asked for second
        // silently gets the other's certificate - a wrong-certificate result inside the very
        // fixture meant to prove certificates are chosen correctly. The hash keeps them apart.
        string safe = host.Replace('*', '_').Replace('.', '_');
        string tag = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(host)))[..8];

        string certPath = Path.Combine(dir, $"sni-{safe}-{tag}.crt");
        string keyPath = Path.Combine(dir, $"sni-{safe}-{tag}.key");

        // Both halves, not just the certificate: a leftover certificate beside a missing key is
        // reused forever and every test fails at startup on a path that looks perfectly fine.
        using FileStream guard = Lock(dir, "named");

        if (!Fresh(certPath, keyPath))
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            request.CertificateExtensions.Add(names.Build());

            using X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

            WriteAtomic(certPath, cert.ExportCertificatePem());
            WriteAtomic(keyPath, rsa.ExportPkcs8PrivateKeyPem());
        }

        return (certPath, keyPath);
    }

    /// <summary>
    /// A certificate for one name, signed by the same CA <see cref="EnsureMutualTls"/> mints, with
    /// that name as a SAN. Unlike <see cref="EnsureNamed"/>'s self-signed pair, this is something a
    /// REAL client can validate: a chain back to an anchor it can be given, and a name to match.
    /// </summary>
    /// <remarks>
    /// Which is the point. ioxide's own QUIC client authenticates nothing, so a test driven by it
    /// can only ever ask "which certificate came back". Handing these to a client that checks makes
    /// the assertion "would anyone actually accept this", and that is a different question.
    /// </remarks>
    /// <summary>
    /// A second, DIFFERENT certificate for the same name, signed by the same CA - what a renewal
    /// produces. Distinct key and serial, identical subject and SAN, so a validating client accepts
    /// either and cannot tell which it got except by looking.
    /// </summary>
    public static (string CaPath, string CertPath, string KeyPath) EnsureRenewedFromCa(string host)
        => EnsureNamedFromCa(host, "renewed");

    public static (string CaPath, string CertPath, string KeyPath) EnsureNamedFromCa(string host)
        => EnsureNamedFromCa(host, "");

    private static (string CaPath, string CertPath, string KeyPath) EnsureNamedFromCa(string host, string variant)
    {
        (string ca, _, _, _, _, _, _) = EnsureMutualTls();

        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-mtls");
        string tag = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(host + "\u0000" + variant)))[..8];

        string certPath = Path.Combine(dir, $"host-{tag}.crt");
        string keyPath = Path.Combine(dir, $"host-{tag}.key");

        using FileStream guard = Lock(dir, "from-ca");

        if (Fresh(certPath, keyPath))
        {
            return (ca, certPath, keyPath);
        }

        // The CA's own key is not kept, so the CA is re-derived here from the same material rather
        // than loaded - EnsureMutualTls writes only the certificate.
        using X509Certificate2 caCert = X509Certificate2.CreateFromPemFile(
            Path.Combine(dir, "ca.crt"), Path.Combine(dir, "ca.key"));

        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = notBefore.AddYears(1);

        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(host);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

        byte[] serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using X509Certificate2 signed = request.Create(caCert, notBefore, notAfter, serial);

        WriteAtomic(certPath, signed.ExportCertificatePem());
        WriteAtomic(keyPath, key.ExportPkcs8PrivateKeyPem());

        return (ca, certPath, keyPath);
    }

    /// <summary>
    /// A CLIENT certificate from the mutual-TLS CA with a subject of the caller's choosing, so a
    /// test can mint an identity that is legitimately issued and yet renders into something
    /// awkward - a name containing the very separator the rendered DN uses, for instance.
    /// </summary>
    /// <param name="subject">Full distinguished name, e.g. <c>O=Acme, CN=bob</c>.</param>
    public static (string CaPath, string CertPath, string KeyPath) EnsureClientCertFromCa(string subject)
    {
        (string ca, _, _, _, _, _, _) = EnsureMutualTls();

        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-mtls");
        string tag = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes("client\u0000" + subject)))[..8];

        string certPath = Path.Combine(dir, $"client-{tag}.crt");
        string keyPath = Path.Combine(dir, $"client-{tag}.key");

        using FileStream guard = Lock(dir, "from-ca");

        if (Fresh(certPath, keyPath))
        {
            return (ca, certPath, keyPath);
        }

        using X509Certificate2 caCert = X509Certificate2.CreateFromPemFile(
            Path.Combine(dir, "ca.crt"), Path.Combine(dir, "ca.key"));

        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = notBefore.AddYears(1);

        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));   // client auth

        byte[] serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using X509Certificate2 signed = request.Create(caCert, notBefore, notAfter, serial);

        WriteAtomic(certPath, signed.ExportCertificatePem());
        WriteAtomic(keyPath, key.ExportPkcs8PrivateKeyPem());

        return (ca, certPath, keyPath);
    }

    public static (string CertPath, string KeyPath) Ensure()
    {
        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-tls");
        Directory.CreateDirectory(dir);

        string certPath = Path.Combine(dir, "test.crt");
        string keyPath = Path.Combine(dir, "test.key");

        using FileStream guard = Lock(dir, "default");

        // Both halves and the validity window: the old check tested only the certificate, so a
        // missing key was cached forever and every suite failed at startup on a path that looked
        // perfectly fine.
        if (!Fresh(certPath, keyPath))
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // A subjectAltName, because client-side hostname verification checks that and only
            // falls back to the CN when no dNSName is present at all. Without it the certificate
            // is fine for a server that never gets verified and useless for testing a client that
            // does.
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            names.AddIpAddress(System.Net.IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());

            using X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

            WriteAtomic(certPath, cert.ExportCertificatePem());
            WriteAtomic(keyPath, rsa.ExportPkcs8PrivateKeyPem());
        }

        return (certPath, keyPath);
    }

    // ---- awkward certificates ---------------------------------------------------------------
    //
    // Everything above mints ONE clean shape: an in-date RSA leaf with the right EKU, a single CN,
    // a PKCS#8 key and LF line endings. That is why so little of the verification code is actually
    // pinned by the suite - a mutation that accepts an expired certificate, ignores the EKU, takes
    // the first CN instead of the last, or drops chain building survives every test here, because
    // no fixture can tell the difference.

    /// <summary>How a test wants a client certificate to be awkward.</summary>
    public sealed record ClientCertSpec
    {
        public string Subject { get; init; } = "CN=alice";

        /// <summary>Relative to now. Positive NotBefore = not yet valid; negative NotAfter = expired.</summary>
        public TimeSpan NotBefore { get; init; } = TimeSpan.FromDays(-1);
        public TimeSpan NotAfter { get; init; } = TimeSpan.FromDays(365);

        /// <summary>clientAuth by default; serverAuth is the one a client must NOT be accepted on.</summary>
        public string? ExtendedKeyUsage { get; init; } = "1.3.6.1.5.5.7.3.2";

        /// <summary>An EC key instead of RSA - a different signature algorithm on the wire.</summary>
        public bool EllipticCurve { get; init; }

        /// <summary>
        /// Names the CA as its issuer but is signed by a key that is not the CA's - the one shape here
        /// the CA never issued. A verifier that matched the issuer's NAME and stopped would build the
        /// chain to the anchor and accept it.
        /// </summary>
        public bool ForgedSignature { get; init; }

        // Unchanged for every spec without a forged signature, so the fixtures cached under it stay valid.
        internal string Tag => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{Subject}|{NotBefore}|{NotAfter}|{ExtendedKeyUsage}|{EllipticCurve}"
            + (ForgedSignature ? "|forged" : ""))))[..10];
    }

    /// <summary>
    /// A client certificate issued by the same CA <see cref="EnsureMutualTls"/> mints, shaped by
    /// <paramref name="spec"/>. Legitimately issued in every case - the point is that a correct
    /// server refuses it for a reason OTHER than its signature.
    /// </summary>
    public static (string CaPath, string CertPath, string KeyPath) EnsureClientCert(ClientCertSpec spec)
    {
        (string ca, _, _, _, _, _, _) = EnsureMutualTls();

        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-mtls");
        string certPath = Path.Combine(dir, $"spec-{spec.Tag}.crt");
        string keyPath = Path.Combine(dir, $"spec-{spec.Tag}.key");

        using FileStream guard = Lock(dir, "spec");

        // Not the Fresh() check - half of these are supposed to be outside their validity window.
        // StillMatchesSpec checks the weaker thing: that it still means what it was minted to mean.
        if (File.Exists(certPath) && File.Exists(keyPath) && StillMatchesSpec(certPath, spec))
        {
            return (ca, certPath, keyPath);
        }

        using X509Certificate2 caCert = X509Certificate2.CreateFromPemFile(
            Path.Combine(dir, "ca.crt"), Path.Combine(dir, "ca.key"));

        DateTimeOffset notBefore = DateTimeOffset.UtcNow + spec.NotBefore;
        DateTimeOffset notAfter = DateTimeOffset.UtcNow + spec.NotAfter;

        CertificateRequest request;
        AsymmetricAlgorithm key;
        if (spec.EllipticCurve)
        {
            ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            key = ec;
            request = new CertificateRequest(spec.Subject, ec, HashAlgorithmName.SHA256);
        }
        else
        {
            RSA rsa = RSA.Create(2048);
            key = rsa;
            request = new CertificateRequest(spec.Subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        try
        {
            if (spec.ExtendedKeyUsage is { } eku)
            {
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(eku)], false));
            }

            byte[] serial = new byte[8];
            RandomNumberGenerator.Fill(serial);

            // Signed through an explicit generator rather than Create(issuer, ...). That overload
            // derives the signature algorithm from the REQUEST's key, so an EC leaf issued by this
            // RSA CA is refused outright - which has nothing to do with what is being tested.
            using RSA caKey = caCert.GetRSAPrivateKey()!;
            using RSA? forger = spec.ForgedSignature ? RSA.Create(2048) : null;
            X509SignatureGenerator generator = X509SignatureGenerator.CreateForRSA(forger ?? caKey, RSASignaturePadding.Pkcs1);
            using X509Certificate2 signed = request.Create(
                caCert.SubjectName, generator, notBefore, notAfter, serial);

            WriteAtomic(certPath, signed.ExportCertificatePem());
            WriteAtomic(keyPath, key switch
            {
                RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
                ECDsa ec => ec.ExportPkcs8PrivateKeyPem(),
                _ => throw new InvalidOperationException("unreachable"),
            });
        }
        finally
        {
            key.Dispose();
        }

        return (ca, certPath, keyPath);
    }

    /// <summary>
    /// Root -> intermediate -> leaf. The returned anchor file holds BOTH the root and the
    /// intermediate, and the client presents the leaf alone.
    /// </summary>
    /// <remarks>
    /// Two things neither of which any other fixture covers. The leaf is not signed by the anchor
    /// the server was configured with, so it can only be accepted by building a chain - every other
    /// client certificate here is signed directly by the anchor, which a server that never chained
    /// at all would still accept. And the anchor file carries two certificates, so it also pins
    /// that a multi-certificate CA bundle is loaded in full rather than stopping at the first.
    /// </remarks>
    public static (string AnchorsPath, string IntermediatePath, string CertPath, string KeyPath) EnsureChainedClientCert()
    {
        (string ca, _, _, _, _, _, _) = EnsureMutualTls();

        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-mtls");
        string anchorsPath = Path.Combine(dir, "chain-anchors.pem");
        string intermediatePath = Path.Combine(dir, "chain-intermediate.crt");
        string certPath = Path.Combine(dir, "chained-client.crt");
        string keyPath = Path.Combine(dir, "chained-client.key");

        using FileStream guard = Lock(dir, "chain");

        if (Fresh(certPath, anchorsPath, intermediatePath, keyPath))
        {
            return (anchorsPath, intermediatePath, certPath, keyPath);
        }

        using X509Certificate2 root = X509Certificate2.CreateFromPemFile(
            Path.Combine(dir, "ca.crt"), Path.Combine(dir, "ca.key"));

        DateTimeOffset notBefore = root.NotBefore.ToUniversalTime();
        DateTimeOffset notAfter = notBefore.AddDays(200);

        using var intermediateKey = RSA.Create(2048);
        var intermediateRequest = new CertificateRequest(
            "CN=ioxide test intermediate", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));

        byte[] intermediateSerial = new byte[8];
        RandomNumberGenerator.Fill(intermediateSerial);
        using X509Certificate2 intermediate = intermediateRequest.Create(root, notBefore, notAfter, intermediateSerial);
        using X509Certificate2 intermediateWithKey = intermediate.CopyWithPrivateKey(intermediateKey);

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            "CN=chained-alice", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));

        byte[] leafSerial = new byte[8];
        RandomNumberGenerator.Fill(leafSerial);
        using X509Certificate2 leaf = leafRequest.Create(
            intermediateWithKey, notBefore, notAfter.AddDays(-1), leafSerial);

        WriteAtomic(anchorsPath, File.ReadAllText(ca).TrimEnd() + "\n" + intermediate.ExportCertificatePem() + "\n");
        WriteAtomic(intermediatePath, intermediate.ExportCertificatePem());
        WriteAtomic(certPath, leaf.ExportCertificatePem());
        WriteAtomic(keyPath, leafKey.ExportPkcs8PrivateKeyPem());

        return (anchorsPath, intermediatePath, certPath, keyPath);
    }

    /// <summary>How a test wants a server certificate's FILES to be awkward, rather than its content.</summary>
    public enum PemShape
    {
        /// <summary>PKCS#8 key, LF endings - what every other fixture writes.</summary>
        Plain,
        /// <summary>"BEGIN RSA PRIVATE KEY": the older PKCS#1 encoding, still what many tools emit.</summary>
        Pkcs1Key,
        /// <summary>CRLF line endings, which is what a file that has been through Windows looks like.</summary>
        CrlfEndings,
        /// <summary>A UTF-8 BOM ahead of the first BEGIN line, which editors add silently.</summary>
        Utf8Bom,
        /// <summary>Human-readable text before the certificate, as openssl x509 -text emits.</summary>
        LeadingText,
        /// <summary>An EC key and certificate rather than RSA.</summary>
        EcKey,
    }

    /// <summary>
    /// A self-signed server certificate written in a particular PEM dialect. These are the shapes a
    /// real deployment hands the library - exported by another tool, edited on another platform,
    /// pasted through a secrets store - and none of them were represented.
    /// </summary>
    public static (string CertPath, string KeyPath) EnsureServerCert(PemShape shape)
    {
        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-tls");
        string certPath = Path.Combine(dir, $"shape-{shape}.crt");
        string keyPath = Path.Combine(dir, $"shape-{shape}.key");

        using FileStream guard = Lock(dir, "shape");

        if (Fresh(certPath, keyPath))
        {
            return (certPath, keyPath);
        }

        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(System.Net.IPAddress.Loopback);

        string certPem;
        string keyPem;

        if (shape == PemShape.EcKey)
        {
            using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=localhost", ec, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(names.Build());
            using X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

            certPem = cert.ExportCertificatePem();
            keyPem = ec.ExportPkcs8PrivateKeyPem();
        }
        else
        {
            using RSA rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(names.Build());
            using X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

            certPem = cert.ExportCertificatePem();
            keyPem = shape == PemShape.Pkcs1Key ? rsa.ExportRSAPrivateKeyPem() : rsa.ExportPkcs8PrivateKeyPem();
        }

        switch (shape)
        {
            case PemShape.CrlfEndings:
                certPem = certPem.ReplaceLineEndings("\r\n");
                keyPem = keyPem.ReplaceLineEndings("\r\n");
                break;

            case PemShape.Utf8Bom:
                certPem = "\uFEFF" + certPem;
                keyPem = "\uFEFF" + keyPem;
                break;

            case PemShape.LeadingText:
                certPem = $"Certificate:\n    Issuer: CN=localhost\n    Subject: CN=localhost\n{certPem}";
                break;
        }

        WriteAtomic(certPath, certPem);
        WriteAtomic(keyPath, keyPem);
        return (certPath, keyPath);
    }

}
