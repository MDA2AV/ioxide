using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// How a peer's name is derived from its certificate: several common names, a very long DN, and
/// the difference between the rendered subject and the structural CN.
///
/// Every fixture here is a certificate the mutual-TLS CA legitimately signed and the server
/// legitimately accepted - the handshake completes and the chain validates in all of them. What is
/// under test is what the two accessors then SAY about the peer, which is the whole of what a
/// handler has to authorise and log on.
/// </summary>
/// <remarks>
/// The subjects are assembled as DER, and the certificates signed by hand, because the interesting
/// shapes cannot be spelled. <c>CertificateRequest</c> takes a subject STRING, and .NET's parser
/// for one has no syntax for the ASN.1 string type an attribute is encoded as - which is what the
/// pending case below turns on - nor will .NET load a certificate holding a type it cannot decode,
/// so even a hand-built DN cannot be issued through it.
/// </remarks>
internal static class IdentitySubjectTests
{
    public static void Register(Runner runner)
    {
        runner.Test("identity: a subject with several common names is read as the last one", () =>
        {
            // Which end of a multi-CN subject is "the" CN is a real disagreement in the wild: the
            // natural OpenSSL one-liner (X509_NAME_get_index_by_NID with -1) answers with the
            // FIRST. This pins the answer ioxide gives, and pins it against the reading .NET makes
            // of the very same certificate - the one an ASP.NET application sees, because
            // ITlsConnectionFeature.ClientCertificate is built from PeerCertificateDer. Two
            // accessors on one connection that named different principals would be a defect; they
            // agree, and this is what says so.
            Identity id = Ask("multi-cn", withDotNetName: true, subjectDer: Dn(
                [Attribute(CommonName, UniversalTagNumber.UTF8String, "first.example")],
                [Attribute(CommonName, UniversalTagNumber.UTF8String, "second.example")]));

            Assert.True(id.Subject.Contains("/CN=first.example/CN=second.example"),
                $"the fixture must really carry both names in that order, got: {id.Subject}");
            Assert.Equal("second.example", id.CommonName);
            Assert.Equal(id.CommonName, id.DotNetName);
        });

        runner.Test("identity: a 20 KB distinguished name is rendered whole, common name included", () =>
        {
            // X509_NAME_oneline's buffer-taking form reports success when handed a buffer too
            // small and writes as many whole attributes as fit - a valid-looking prefix with the
            // CN missing, which is one string for two principals. RenderSubject uses the
            // allocating form to avoid exactly that, and this is what says the avoidance holds at
            // a size no real DN reaches. Larger is not testable through a handshake: both session
            // tickets carry the client certificate, and past about 30 KB the two of them outgrow
            // the 64 KB buffer BoringSSL writes its first response record from.
            Identity id = Ask("long-dn", Dn(
                [Attribute(Organisation, UniversalTagNumber.UTF8String, new string('x', 20_000))],
                [Attribute(CommonName, UniversalTagNumber.UTF8String, "tail.example")]));

            // The length is asserted first: without it a subject truncated to nothing would still
            // satisfy the CN assertion, because the CN comes from the DN and not from the render.
            Assert.True(id.SubjectLength > 20_000,
                $"the whole DN should be rendered, got {id.SubjectLength} characters");
            Assert.True(id.Subject.EndsWith("/CN=tail.example", StringComparison.Ordinal),
                $"the rendered subject should end with the CN, got the last 40: {Tail(id.Subject)}");
            Assert.Equal("tail.example", id.CommonName);
        });

        runner.Test("identity: a common name carrying CRLF is refused, and the subject escapes it", () =>
        {
            // The pair the refusal rests on. PeerCommonName is documented as the value to compare,
            // and logging it is what callers do next to comparing it, so a CN that could forge a
            // log line or split a header is not reported as a name at all. PeerSubject may carry
            // it because the render escapes it. If either half changes, one of these two fails.
            Identity id = Ask("crlf-cn", Dn(
                [Attribute(CommonName, UniversalTagNumber.UTF8String, "alice\r\nauthorized=root")]));

            Assert.True(id.CommonName is null,
                $"a CN carrying CR/LF must not be reported as an identity, got: {id.CommonName}");

            // Not merely non-null: the peer authenticated, so a subject exists, and it carries
            // those bytes in OpenSSL's escaped form rather than as real control characters.
            Assert.True(id.Subject.Contains(@"alice\x0D\x0Aauthorized=root", StringComparison.Ordinal),
                $"the rendered subject should escape the CR/LF, got: {id.Subject}");
        });

        runner.Test("identity: a CN the decoder refuses is not named, even where the rendered subject cannot tell it apart", () =>
        {
            // Both certificates are signed by the same CA and both handshakes complete, so both
            // peers are authenticated. They differ in ONE thing: the ASN.1 string type the common
            // name is encoded as.
            //
            // PrintableString is the ordinary one. A BIT STRING is a type OpenSSL accepts inside a
            // Name - it is in the mask X509_NAME's template parses with - but will not decode to
            // text, so ExtractCommonName's ASN1_STRING_to_UTF8 fails and ioxide reports no name at
            // all. The render is not so careful: X509_NAME_oneline copies the attribute's bytes
            // out as they are, so the forged certificate renders character for character as the
            // real one's subject.
            Identity real = Ask("printable-cn", withDotNetName: true, subjectDer: Dn(
                [Attribute(CommonName, UniversalTagNumber.PrintableString, "audit-alice")]));

            Identity forged = Ask("bitstring-cn", withDotNetName: true, subjectDer: Dn(
                [Attribute(CommonName, BitString, "\0audit-alice")]));

            // Guards, so the comparison below cannot be satisfied by a fixture that never arrived.
            // Both peers were validated: a chain that does not build fails the handshake, and
            // neither accessor is populated unless SSL_get_verify_result said X509_V_OK.
            Assert.Equal("audit-alice", real.CommonName);
            Assert.True(forged.CommonName is null,
                $"the forged CN does not decode and must not be reported, got: {forged.CommonName}");
            Assert.True(real.SubjectLength > 0 && forged.SubjectLength > 0,
                "both peers authenticated, so both must have a rendered subject");
            Assert.True(real.Subject.Length == real.SubjectLength && forged.Subject.Length == forged.SubjectLength,
                "both subjects must arrive whole for a comparison of them to mean anything");

            // The two DO render alike, and that is why the assertion above is the one that matters.
            // RenderSubject copies an attribute's bytes out verbatim, so a CN carried in an ASN.1
            // type ExtractCommonName refuses still renders as an ordinary name: X509_NAME_oneline
            // is a display function and cannot separate these two principals. Reviewed as a defect
            // and kept, because PeerSubject is documented for exactly one use - "rendered for
            // people: logs, audit trails, error messages" - and its own remarks tell the caller not
            // to authorize on a substring of it and to use PeerCommonName, which fails closed here.
            // A trusted CA that will sign a hand-assembled DER Name could equally issue the plain
            // CN, so the encoding buys an attacker nothing the CA had not already granted.
            Assert.True(real.Subject == forged.Subject,
                "the two subjects no longer collide - if RenderSubject learned to tell these apart, "
                + "this test should become the stronger claim that they differ");
        });
    }

    // ---- talking to a server ------------------------------------------------------------------

    /// <summary>
    /// What the two accessors said about one connection. <paramref name="Subject"/> is elided in
    /// the middle when it is very long, which <paramref name="SubjectLength"/> never is.
    /// </summary>
    private readonly record struct Identity(
        string? CommonName, string Subject, int SubjectLength, string? DotNetName);

    /// <summary>
    /// Start a server that reports both accessors, hand it a client certificate carrying
    /// <paramref name="subjectDer"/> as its subject, and return what it said.
    /// </summary>
    private static Identity Ask(string tag, byte[] subjectDer, bool withDotNetName = false)
    {
        (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();
        (string certPath, string keyPath) = MintClient(tag, subjectDer);

        int port = TestServer.Start((r, c) => Report(r, c, withDotNetName), r => TlsService.Start(r, new TlsOptions
        {
            CertificatePath = serverCert,
            KeyPath = serverKey,
            ClientCaPath = ca,

            // Required rather than optional, so a certificate that failed to validate could not be
            // answered at all: every assertion here is about a peer that authenticated.
            RequireClientCertificate = true,
        }));

        // The deadline is generous rather than tight: nothing here asserts on time, it only keeps
        // a wedged read from waiting out the runner's watchdog.
        (int status, string body) = Client.GetTlsClientCert(port, "/who", certPath, keyPath, timeoutMs: 20_000);
        Assert.Equal(200, status);

        return new Identity(
            Unwrap(Field(body, "cn")),
            Field(body, "subject"),
            int.Parse(Field(body, "subjectlen")),
            Unwrap(Field(body, "net")));
    }

    /// <summary>
    /// Reports both accessors, plus what .NET makes of the same certificate - the reading an
    /// ASP.NET application gets, since ITlsConnectionFeature.ClientCertificate is built from
    /// <see cref="TlsSession.PeerCertificateDer"/>.
    /// </summary>
    private static async Task Report(Reactor reactor, TcpConnection connection, bool withDotNetName)
    {
        TlsSession? session = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);

            // The request routinely rides in with the handshake's final flight - a TLS 1.3 client
            // sends it straight after Finished - and those bytes are decrypted and gone from the
            // socket before AcceptAsync returns. Answering that one before parking on a read is
            // what keeps this from waiting for bytes that already arrived; the big-DN fixture hits
            // it often enough to have shown up as an intermittent timeout while it was missing.
            if (!session.DrainPlaintext().IsEmpty)
            {
                Answer(connection, session, withDotNetName);
                await connection.FlushAsync();
            }

            // No ResetRead above: that belongs to a read this handler actually issued.
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }

                Answer(connection, session, withDotNetName);
                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            session?.Dispose();
            connection.DecRef();
        }
    }

    private static void Answer(TcpConnection connection, TlsSession session, bool withDotNetName)
    {
        // Costs a full certificate parse on the reactor thread, and one of these certificates is
        // 41 KB - so it is only done for the tests whose claim is about the two readings agreeing.
        string? dotnet = null;
        if (withDotNetName && session.PeerCertificateDer is { } der)
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
            dotnet = certificate.GetNameInfo(X509NameType.SimpleName, false);
        }

        byte[] body = Encoding.ASCII.GetBytes(
            $"cn={Escape(session.PeerCommonName)}\n"
            + $"subject={Escape(Elide(session.PeerSubject))}\n"
            + $"subjectlen={session.PeerSubject?.Length ?? -1}\n"
            + $"net={Escape(dotnet)}\n");

        session.Write(connection, [
            .. Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\ncontent-length: {body.Length}\r\n\r\n"),
            .. body]);
    }

    // The response has to fit the harness server's 16 KB write slab, and one of these subjects is
    // 40 KB. Only the ends of a long one are sent - the length travels separately and unabridged,
    // and a test that compares subjects whole asserts it got an unelided one.
    private static string? Elide(string? subject)
        => subject is null || subject.Length <= 160 ? subject : subject[..80] + "[...]" + subject[^80..];

    // A name can hold anything and this one travels back in the response body, which the client
    // reads as ASCII lines: a raw CR would end the line the reader splits on, and a null name has
    // to stay distinguishable from an empty one.
    private const string None = "(none)";

    private static string Escape(string? value)
    {
        if (value is null)
        {
            return None;
        }

        var encoded = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            encoded.Append(c is >= ' ' and <= '~' && c != '%' ? c.ToString() : $"%{(int)c:X4}");
        }

        return encoded.ToString();
    }

    private static string? Unwrap(string field) => field == None ? null : field;

    private static string Field(string body, string name)
    {
        foreach (string line in body.Split('\n'))
        {
            if (line.StartsWith($"{name}=", StringComparison.Ordinal))
            {
                return line[(name.Length + 1)..];
            }
        }

        throw new Exception($"the handler reported no '{name}' - the body was: {body}");
    }

    private static string Tail(string value) => value.Length <= 40 ? value : value[^40..];

    // ---- fixtures -----------------------------------------------------------------------------

    private const string CommonName = "2.5.4.3";
    private const string Organisation = "2.5.4.10";

    /// <summary>
    /// An ASN.1 tag written as itself, for a type <see cref="AsnWriter"/> will not write as a
    /// character string. 3 is BIT STRING, which a Name may carry and text decoding refuses.
    /// </summary>
    private const UniversalTagNumber BitString = (UniversalTagNumber)3;

    private static (string Oid, UniversalTagNumber Tag, string Value) Attribute(
        string oid, UniversalTagNumber tag, string value) => (oid, tag, value);

    /// <summary>A Name, from RDNs, each a set of attributes.</summary>
    private static byte[] Dn(params (string Oid, UniversalTagNumber Tag, string Value)[][] rdns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach ((string Oid, UniversalTagNumber Tag, string Value)[] rdn in rdns)
            {
                using (writer.PushSetOf())
                {
                    foreach ((string oid, UniversalTagNumber tag, string value) in rdn)
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(oid);
                            WriteValue(writer, tag, value);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static void WriteValue(AsnWriter writer, UniversalTagNumber tag, string value)
    {
        if (tag == BitString)
        {
            // Written as a raw tag-length-value, because the point of this attribute is to be a
            // type the writer's character-string path would never produce. Latin-1 so that one
            // char is one byte, and the caller supplies the leading unused-bit count itself.
            byte[] content = Encoding.Latin1.GetBytes(value);
            writer.WriteEncodedValue([(byte)tag, (byte)content.Length, .. content]);
            return;
        }

        writer.WriteCharacterString(tag, value);
    }

    /// <summary>
    /// A client certificate for an arbitrary subject, signed by the CA
    /// <see cref="TestCert.EnsureMutualTls"/> writes. Named per process, so suites running
    /// concurrently never overwrite one another's certificate with another one's key.
    /// </summary>
    private static (string CertPath, string KeyPath) MintClient(string tag, byte[] subjectDer)
    {
        (string ca, _, _, _, _, _, _) = TestCert.EnsureMutualTls();

        string dir = Path.Combine(Path.GetTempPath(), "ioxide-identity-subject");
        Directory.CreateDirectory(dir);

        string certPath = Path.Combine(dir, $"{tag}-{Environment.ProcessId}.crt");
        string keyPath = Path.Combine(dir, $"{tag}-{Environment.ProcessId}.key");

        using X509Certificate2 caCert = X509Certificate2.CreateFromPemFile(ca, Path.ChangeExtension(ca, ".key"));
        using RSA caKey = caCert.GetRSAPrivateKey()!;
        using var key = RSA.Create(2048);

        byte[] der = BuildCertificate(subjectDer, key, caCert, caKey);

        File.WriteAllText(certPath, "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END CERTIFICATE-----\n");
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());

        return (certPath, keyPath);
    }

    /// <summary>
    /// Assemble and sign a leaf by hand, because <c>CertificateRequest</c> cannot carry these
    /// subjects: it parses the certificate it produces, and .NET refuses to load one whose DN
    /// holds a string type it will not decode.
    /// </summary>
    /// <remarks>
    /// The window sits inside the CA's own at both ends - .NET refuses to issue a leaf that starts
    /// before its issuer does, and the fixture CA starts a day ago and runs for two years.
    /// </remarks>
    private static byte[] BuildCertificate(byte[] subject, RSA key, X509Certificate2 issuer, RSA issuerKey)
    {
        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence())
        {
            using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                tbs.WriteInteger(2);   // v3
            }

            tbs.WriteInteger(Random.Shared.NextInt64(1, long.MaxValue));
            SignatureAlgorithm(tbs);
            tbs.WriteEncodedValue(issuer.SubjectName.RawData);

            using (tbs.PushSequence())
            {
                tbs.WriteUtcTime(DateTimeOffset.UtcNow.AddMinutes(-5));
                tbs.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(30));
            }

            tbs.WriteEncodedValue(subject);
            tbs.WriteEncodedValue(key.ExportSubjectPublicKeyInfo());

            using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true)))
            using (tbs.PushSequence())
            using (tbs.PushSequence())
            {
                // clientAuth, and not decoration: the server verifies a client chain with
                // OpenSSL's ssl_client purpose, which refuses a leaf that does not carry it.
                tbs.WriteObjectIdentifier("2.5.29.37");
                var eku = new AsnWriter(AsnEncodingRules.DER);
                using (eku.PushSequence())
                {
                    eku.WriteObjectIdentifier("1.3.6.1.5.5.7.3.2");
                }

                tbs.WriteOctetString(eku.Encode());
            }
        }

        byte[] tbsBytes = tbs.Encode();

        var certificate = new AsnWriter(AsnEncodingRules.DER);
        using (certificate.PushSequence())
        {
            certificate.WriteEncodedValue(tbsBytes);
            SignatureAlgorithm(certificate);
            certificate.WriteBitString(
                issuerKey.SignData(tbsBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        return certificate.Encode();

        static void SignatureAlgorithm(AsnWriter writer)
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");   // sha256WithRSAEncryption
                writer.WriteNull();
            }
        }
    }
}
