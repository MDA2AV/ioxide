using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The fixed-size identity buffers on the QUIC side, what happens to a name that does not fit, and
/// to a common name that would not be safe to log.
/// </summary>
/// <remarks>
/// The shim keeps a verified peer's identity in <c>char peer_subject[1024]</c> and
/// <c>char peer_cn[256]</c>, and a name that does not fit is recorded as no name at all. That is
/// the right instinct - a truncated DN is a prefix two different principals can share, and one
/// string standing for two principals is the one thing an identity must never do - but it is only
/// half applied, and nothing tells the caller it happened:
///
/// <list type="bullet">
/// <item>the same certificate is named in full by TLS over TCP, which caps nothing
/// (<c>TlsSession.RenderSubject</c> hands back whatever <c>X509_NAME_oneline</c> rendered), so one
/// client is alice on 443 and anonymous on 443/udp - the certificate the first test below mints
/// reports its whole 1456-byte subject through <c>Handlers.TlsIdentity</c> on the TCP stack, and
/// null here;</item>
/// <item>null is documented as "the peer offered none", which for a connection the server only
/// accepted BECAUSE a certificate verified is untrue;</item>
/// <item>the two accessors disagree with each other on one connection, which is what the tests
/// below assert on - no second stack required to see it;</item>
/// <item>and the rule is not even the same in both directions: <c>iq_copy_subject</c> truncates a
/// recorded name to the caller's buffer while <c>iq_conn_peer_cn</c> returns 0 for one that does
/// not fit, under a comment claiming it follows "the same rule as the subject".</item>
/// </list>
///
/// None of this is a bypass: a name that is dropped fails closed, and a server requiring client
/// certificates still refuses everyone it refused before. It is a correctness and observability
/// divergence - an application authorizing on <c>PeerCommonName</c> behaves differently on the two
/// ports for one certificate, and an audit trail records nobody.
/// </remarks>
internal static class QuicIdentityCapTests
{
    public static void Register(Runner runner)
    {
        RegisterVerifiedClientNames(runner);
        RegisterRecordedServerNames(runner);
    }

    // ---- the verified client's identity ---------------------------------------------------------
    //
    // Every server here demands a client certificate, which is the vacuity guard for the whole
    // group: a connection that gets an answer at all is one whose certificate was offered AND
    // verified, so a name missing from the response cannot be explained by "the peer offered none".

    private static void RegisterVerifiedClientNames(Runner runner)
    {
        runner.Test("mtls/quic: control - a client whose name fits is named by both the subject and the CN", () =>
        {
            // The control for the two below, and for the minting helper they share: same CA, same
            // server, same code path, a name that is merely short. Without it a PEND below could
            // just as well be a fixture this file failed to mint correctly.
            (string cert, string key) = SignedByTestCa("fits", "CN=alice-fits,OU=one,OU=two", server: false);

            (int status, string? subject, string? commonName) = NameSeenBy(cert, key);

            Assert.True(status == 200, $"the server never answered, so nothing was verified (status {status})");
            Assert.True(subject is not null && subject.Contains("alice-fits", StringComparison.Ordinal),
                $"a verified client must be named in the subject, got: {subject ?? "<null>"}");
            Assert.Equal("alice-fits", commonName);
        });

        runner.Test("mtls/quic: a DN too long to record is reported as no name, never as a prefix", () =>
        {
            // 24 organisational units: a rendered DN of 1456 bytes, which is large but is the shape
            // an enterprise PKI actually issues. The shim's field is 1024.
            string subjectName = LongDistinguishedName("alice-longdn");
            Assert.True(subjectName.Length > 1024,
                $"the padding no longer exceeds the shim's 1024-byte field ({subjectName.Length}), so this "
                + "test would pass without the defect being fixed");

            (string cert, string key) = SignedByTestCa("longdn", subjectName, server: false);

            (int status, string? subject, string? commonName) = NameSeenBy(cert, key);

            Assert.True(status == 200, $"the server never answered, so nothing was verified (status {status})");

            // The guard that makes the assertion below mean what it says: the CN comes back, so the
            // certificate was verified, iq_record_subject ran, and this connection HAS an identity.
            Assert.Equal("alice-longdn", commonName);

            // Reviewed as a defect and kept, because it fails CLOSED and deliberately so: the
            // buffer-taking form of X509_NAME_oneline was rejected for this very reason, since it
            // returns a valid-looking prefix WITH THE CN MISSING and two clients agreeing on their
            // leading attributes then render identically. No name beats a name that may belong to
            // someone else. The accessor's doc now says so rather than calling null "the peer
            // offered none"; what is worth pinning is that nothing hands back a shortened identity.
            Assert.True(subject is null,
                $"a DN too long to record must be reported as no name, not as a prefix, got: {subject}");
        });

        runner.Test("mtls/quic: a CN too long to record is reported as no name, never as a prefix", () =>
        {
            // The mirror image, and the quiet one: the subject case at least prints to stderr, the
            // CN case drops the name in silence. The whole DN is ~300 bytes, so it fits the subject
            // field comfortably - only peer_cn[256] is exceeded.
            string commonNameValue = new string('c', 300);
            Assert.True(commonNameValue.Length > 256,
                $"the CN no longer exceeds the shim's 256-byte field ({commonNameValue.Length}), so this "
                + "test would pass without the defect being fixed");

            (string cert, string key) = SignedByTestCa("longcn", $"CN={commonNameValue}", server: false);

            (int status, string? subject, string? commonName) = NameSeenBy(cert, key);

            Assert.True(status == 200, $"the server never answered, so nothing was verified (status {status})");

            // The guard, the other way round: the subject carries the CN, so the certificate was
            // verified, it HAS a common name, and that name is neither empty nor carries a control
            // character - which is every reason PeerCommonName documents for being null.
            Assert.True(subject is not null && subject.Contains(commonNameValue, StringComparison.Ordinal),
                $"the subject should carry the CN this test signed, got: {subject ?? "<null>"}");

            // Same rule, and the same verdict. peer_cn holds 256 bytes, four times RFC 5280's
            // ub-common-name of 64, so a CN that does not fit was hand-built rather than issued -
            // and this is the value applications AUTHORIZE on, where reporting a prefix would be
            // the one failure that actually grants something. Null denies; a prefix might not.
            Assert.True(commonName is null,
                $"a CN too long to record must be reported as no name, not as a prefix, got: {commonName}");
        });

        runner.Test("mtls/quic: a common name carrying CRLF is refused, and the subject escapes it", () =>
        {
            // The QUIC side of the Tls suite's test of the same name: PeerCommonName is the value to
            // authorize on, and what gets logged beside the decision, so a CN that could forge a log
            // line or split a header is not reported as a name. PeerSubject may carry it, escaped.
            (string cert, string key) = SignedByTestCa("crlf-cn", CommonNamed("alice\r\nauthorized=root"), server: false);

            (int status, string? subject, string? commonName) = NameSeenBy(cert, key);

            Assert.True(status == 200, $"the server never answered, so nothing was verified (status {status})");
            Assert.True(commonName is null,
                $"a CN carrying CR/LF must not be reported as an identity, got: {Show(commonName)}");
            Assert.True(subject is not null && subject.Contains(@"alice\x0D\x0Aauthorized=root", StringComparison.Ordinal),
                $"the rendered subject should escape the CR/LF, got: {subject ?? "<null>"}");
        });

        runner.Test("mtls/quic: a common name is refused for exactly the characters TCP refuses", () =>
        {
            // TlsSession.ExtractCommonName refuses any char.IsControl character: C0, DEL and C1. The
            // shim checks UTF-8 bytes, where C1 is C2 80..C2 9F and the next character, U+00A0, is
            // C2 A0 and no control - so both sides of each edge are asked, and the TCP rule decides.
            string[] names =
            [
                "tab\there", "esc\u001Bhere", "del\u007Fhere", "nel\u0085here", "apc\u009Fhere",
                "nbsp\u00A0here", "zo\u00EB", "y\u00FF",
            ];

            var wrong = new List<string>();
            for (int i = 0; i < names.Length; i++)
            {
                string? expected = names[i].Any(char.IsControl) ? null : names[i];
                (string cert, string key) = SignedByTestCa($"ctl-{i}", CommonNamed(names[i]), server: false);

                (int status, string? subject, string? commonName) = NameSeenBy(cert, key);

                if (status != 200 || subject is null)
                {
                    wrong.Add($"{Show(names[i])}: not verified (status {status})");
                }
                else if (commonName != expected)
                {
                    wrong.Add($"{Show(names[i])}: the TCP rule gives {Show(expected)}, QUIC read {Show(commonName)}");
                }
            }

            Assert.True(wrong.Count == 0, string.Join("; ", wrong));
        });
    }

    // ---- the recorded server name ---------------------------------------------------------------

    private static void RegisterRecordedServerNames(Runner runner)
    {
        runner.Test("quic: control - a recorded server name that fits comes back whole", () =>
        {
            // Proves the recording path works at all, so the collision below is about length and
            // not about a client that never asked for the name.
            (string cert, string key) = SignedByTestCa("recorded-short", "CN=svc-short", server: true);

            string recorded = RecordedServerName(cert, key);

            Assert.Equal("/CN=svc-short", recorded);
        });

        runner.Test("quic: two server certificates are never recorded under one name", () =>
        {
            // Two certificates for two different services, agreeing on the padding that renders
            // ahead of their common names. iq_record_subject keeps both DNs whole - each is ~370
            // bytes, well inside peer_subject[1024] - and then iq_copy_subject hands the caller as
            // much as its buffer holds, which is the prefix they share.
            //
            // Both halves of that are now closed. iq_copy_subject refuses rather than truncating,
            // the rule iq_conn_peer_cn three lines away already followed and its comment already
            // claimed for the subject; and H3TestClient asks for the same 1024 the shim holds, so
            // the only empty answer is a genuinely absent name rather than one its buffer erased.
            (string oneCert, string oneKey) = SignedByTestCa("svc-one", PaddedName("svc-one"), server: true);
            (string twoCert, string twoKey) = SignedByTestCa("svc-two", PaddedName("svc-two-different"), server: true);

            string first = RecordedServerName(oneCert, oneKey);
            string second = RecordedServerName(twoCert, twoKey);

            // Stated as the property rather than as "first != second", because a fix may well be
            // to report NO name for one that does not fit - the rule the CN getter already follows
            // - and two empty strings must count as passing, not as the collision this is about.
            Assert.True(first.Length == 0 || second.Length == 0 || first != second,
                $"two different server certificates were both recorded as [{first}] ({first.Length} bytes): "
                + "one string standing for two principals, which is what iq_record_subject drops a "
                + "too-long DN to avoid in the first place");
        });
    }

    // ---- driving ---------------------------------------------------------------------------------

    /// <summary>
    /// Runs one mutual-TLS QUIC connection with the given client certificate and returns what the
    /// request handler saw of the peer: the response status, <c>PeerSubject</c> and
    /// <c>PeerCommonName</c>, with an absent name as null.
    /// </summary>
    /// <remarks>
    /// <c>requireClientCertificate: true</c> deliberately: it turns "was answered" into proof that a
    /// certificate was verified, which is what stops a missing name below from being read as the
    /// peer having offered nothing.
    /// </remarks>
    private static (int Status, string? Subject, string? CommonName) NameSeenBy(string clientCert, string clientKey)
    {
        (string ca, string serverCert, string serverKey, _, _, _, _) = TestCert.EnsureMutualTls();

        var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
            clientCaPemPath: ca, requireClientCertificate: true);

        try
        {
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                // Read inside the REQUEST handler, not at accept: the connection callback fires
                // before the handshake finishes, so the identity does not exist yet there.
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    _ => new Nghttp3Response
                    {
                        Body = Encoding.UTF8.GetBytes(
                            $"subject={(conn as QuicEngineConnection)?.PeerSubject}\n"
                            + $"cn={Uri.EscapeDataString((conn as QuicEngineConnection)?.PeerCommonName ?? "")}"),
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            (string? subject, string? commonName) = NamesFrom(body);
            return (status, subject, commonName);
        }
        finally
        {
            // The reactor comes down before the engine it was handed, or a poll can still be inside
            // native code the dispose has freed.
            TestServer.StopAll();
            engine.Dispose();
        }
    }

    /// <summary>
    /// Serves one connection with the given certificate and returns the subject the CLIENT recorded
    /// for it - observed, not verified, which is why it is read through the shim's server-subject
    /// entry point rather than its peer-subject one.
    /// </summary>
    private static string RecordedServerName(string serverCert, string serverKey)
    {
        var engine = new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"]);

        try
        {
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    static _ => new Nghttp3Response { Body = "ok"u8.ToArray() }));

            using var client = new H3TestClient("127.0.0.1", udpPort) { RecordServerCertificate = true };
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // Asked for and answered, so the connection this name is read off is a live one.
            (int status, _) = client.Get("/", timeoutMs: 5000);
            Assert.True(status == 200, $"the server never answered, so no certificate was served (status {status})");

            return client.ServerCertificateSubject();
        }
        finally
        {
            TestServer.StopAll();
            engine.Dispose();
        }
    }

    /// <summary>
    /// The two accessors out of the response the handler wrote, with an empty value meaning null -
    /// which is exactly the distinction under test, so it is decoded rather than flattened. A
    /// rendered DN cannot contain a newline (<c>X509_NAME_oneline</c> escapes control bytes as
    /// <c>\xHH</c>), so the name itself cannot be mistaken for the separator.
    /// </summary>
    private static (string? Subject, string? CommonName) NamesFrom(string body)
    {
        string? subject = null;
        string? commonName = null;

        foreach (string line in body.Split('\n'))
        {
            if (line.StartsWith("subject=", StringComparison.Ordinal))
            {
                subject = line["subject=".Length..];
            }
            else if (line.StartsWith("cn=", StringComparison.Ordinal))
            {
                commonName = Uri.UnescapeDataString(line["cn=".Length..]);   // a CN can hold the separator
            }
        }

        return (subject is { Length: > 0 } ? subject : null, commonName is { Length: > 0 } ? commonName : null);
    }

    // ---- fixtures --------------------------------------------------------------------------------

    /// <summary>A subject of one common name, encoded as a UTF8String whatever it holds.</summary>
    private static X500DistinguishedName CommonNamed(string commonName)
    {
        var name = new X500DistinguishedNameBuilder();
        name.AddCommonName(commonName);
        return name.Build();
    }

    /// <summary>A name for a failure message, its control and non-ASCII characters spelled out.</summary>
    private static string Show(string? name)
        => name is null ? "no name" : string.Concat(name.Select(c => c is >= ' ' and <= '~' ? c.ToString() : $"\\u{(int)c:X4}"));

    /// <summary>A DN of 24 organisational units, rendering to 1456 bytes - past peer_subject[1024].</summary>
    private static string LongDistinguishedName(string commonName)
    {
        var subject = new StringBuilder($"CN={commonName}");

        for (int i = 0; i < 24; i++)
        {
            subject.Append($",OU=unit-{i:D2}-{new string('x', 48)}");
        }

        return subject.ToString();
    }

    /// <summary>
    /// A DN whose rendered form carries ~340 bytes of padding BEFORE the common name. The order
    /// matters: .NET encodes a subject string in reverse, so the attribute written first renders
    /// last, and only this way do two of these differ past a 256-byte read rather than inside it.
    /// </summary>
    private static string PaddedName(string commonName)
    {
        var subject = new StringBuilder($"CN={commonName}");

        for (int i = 0; i < 6; i++)
        {
            subject.Append($",OU=pad-{i:D2}-{new string('p', 48)}");
        }

        return subject.ToString();
    }

    /// <summary>
    /// A leaf with a subject of this file's choosing, signed by the CA <c>EnsureMutualTls</c>
    /// writes - so the servers here trust it without any change to the shared fixtures.
    /// </summary>
    /// <remarks>
    /// The validity window is taken FROM the CA rather than from the clock: .NET refuses to issue a
    /// leaf whose notBefore precedes its issuer's, and that fixture is cached across days, so
    /// "now minus an hour" is not reliably inside it.
    ///
    /// The files carry the process id and sit outside the shared fixture directory, because these
    /// are not TestCert's locked, atomically written fixtures: two suites running at once would
    /// otherwise leave one process's certificate beside another's key, and every handshake failing
    /// on a fixture looks exactly like the defect under test.
    /// </remarks>
    private static (string Cert, string Key) SignedByTestCa(string tag, string subject, bool server)
        => SignedByTestCa(tag, new X500DistinguishedName(subject), server);

    private static (string Cert, string Key) SignedByTestCa(string tag, X500DistinguishedName subject, bool server)
    {
        (string caPath, _, _, _, _, _, _) = TestCert.EnsureMutualTls();

        using X509Certificate2 ca = X509Certificate2.CreateFromPemFile(
            caPath, Path.Combine(Path.GetDirectoryName(caPath)!, "ca.key"));

        DateTimeOffset notBefore = new DateTimeOffset(ca.NotBefore.ToUniversalTime()).AddMinutes(1);
        DateTimeOffset notAfter = new DateTimeOffset(ca.NotAfter.ToUniversalTime()).AddMinutes(-1);

        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        if (server)
        {
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            names.AddIpAddress(System.Net.IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
        }

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")], false));

        byte[] serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using X509Certificate2 signed = request.Create(ca, notBefore, notAfter, serial);

        string dir = Path.Combine(Path.GetTempPath(), "ioxide-e2e-identity-cap");
        Directory.CreateDirectory(dir);

        string certPath = Path.Combine(dir, $"{tag}-{Environment.ProcessId}.crt");
        string keyPath = Path.Combine(dir, $"{tag}-{Environment.ProcessId}.key");
        File.WriteAllText(certPath, signed.ExportCertificatePem());
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());

        return (certPath, keyPath);
    }
}
