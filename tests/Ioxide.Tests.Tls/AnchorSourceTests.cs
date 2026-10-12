using System.Formats.Asn1;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// ClientCaPath and ClientCaPem, which TlsOptions documents as equivalent. Every way they might
/// not be: ordering, encodings, auxiliary trust settings, bundle size.
/// </summary>
/// <remarks>
/// The two sources reach OpenSSL by different doors, which is why the claim is worth testing at
/// all: the path goes through SSL_CTX_load_verify_locations, which parses the bundle with
/// PEM_X509_INFO_read_bio, while the text goes through a PEM_read_bio_X509_AUX loop. Those two
/// readers have to accept the same set of blocks, and a difference is silent - a block one of them
/// does not recognise is skipped, not reported.
///
/// The clients are driven with a selection callback that presents the certificate it was handed
/// whatever the server hinted. That is deliberate: the acceptable-CA hint is built by
/// SSL_load_client_CA_file / SSL_CTX_add_client_CA, which is a SEPARATE question from what the
/// store trusts, and the path's hint leaves out an anchor read from a TRUSTED CERTIFICATE block. A
/// client that filtered on the hint would send nothing, and "sent nothing" is indistinguishable at
/// the server from "was not trusted" - so the callback keeps these tests measuring the trust
/// decision rather than a client-side heuristic.
/// </remarks>
internal static class AnchorSourceTests
{
    public static void Register(Runner runner)
    {
        // Control, and the fixture check for the Pending below. Both anchors of the one bundle
        // admit their client when the bundle is read from a path, so anything the PEM-text route
        // does differently is the source and not the certificates.
        runner.Test("anchors: a TRUSTED CERTIFICATE block in a bundle read from a path is trusted", () =>
        {
            Anchors anchors = Fixture.Value;

            int port = TestServer.Start(Handlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = anchors.ServerCert,
                KeyPath = anchors.ServerKey,
                ClientCaPath = anchors.BundlePath,
                RequireClientCertificate = true,
            }));

            (Client.TlsOutcome trusted, string alice) = Present(port, anchors.AliceCert, anchors.AliceKey);
            Assert.Equal(Client.TlsOutcome.Served, trusted);
            Assert.Equal("alice", alice);

            (Client.TlsOutcome plain, string bob) = Present(port, anchors.BobCert, anchors.BobKey);
            Assert.Equal(Client.TlsOutcome.Served, plain);
            Assert.Equal("bob", bob);
        });

        runner.Test("anchors: a TRUSTED CERTIFICATE block is trusted from PEM text as it is from a path", () =>
        {
            Anchors anchors = Fixture.Value;

            int port = TestServer.Start(Handlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = anchors.ServerCert,
                KeyPath = anchors.ServerKey,
                ClientCaPem = anchors.BundlePem,   // the same bytes, handed over as a value
                RequireClientCertificate = true,
            }));

            // Not vacuous: the PLAIN block of the same bundle is loaded, so this server is up, is
            // asking for a certificate and is verifying what it gets. The two clients differ in one
            // thing - which of the two anchors in the one bundle issued them.
            (Client.TlsOutcome plain, string bob) = Present(port, anchors.BobCert, anchors.BobKey);
            Assert.Equal(Client.TlsOutcome.Served, plain);
            Assert.Equal("bob", bob);

            (Client.TlsOutcome trusted, string alice) = Present(port, anchors.AliceCert, anchors.AliceKey);
            Assert.Equal(Client.TlsOutcome.Served, trusted);
            Assert.Equal("alice", alice);
        });

        RegisterIssuerHint(runner);
        RegisterEncoding(runner);
    }

    /// <summary>
    /// What the PEM-text route does to bytes on the way in. It converts the string to UTF-8, so a
    /// byte-order mark reaches OpenSSL as the three bytes it strips from a file; converted as ASCII
    /// it was a question mark, which OpenSSL has no reason to strip.
    /// </summary>
    private static void RegisterEncoding(Runner runner)
    {
        // Control. A byte-order mark in front of a PEM bundle is what Windows tooling writes, which
        // is why OpenSSL strips one from the first line rather than choking on it.
        runner.Test("anchors: a bundle with a byte-order mark read from a path is trusted", () =>
        {
            Anchors anchors = Fixture.Value;

            int port = TestServer.Start(Handlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = anchors.ServerCert,
                KeyPath = anchors.ServerKey,
                ClientCaPath = anchors.BomPath,
                RequireClientCertificate = true,
            }));

            (Client.TlsOutcome outcome, string alice) = Present(port, anchors.AliceCert, anchors.AliceKey);
            Assert.Equal(Client.TlsOutcome.Served, outcome);
            Assert.Equal("alice", alice);
        });

        runner.Test("anchors: a bundle with a byte-order mark is trusted as PEM text as it is from a path", () =>
        {
            Anchors anchors = Fixture.Value;

            int port = TestServer.Start(Handlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = anchors.ServerCert,
                KeyPath = anchors.ServerKey,
                ClientCaPem = anchors.BomPem,   // the same characters the file holds
                RequireClientCertificate = true,
            }));

            (Client.TlsOutcome outcome, string alice) = Present(port, anchors.AliceCert, anchors.AliceKey);
            Assert.Equal(Client.TlsOutcome.Served, outcome);
            Assert.Equal("alice", alice);
        });
    }

    /// <summary>
    /// The other half of the documented equivalence: the acceptable-CA hint, which the server
    /// lists in its CertificateRequest and which a client holding several certificates chooses by.
    /// Read off the wire here - see <see cref="HintedAuthorities"/> - because it is a claim worth
    /// checking rather than assuming.
    /// </summary>
    private static void RegisterIssuerHint(Runner runner)
    {
        // Control, and the proof that the hint reaches a client here at all - without it the
        // Pending below would pass for an empty list as readily as for a correct one.
        runner.Test("anchors: an anchor written twice in a bundle read from a path is hinted once", () =>
        {
            Anchors anchors = Fixture.Value;

            int port = TestServer.Start(Handlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = anchors.ServerCert,
                KeyPath = anchors.ServerKey,
                ClientCaPath = anchors.RepeatedPath,
                RequireClientCertificate = true,
            }));

            List<string> hint = HintedAuthorities(port, anchors.AliceCert, anchors.AliceKey);

            Assert.Equal(1, hint.Count);
            Assert.True(hint[0].Contains("ioxide test CA"), $"hinted something else: {hint[0]}");
        });

        runner.Test("anchors: an anchor written twice is hinted once from PEM text as it is from a path", () =>
        {
            Anchors anchors = Fixture.Value;

            int port = TestServer.Start(Handlers.TlsCommonName, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = anchors.ServerCert,
                KeyPath = anchors.ServerKey,
                ClientCaPem = anchors.RepeatedPem,   // the same bytes again
                RequireClientCertificate = true,
            }));

            List<string> hint = HintedAuthorities(port, anchors.AliceCert, anchors.AliceKey);

            // Not vacuous: HintedAuthorities requires the handshake to have completed and the
            // request to have been answered, so an empty or unparsed hint fails as loudly as a
            // wrong one - and it says "alice", so this anchor is genuinely trusted here.
            Assert.Equal(1, hint.Count);
        });
    }

    /// <summary>
    /// A bundle holding two anchors in the two PEM spellings a trust store uses, the certificates
    /// they issued, and the server's own pair.
    /// </summary>
    private sealed record Anchors(
        string ServerCert, string ServerKey,
        string BundlePath, string BundlePem,
        string RepeatedPath, string RepeatedPem,
        string BomPath, string BomPem,
        string AliceCert, string AliceKey,
        string BobCert, string BobKey);

    private static readonly Lazy<Anchors> Fixture = new(Mint);

    /// <summary>
    /// The bundle: the mutual-TLS CA as a TRUSTED CERTIFICATE carrying an auxiliary trust setting
    /// for TLS client authentication, then a second CA as an ordinary CERTIFICATE. One file, two
    /// anchors, two clients - one issued by each.
    /// </summary>
    /// <remarks>
    /// The second anchor is minted here rather than taken from TestCert because the point is a
    /// bundle whose blocks are spelled differently: with only the trusted block the PEM-text route
    /// would refuse to start ("contained no certificates"), which is a loud failure and a different
    /// finding. With a plain block beside it the route starts perfectly happily, having quietly
    /// dropped half of what it was given.
    /// </remarks>
    private static Anchors Mint()
    {
        (string ca, string serverCert, string serverKey, string aliceCert, string aliceKey, _, _)
            = TestCert.EnsureMutualTls();

        string dir = Directory.CreateTempSubdirectory("ioxide-anchor-source-").FullName;

        // One window for the pair: .NET refuses to issue a leaf whose notBefore precedes its
        // issuer's, and taking UtcNow twice can straddle a second boundary.
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);

        using RSA secondCaKey = RSA.Create(2048);
        var secondCaRequest = new CertificateRequest(
            "CN=ioxide second anchor CA", secondCaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        secondCaRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 secondCa = secondCaRequest.CreateSelfSigned(notBefore, notBefore.AddYears(2));

        using RSA bobKey = RSA.Create(2048);
        var bobRequest = new CertificateRequest(
            "CN=bob", bobKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        bobRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));

        byte[] serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using X509Certificate2 bob = bobRequest.Create(secondCa, notBefore, notBefore.AddYears(1), serial);

        string bobCert = Path.Combine(dir, "bob.crt");
        string bobKeyPath = Path.Combine(dir, "bob.key");
        File.WriteAllText(bobCert, bob.ExportCertificatePem());
        File.WriteAllText(bobKeyPath, bobKey.ExportPkcs8PrivateKeyPem());

        string bundle = TrustedCertificateBlock(ca) + secondCa.ExportCertificatePem() + "\n";
        string bundlePath = Path.Combine(dir, "anchors.pem");
        File.WriteAllText(bundlePath, bundle);

        // The other bundle: ONE anchor, written twice. What two overlapping trust stores
        // concatenated together look like, and the cheapest way to ask whether the acceptable-CA
        // hint is built the same way from both sources.
        string once = File.ReadAllText(ca).TrimEnd() + "\n";
        string repeated = once + once;
        string repeatedPath = Path.Combine(dir, "repeated.pem");
        File.WriteAllText(repeatedPath, repeated);

        // And the third: one anchor behind a byte-order mark. The file and the string hold the same
        // characters - writing U+FEFF as UTF-8 IS the three-byte mark - so the two sources are
        // being given the same bundle in the two shapes the API offers.
        string bom = "\uFEFF" + once;
        string bomPath = Path.Combine(dir, "bom.pem");
        File.WriteAllText(bomPath, bom, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        return new Anchors(
            serverCert, serverKey, bundlePath, bundle, repeatedPath, repeated, bomPath, bom,
            aliceCert, aliceKey, bobCert, bobKeyPath);
    }

    /// <summary>
    /// One certificate as a TRUSTED CERTIFICATE block: its own DER with an X509_CERT_AUX appended,
    /// which is all the format is. The aux here says the anchor is trusted for TLS client
    /// authentication - the setting a server doing mutual TLS is the one to care about.
    /// </summary>
    /// <remarks>
    /// X509_CERT_AUX ::= SEQUENCE { trust SEQUENCE OF OBJECT IDENTIFIER OPTIONAL, ... }, so the
    /// fourteen bytes appended are 30 0C 30 0A 06 08 2B 06 01 05 05 07 03 02 - byte for byte what
    /// <c>openssl x509 -addtrust clientAuth -trustout</c> writes.
    /// </remarks>
    private static string TrustedCertificateBlock(string certPath)
    {
        using X509Certificate2 anchor = X509CertificateLoader.LoadCertificateFromFile(certPath);

        var aux = new AsnWriter(AsnEncodingRules.DER);
        using (aux.PushSequence())
        {
            using (aux.PushSequence())
            {
                aux.WriteObjectIdentifier("1.3.6.1.5.5.7.3.2");
            }
        }

        return PemBlock("TRUSTED CERTIFICATE", [.. anchor.RawData, .. aux.Encode()]);
    }

    private static string PemBlock(string label, byte[] der)
    {
        var pem = new StringBuilder();
        pem.Append("-----BEGIN ").Append(label).Append("-----\n");

        string base64 = Convert.ToBase64String(der);
        for (int at = 0; at < base64.Length; at += 64)
        {
            pem.Append(base64, at, Math.Min(64, base64.Length - at)).Append('\n');
        }

        return pem.Append("-----END ").Append(label).Append("-----\n").ToString();
    }

    /// <summary>
    /// Presents one certificate and reports how the attempt ended and what identity the handler
    /// saw. The outcome is classified rather than caught: "the server refused this client" must not
    /// also be satisfied by the server hanging, by the port belonging to something else, or by the
    /// fixture failing to load.
    /// </summary>
    /// <remarks>
    /// The selection callback is the reason this is not <see cref="Client.GetTlsClientCert"/>.
    /// The path route does not hint an anchor it read from a TRUSTED CERTIFICATE block -
    /// SSL_load_client_CA_file reads with PEM_read_bio_X509, which skips one - and a client that
    /// picked its certificate by that hint would send nothing at all, which the server cannot tell
    /// apart from a certificate it refused. Presenting it regardless leaves exactly one thing
    /// deciding the outcome: whether the server trusts the anchor that issued it.
    /// </remarks>
    private static (Client.TlsOutcome Outcome, string Identity) Present(
        int port, string certPath, string keyPath)
    {
        using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certPath, keyPath);

        // SslStream on Linux needs the key associated through a PFX round-trip, exactly as the
        // harness client does it.
        using X509Certificate2 usable = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null);

        try
        {
            using var socket = new TcpClient();
            socket.Connect("127.0.0.1", port);
            socket.ReceiveTimeout = 6000;

            using var ssl = new SslStream(
                socket.GetStream(), leaveInnerStreamOpen: false,
                (_, _, _, _) => true,
                (_, _, _, _, _) => usable);

            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = new X509CertificateCollection { usable },
            });

            // The request is not incidental. Under TLS 1.3 the client's Certificate is sent after
            // the server's Finished, so a server rejecting it has nothing left to interrupt: the
            // handshake returns happily and the alert only arrives on the next read.
            ssl.Write(Encoding.ASCII.GetBytes("GET /who HTTP/1.1\r\nHost: test\r\n\r\n"));
            ssl.Flush();

            (int status, string body) = Client.ReadResponse(ssl);
            return status > 0
                ? (Client.TlsOutcome.Served, body)
                : (Client.TlsOutcome.Dropped, body);
        }
        catch (AuthenticationException)
        {
            return (Client.TlsOutcome.Refused, string.Empty);
        }
        catch (Exception e) when (e is IOException && Inner<AuthenticationException>(e) is not null)
        {
            return (Client.TlsOutcome.Refused, string.Empty);
        }
        catch (Exception e) when (Inner<SocketException>(e) is { SocketErrorCode: SocketError.TimedOut })
        {
            return (Client.TlsOutcome.TimedOut, string.Empty);
        }
        catch (IOException)
        {
            return (Client.TlsOutcome.Dropped, string.Empty);
        }
        catch (Exception e) when (e.Message.Contains("closed before headers", StringComparison.Ordinal))
        {
            return (Client.TlsOutcome.Dropped, string.Empty);
        }

        static T? Inner<T>(Exception e) where T : Exception
        {
            for (Exception? at = e; at is not null; at = at.InnerException)
            {
                if (at is T match)
                {
                    return match;
                }
            }

            return null;
        }
    }

    /// <summary>
    /// The certificate authorities the server listed in its CertificateRequest, read off the wire.
    /// </summary>
    /// <remarks>
    /// Off the wire because there is nowhere else to read them here: SslStream on Linux hands its
    /// selection callback an EMPTY acceptable-issuers array, whatever the server sent. So the
    /// handshake is pinned to TLS 1.2, where CertificateRequest is still plaintext, and the bytes
    /// the client read are teed off on the way past. The request afterwards is what makes an empty
    /// or misparsed result impossible to confuse with a hint that was really empty: the identity
    /// has to come back, so the handshake has to have completed and the certificate has to have
    /// been accepted.
    /// </remarks>
    private static List<string> HintedAuthorities(int port, string certPath, string keyPath)
    {
        using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certPath, keyPath);
        using X509Certificate2 usable = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null);

        using var socket = new TcpClient();
        socket.Connect("127.0.0.1", port);
        socket.ReceiveTimeout = 6000;

        var wire = new Tee(socket.GetStream());
        using var ssl = new SslStream(
            wire, leaveInnerStreamOpen: false,
            (_, _, _, _) => true,
            (_, _, _, _, _) => usable);

        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12,
            ClientCertificates = new X509CertificateCollection { usable },
        });

        ssl.Write(Encoding.ASCII.GetBytes("GET /who HTTP/1.1\r\nHost: test\r\n\r\n"));
        ssl.Flush();

        (int status, string identity) = Client.ReadResponse(ssl);
        Assert.Equal(200, status);
        Assert.Equal("alice", identity);

        return CertificateAuthorities(wire.Seen.ToArray());
    }

    /// <summary>
    /// Walks a recorded server flight - records, then handshake messages - and returns the subject
    /// names carried by the CertificateRequest (type 13). Empty if there was none.
    /// </summary>
    private static List<string> CertificateAuthorities(byte[] fromServer)
    {
        var handshake = new List<byte>();

        for (int at = 0; at + 5 <= fromServer.Length;)
        {
            int type = fromServer[at];
            int length = (fromServer[at + 3] << 8) | fromServer[at + 4];
            if (at + 5 + length > fromServer.Length || type == 20)
            {
                break;   // ChangeCipherSpec: everything past it is encrypted
            }

            if (type == 22)
            {
                handshake.AddRange(new ArraySegment<byte>(fromServer, at + 5, length));
            }

            at += 5 + length;
        }

        byte[] messages = [.. handshake];

        for (int at = 0; at + 4 <= messages.Length;)
        {
            int type = messages[at];
            int length = (messages[at + 1] << 16) | (messages[at + 2] << 8) | messages[at + 3];
            int body = at + 4;

            if (body + length > messages.Length)
            {
                break;
            }

            if (type == 13)
            {
                return Authorities(messages, body, body + length);
            }

            at = body + length;
        }

        return [];
    }

    // certificate_types, then supported_signature_algorithms, then the DER-encoded issuer names -
    // RFC 5246 7.4.4, which is the layout only TLS 1.2 has.
    private static List<string> Authorities(byte[] message, int at, int end)
    {
        at += 1 + message[at];
        at += 2 + ((message[at] << 8) | message[at + 1]);

        int listEnd = Math.Min(at + 2 + ((message[at] << 8) | message[at + 1]), end);
        at += 2;

        var names = new List<string>();
        while (at + 2 <= listEnd)
        {
            int length = (message[at] << 8) | message[at + 1];
            at += 2;

            if (at + length > listEnd)
            {
                break;
            }

            names.Add(new X500DistinguishedName(message[at..(at + length)]).Name);
            at += length;
        }

        return names;
    }

    /// <summary>Passes bytes through and keeps a copy of everything READ, so a plaintext handshake
    /// can be inspected after SslStream has performed it.</summary>
    private sealed class Tee(Stream inner) : Stream
    {
        public MemoryStream Seen { get; } = new();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = inner.Read(buffer, offset, count);
            if (read > 0)
            {
                Seen.Write(buffer, offset, read);
            }

            return read;
        }

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override void Flush() => inner.Flush();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
