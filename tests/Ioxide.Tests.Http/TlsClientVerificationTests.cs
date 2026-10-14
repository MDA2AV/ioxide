using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// What the ring-native client checks about a server certificate: the name, wildcards, an address
/// rather than a name, and the chain.
/// </summary>
/// <remarks>
/// This is the one place in the repo where ioxide is the party being PROTECTED rather than the
/// party protecting, so a gap here is a gap in every outbound call a user makes. Every case here
/// drives the real pooled client against an independent server (the BCL's SslStream) holding a
/// certificate minted for that case, so a pass means our verification agrees with somebody else's
/// idea of the certificate rather than only with itself.
///
/// The certificates are minted here rather than through TestCert because each one is deliberately
/// malformed in a different way - a partial wildcard, an address instead of a name, a window that
/// has closed - and a fixture cache exists to hand out the clean shapes.
/// </remarks>
internal static class TlsClientVerificationTests
{
    public static void Register(Runner runner)
    {
        RegisterWildcards(runner);
        RegisterAddresses(runner);
        RegisterChain(runner);
    }

    /// <summary>
    /// Wildcard matching, which the client spells out rather than inheriting whatever OpenSSL's
    /// default hostflags mean this month: SSL_set1_host with X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS.
    /// </summary>
    private static void RegisterWildcards(Runner runner)
    {
        runner.Test("tls client: a partial wildcard must not match (ww*.example.com is not www.example.com)", () =>
        {
            // A certificate issued for 'ww*.example.com' is a certificate for a PREFIX, and the
            // holder of one for 'ww*' can speak for www, wwx and every other name that starts the
            // same way. Nobody issues these deliberately; the reason it matters is that a name
            // constraint or an issuance policy written in terms of whole labels does not see them.
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=partial wildcard origin", dns: ["ww*.example.com"]);
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, "www.example.com", ca.PemPath);

            Assert.True(!body.Contains("verified"),
                $"a partial wildcard should not have authenticated www.example.com, got: {body}");
            Assert.True(body.Contains("certificate verify failed"),
                $"should be refused as a verification failure, got: {body}");
        });

        runner.Test("tls client: control - a full wildcard matches one label below it", () =>
        {
            // The control for the case above, and the reason it is a control: the ONLY difference
            // is the two characters in front of the star. A '*.example.com' certificate is
            // ordinary and has to keep working, so the test above cannot be satisfied by
            // refusing wildcards altogether.
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=wildcard origin", dns: ["*.example.com"]);
            using Origin origin = Origin.Start(leaf);

            Assert.Equal("200|verified", Fetch(origin.Port, "www.example.com", ca.PemPath));
        });

        runner.Test("tls client: a wildcard does not match across a label", () =>
        {
            // '*.example.com' covers one label, not a subtree - so it must not authenticate
            // a.b.example.com. Pinned because the obvious wrong fix for the partial case above is
            // to reach for the hostflags argument and pass the wrong constant:
            // X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS is right next to the one that is wanted and
            // widens matching instead of narrowing it.
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=wildcard origin", dns: ["*.example.com"]);
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, "a.b.example.com", ca.PemPath);
            Assert.True(body.Contains("certificate verify failed"),
                $"a single-label wildcard should not span two labels, got: {body}");
        });
    }

    /// <summary>
    /// An origin reached by its address rather than by a name. The client only ever calls
    /// SSL_set1_host, never SSL_set1_ip_asc - these pin that this is nonetheless correct, because
    /// OpenSSL 3's SSL_set1_host routes a literal address to the IP parameter itself.
    /// </summary>
    private static void RegisterAddresses(Runner runner)
    {
        runner.Test("tls client: an origin reached by its address is verified against the iPAddress SAN", () =>
        {
            // No dNSName at all, and a subject that is deliberately NOT the address: the only
            // thing in this certificate that can authenticate 127.0.0.1 is the iPAddress SAN, so a
            // pass means that SAN was the thing consulted, not a CN fallback.
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=ioxide address origin", ips: [IPAddress.Loopback]);
            using Origin origin = Origin.Start(leaf);

            Assert.Equal("200|verified", Fetch(origin.Port, "127.0.0.1", ca.PemPath));
        });

        runner.Test("tls client: a dNSName holding the literal address does not authenticate that address", () =>
        {
            // The other half, and the half that says the address is treated AS an address: this
            // certificate carries the text '127.0.0.1' as a dNSName and no iPAddress SAN. A
            // hostname comparison would match it string-for-string. It must not.
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=ioxide address origin", dns: ["127.0.0.1"]);
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, "127.0.0.1", ca.PemPath);
            Assert.True(body.Contains("certificate verify failed"),
                $"a dNSName of the literal address must not authenticate it, got: {body}");
        });
    }

    /// <summary>
    /// The ordinary matrix - expired, an anchor we were not given, self-signed, an intermediate the
    /// origin did not send - asserted on the REASON rather than only on the refusal.
    /// </summary>
    private static void RegisterChain(Runner runner)
    {
        runner.Test("tls client: an expired server certificate is refused as a verification failure", () =>
        {
            // Correctly signed by an anchor the client trusts, correct name, and its window closed
            // yesterday. It sits inside the CA's own window because .NET will not issue a leaf that
            // starts before its issuer does.
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=expired origin", dns: [OriginName],
                notBefore: DateTimeOffset.UtcNow.AddDays(-10), notAfter: DateTimeOffset.UtcNow.AddDays(-1));
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, OriginName, ca.PemPath);
            Assert.True(body.Contains("certificate verify failed"),
                $"an expired certificate should be refused as a verification failure, got: {body}");
        });

        runner.Test("tls client: an anchor the client was not given is refused as a verification failure", () =>
        {
            // Valid, in date, and issued by a CA that is simply not the one this client was
            // configured with. Distinct from the existing untrusted-certificate test, which checks
            // a self-signed leaf against the system store.
            using Authority ca = Authority.Mint();
            using Authority stranger = Authority.Mint();
            using X509Certificate2 leaf = ca.Leaf("CN=good origin", dns: [OriginName]);
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, OriginName, stranger.PemPath);
            Assert.True(body.Contains("certificate verify failed"),
                $"an unknown issuer should be refused as a verification failure, got: {body}");
        });

        runner.Test("tls client: a self-signed server certificate is refused as a verification failure", () =>
        {
            using Authority ca = Authority.Mint();
            using X509Certificate2 leaf = SelfSigned("CN=self-signed origin", OriginName);
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, OriginName, ca.PemPath);
            Assert.True(body.Contains("certificate verify failed"),
                $"a self-signed certificate should be refused as a verification failure, got: {body}");
        });

        runner.Test("tls client: a chain missing its intermediate is refused as a verification failure", () =>
        {
            // root -> intermediate -> leaf, with the origin sending the leaf alone. The client
            // holds the root, so every signature in the chain is one it could verify - it just
            // cannot get from the leaf to the root without a certificate nobody sent it. This is
            // the failure that looks like "works on my machine", because a client whose store
            // happens to hold the intermediate is served.
            using Authority ca = Authority.Mint();
            using Authority intermediate = ca.Intermediate("CN=ioxide test intermediate");
            using X509Certificate2 leaf = intermediate.Leaf("CN=deep origin", dns: [OriginName]);
            using Origin origin = Origin.Start(leaf);

            string body = Fetch(origin.Port, OriginName, ca.PemPath);
            Assert.True(body.Contains("certificate verify failed"),
                $"an incomplete chain should be refused as a verification failure, got: {body}");

            // The control, on the same origin and the same bytes on the wire: trusting the
            // intermediate directly completes the chain. So the refusal above was about the gap in
            // the chain and not about anything else being wrong with the leaf.
            using PemFile bundle = PemFile.Write(ca.Certificate, intermediate.Certificate);
            Assert.Equal("200|verified", Fetch(origin.Port, OriginName, bundle.Path));
        });

        runner.Test("tls client: a dropped connection is not reported as a verification failure", () =>
        {
            // The control for every assertion above. 'certificate verify failed' only means
            // something if a connection that fails for an unrelated reason does NOT say it - and
            // the caller's whole ability to act on a certificate problem rests on telling the two
            // apart.
            using Origin origin = Origin.StartClosingImmediately();
            using Authority ca = Authority.Mint();

            string body = Fetch(origin.Port, OriginName, ca.PemPath);
            Assert.True(body.StartsWith("599|"), $"the connection should have failed, got: {body}");
            Assert.True(!body.Contains("certificate verify failed"),
                $"a dropped connection must not be reported as a certificate problem, got: {body}");

            // And it has to name what DID happen, or this control would be satisfied by any
            // failure at all - including the proxy never reaching the origin.
            Assert.True(body.Contains("closed during the TLS handshake"),
                $"should say the connection closed, got: {body}");
        });

        runner.Test("tls client: a verification failure says which check failed", () =>
        {
            // Expired, self-signed and unknown-issuer are three different X509 verify codes (10, 18
            // and 20), and a caller acts on them differently: one is a clock or a renewal, one is
            // an origin misconfigured, one is trust configured wrongly on OUR side. All three
            // used to arrive as the same sentence.
            using Authority trusted = Authority.Mint();
            using Authority stranger = Authority.Mint();

            string expired = Refusal(trusted.PemPath, trusted.Leaf("CN=expired origin", dns: [OriginName],
                notBefore: DateTimeOffset.UtcNow.AddDays(-10), notAfter: DateTimeOffset.UtcNow.AddDays(-1)));
            string selfSigned = Refusal(trusted.PemPath, SelfSigned("CN=self-signed origin", OriginName));
            string unknownIssuer = Refusal(trusted.PemPath, stranger.Leaf("CN=good origin", dns: [OriginName]));

            // Vacuity guard: this must be three refusals that all reached verification, or
            // "they differ" would be satisfied by three unrelated failures.
            foreach (string body in new[] { expired, selfSigned, unknownIssuer })
            {
                Assert.True(body.Contains("certificate verify failed"),
                    $"expected a verification failure, got: {body}");
            }

            // Compared from the handshake message onwards, because the pool's own prefix carries
            // the port and would make three identical reasons look different.
            string[] reasons = [Reason(expired), Reason(selfSigned), Reason(unknownIssuer)];
            Assert.True(reasons.Distinct().Count() == 3,
                "three different verification failures reported the same thing: " + reasons[0]);
        });
    }

    // --- driving the client ----------------------------------------------------------------------

    /// <summary>The name every case that is not about naming uses, so nothing turns on it.</summary>
    private const string OriginName = "origin.example.com";

    private const string HandshakeMarker = "TLS handshake to";

    /// <summary>
    /// Fetch through the pooled client and return "&lt;upstream status&gt;|&lt;detail&gt;" - the
    /// shape the other client suites use. A refused handshake arrives as 599 plus the cause.
    /// </summary>
    private static string Fetch(int originPort, string serverName, string caFile)
    {
        int proxy = StartProxy(originPort, new TlsClientOptions
        {
            ServerName = serverName,
            AlpnProtocols = ["http/1.1"],
            CaFile = caFile,
        });

        (int status, string body) = Client.Get(proxy, "/verify", timeoutMs: 20_000);
        Assert.Equal(200, status);   // the proxy handler always answers; the upstream call is the test
        return body;
    }

    /// <summary>
    /// Serve <paramref name="leaf"/> to a client trusting <paramref name="caFile"/>, and hand back
    /// what the client reported. Takes ownership of the leaf.
    /// </summary>
    private static string Refusal(string caFile, X509Certificate2 leaf)
    {
        using (leaf)
        {
            using Origin origin = Origin.Start(leaf);
            return Fetch(origin.Port, OriginName, caFile);
        }
    }

    /// <summary>The message from the handshake onwards, with the pool's per-run prefix dropped.</summary>
    private static string Reason(string body)
    {
        int at = body.IndexOf(HandshakeMarker, StringComparison.Ordinal);
        Assert.True(at >= 0, $"the handshake failure should reach the caller, got: {body}");
        return body[at..];
    }

    private static int StartProxy(int originPort, TlsClientOptions tlsOptions)
    {
        TlsClientContext tls = TlsClientContext.Create(tlsOptions);

        var options = new HttpClientOptions
        {
            Host = "127.0.0.1",
            Port = (ushort)originPort,
            PoolSize = 1,
            AcquireTimeoutMs = 5_000,
            Tls = tls,
        };

        return TestServer.Start(ProxyHandler, onStart: reactor => HttpClientPool.Start(reactor, options));
    }

    private static async Task ProxyHandler(Reactor reactor, TcpConnection connection)
    {
        try
        {
            HttpClientPool upstream = reactor.GetService<HttpClientPool>()!;

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }
                string path = Wire.ReadPath(connection, snapshot);

                string detail;
                int status;
                try
                {
                    using HttpClientResponse response = await upstream.GetAsync(path);
                    status = response.Status;
                    detail = Encoding.ASCII.GetString(response.Body.Span);
                }
                catch (Exception e)
                {
                    status = 599;
                    detail = e.Message;
                }

                Wire.Write(connection, 200, $"{status}|{detail}");
                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            connection.DecRef();
        }
    }

    // --- fixtures ---------------------------------------------------------------------------------

    /// <summary>
    /// A PEM the client can be pointed at. Deleted when the test that made it finishes: these are
    /// one-off shapes rather than fixtures, and leaving them behind would grow a directory forever
    /// while inviting a later test to reuse one it did not mint.
    /// </summary>
    private sealed class PemFile : IDisposable
    {
        public required string Path { get; init; }

        public static PemFile Write(params X509Certificate2[] certificates)
        {
            // Flat in the temp directory rather than in one of our own: nothing here is a fixture
            // to be found again, so there is no directory to leave behind either.
            string path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"ioxide-httpclient-verify-{Environment.ProcessId}-{Guid.NewGuid():N}.pem");
            File.WriteAllText(path, string.Concat(certificates.Select(c => c.ExportCertificatePem() + "\n")));
            return new PemFile { Path = path };
        }

        public void Dispose()
        {
            try
            {
                File.Delete(Path);
            }
            catch (IOException)
            {
                // Best effort: a leftover PEM in the temp directory is not a test failure.
            }
        }
    }

    /// <summary>A CA that can issue leaves and intermediates, and the PEM a client trusts it by.</summary>
    private sealed class Authority : IDisposable
    {
        public required X509Certificate2 Certificate { get; init; }
        public required PemFile Pem { private get; init; }

        public string PemPath => Pem.Path;

        public static Authority Mint()
        {
            using RSA key = RSA.Create(2048);

            // A distinct subject per authority: two roots with the same name in one process is the
            // sort of coincidence that makes a chain build succeed for the wrong reason.
            var request = new CertificateRequest(
                $"CN=ioxide client-verify root {Guid.NewGuid().ToString("N")[..8]}",
                key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            // Wide enough to hold an expired leaf: .NET refuses to issue one whose notBefore
            // precedes its issuer's, so "expired" has to mean expired INSIDE this window.
            using X509Certificate2 selfSigned = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(365));
            X509Certificate2 ca = Usable(selfSigned);

            return new Authority { Certificate = ca, Pem = PemFile.Write(ca) };
        }

        public Authority Intermediate(string subject)
        {
            using RSA key = RSA.Create(2048);
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            byte[] serial = new byte[8];
            RandomNumberGenerator.Fill(serial);
            using X509Certificate2 signed = request.Create(
                Certificate, DateTimeOffset.UtcNow.AddDays(-20), DateTimeOffset.UtcNow.AddDays(200), serial);
            using X509Certificate2 withKey = signed.CopyWithPrivateKey(key);
            X509Certificate2 intermediate = Usable(withKey);

            return new Authority { Certificate = intermediate, Pem = PemFile.Write(intermediate) };
        }

        public X509Certificate2 Leaf(
            string subject,
            string[]? dns = null,
            IPAddress[]? ips = null,
            DateTimeOffset? notBefore = null,
            DateTimeOffset? notAfter = null)
        {
            using RSA key = RSA.Create(2048);
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var names = new SubjectAlternativeNameBuilder();
            foreach (string name in dns ?? [])
            {
                names.AddDnsName(name);
            }
            foreach (IPAddress ip in ips ?? [])
            {
                names.AddIpAddress(ip);
            }
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

            byte[] serial = new byte[8];
            RandomNumberGenerator.Fill(serial);
            using X509Certificate2 signed = request.Create(
                Certificate,
                notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
                notAfter ?? DateTimeOffset.UtcNow.AddDays(30),
                serial);
            using X509Certificate2 withKey = signed.CopyWithPrivateKey(key);
            return Usable(withKey);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            Pem.Dispose();
        }
    }

    private static X509Certificate2 SelfSigned(string subject, string dns)
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(dns);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

        using X509Certificate2 signed = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return Usable(signed);
    }

    /// <summary>
    /// A PFX round trip, because SslStream on Linux will not present a certificate whose private
    /// key is only attached in memory.
    /// </summary>
    private static X509Certificate2 Usable(X509Certificate2 withKey)
        => X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null);

    // --- the origin --------------------------------------------------------------------------------

    /// <summary>
    /// An HTTPS origin holding one certificate of the caller's choosing. SslStream rather than one
    /// of our own servers, so a served request means our client and an independent implementation
    /// agreed - and so the suite needs no kTLS module to run.
    /// </summary>
    private sealed class Origin : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2? _certificate;
        private readonly CancellationTokenSource _stopping = new();

        public int Port { get; }

        private Origin(TcpListener listener, X509Certificate2? certificate)
        {
            _listener = listener;
            _certificate = certificate;
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        public static Origin Start(X509Certificate2 certificate) => StartCore(certificate);

        /// <summary>Accepts and closes without a handshake: a connection failure that is not a
        /// certificate failure.</summary>
        public static Origin StartClosingImmediately() => StartCore(certificate: null);

        private static Origin StartCore(X509Certificate2? certificate)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var origin = new Origin(listener, certificate);
            _ = origin.AcceptAsync();
            return origin;
        }

        private async Task AcceptAsync()
        {
            while (!_stopping.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stopping.Token);
                }
                catch
                {
                    return;   // stopped
                }

                _ = ServeAsync(client);
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            {
                if (_certificate is null)
                {
                    return;   // close, having said nothing
                }

                SslStream? tls = null;
                try
                {
                    tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        ApplicationProtocols = [new SslApplicationProtocol("http/1.1")],
                    });

                    var request = new byte[8192];
                    while (true)
                    {
                        int n = await tls.ReadAsync(request, _stopping.Token);
                        if (n == 0)
                        {
                            return;   // peer closed
                        }

                        const string body = "verified";
                        byte[] response = Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\n"
                            + $"content-length: {body.Length}\r\n"
                            + "content-type: text/plain\r\n\r\n"
                            + body);
                        await tls.WriteAsync(response, _stopping.Token);
                    }
                }
                catch
                {
                    // A client that rejects this certificate is the POINT of most of these tests,
                    // so the handshake failing here is data rather than an error to report.
                }
                finally
                {
                    tls?.Dispose();
                }
            }
        }

        public void Dispose()
        {
            _stopping.Cancel();
            _listener.Stop();
            _stopping.Dispose();
        }
    }
}
