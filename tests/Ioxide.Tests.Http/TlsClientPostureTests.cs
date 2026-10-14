using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// The client's own posture knobs: protocol floor, ALPN, and where its trust comes from. Each test
/// asserts the option TOOK EFFECT on the wire - a peer outside the stated posture is turned away
/// while one inside it is served - not that setting it was accepted.
/// </summary>
/// <remarks>
/// Examined without a failing result, stated so they are not re-litigated: MinimumVersion = 0 is
/// accepted and is BoringSSL's default floor, TLS 1.2 - the client's own default, so nothing is
/// weakened; a ServerName over 255 bytes is refused by SSL_set_tlsext_host_name, so the connect
/// fails rather than going out without SNI; and the client has no in-memory CA source, so the
/// file/in-memory equivalence question the server answers cannot arise.
/// </remarks>
internal static class TlsClientPostureTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tls client: a TLS 1.3 floor refuses a 1.2-capped origin and still serves a 1.3 one", () =>
        {
            // The defect this pins was real and is fixed: MinimumVersion went to SSL_CTX_ctrl and
            // the return was DISCARDED, so a floor OpenSSL did not apply was silently the default.
            // Nothing end-to-end held the fix in place; this does, from the wire.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var capped = new PosturedOrigin(certPath, keyPath, SslProtocols.Tls12);

            // Control first, on the DEFAULT floor (1.2): served, and the origin's body names
            // Tls12, which proves the cap on the origin is real - without this, the refusal below
            // could be any broken origin.
            int control = StartProxy(capped.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = certPath,
            });
            (int status, string body) = Client.Get(control, "/floor-control", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.Equal("200|hello over Tls12", body);

            // The ONLY change from the control is the floor. The 1.2-capped origin must now be
            // refused, and for the version - not a certificate or a timeout.
            int pinned = StartProxy(capped.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = certPath,
                MinimumVersion = OpenSslVersions.Tls13,
            });
            (status, body) = Client.Get(pinned, "/floor-pinned", timeoutMs: 20_000);
            Assert.Equal(200, status);   // the proxy answers; the upstream outcome is in the body
            Assert.True(body.StartsWith("599|"),
                $"a TLS 1.3 floor should refuse an origin capped at 1.2, got: {body}");
            Assert.True(body.Contains("protocol", StringComparison.OrdinalIgnoreCase),
                $"the refusal should name the protocol version, got: {body}");

            // And the floor is a floor, not a breaker: an origin that can speak 1.3 is served,
            // at 1.3.
            using var modern = new PosturedOrigin(certPath, keyPath, SslProtocols.None);
            int strict = StartProxy(modern.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = certPath,
                MinimumVersion = OpenSslVersions.Tls13,
            });
            (status, body) = Client.Get(strict, "/floor-modern", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.Equal("200|hello over Tls13", body);
        });

        runner.Test("tls client: a MinimumVersion BoringSSL will not accept fails Create, not silently the default floor", () =>
        {
            // MinimumVersion is a bare int. A value the library does not recognise comes back 0
            // with NOTHING applied - OpenSSL did not even queue an error - so before the return was
            // checked, a typo'd floor meant the default floor with no way to find out. The refusal
            // has to be loud and has to name the call.
            Assert.Throws<IOException>(() =>
            {
                using TlsClientContext _ = TlsClientContext.Create(new TlsClientOptions
                {
                    ServerName = "localhost",
                    MinimumVersion = 0x0305,   // one past TLS 1.3 - the off-by-one typo shape
                });
            }, because: "set_min_proto_version");

            Assert.Throws<IOException>(() =>
            {
                using TlsClientContext _ = TlsClientContext.Create(new TlsClientOptions
                {
                    ServerName = "localhost",
                    MinimumVersion = 0x0034,   // 0x0304 with a dropped digit
                });
            }, because: "set_min_proto_version");

            // The control for both is every other test in this file constructing a context with a
            // documented version and being served.
        });

        runner.Test("tls client: trust is exactly the CaFile - a chain it anchors is served, one it does not is refused", () =>
        {
            // The existing suite only ever trusts a SELF-SIGNED origin through CaFile (the leaf is
            // its own anchor), and only refuses against the SYSTEM store. This pins the other two
            // corners: a real CA -> leaf chain verifies through CaFile, and a well-formed chain
            // anchored OUTSIDE the file is refused - CaFile decides, not whatever else is lying
            // around.
            (string ca, string cert, string key) = TestCert.EnsureNamedFromCa("localhost");
            using var origin = new PosturedOrigin(cert, key, SslProtocols.None);

            int inside = StartProxy(origin.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = ca,
            });
            (int status, string body) = Client.Get(inside, "/ca-inside", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.True(body.StartsWith("200|hello over "),
                $"a chain anchored in CaFile should verify, got: {body}");

            // Same origin, and the ONLY change is the anchor: a trust file that never signed this
            // chain. Refused for verification, not for a connect or a timeout.
            (string stranger, _) = TestCert.Ensure();
            int outside = StartProxy(origin.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = stranger,
            });
            (status, body) = Client.Get(outside, "/ca-outside", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.True(body.StartsWith("599|"),
                $"a chain anchored outside CaFile should be refused, got: {body}");
            Assert.True(body.Contains("certificate verify failed"),
                $"should name the verification failure, got: {body}");
        });

        runner.Test("tls client: a non-ascii alpn protocol must not be offered as a different protocol", () =>
        {
            // TlsClientContext.BuildAlpnWire writes (byte)protocol[i] - the LOW BYTE of each UTF-16
            // unit. U+0168 has low byte 0x68, 'h', so a client configured to offer ONLY
            // "Ũ" + "2" put the exact bytes "h2" on the wire, the origin selected h2, and
            // NegotiatedAlpn reported a protocol the caller never configured. The server side had
            // the same cast; this is the client half. Create now refuses a non-ASCII name.
            string exotic = "Ũ" + "2";

            using TlsTestOrigin origin = TlsTestOrigin.Start("h2");   // speaks ONLY h2
            (string certPath, _) = TestCert.Ensure();

            // Control: a genuine h2 offer against this origin negotiates h2 and converses. So if
            // the exotic probe below also lands "hello over h2", it is the cast - not environment.
            int control = StartProxy(origin.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["h2"],
                CaFile = certPath,
            });
            (int status, string body) = Client.Get(control, "/alpn-control", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.Equal("200|hello over h2", body);

            int proxy;
            try
            {
                proxy = StartProxy(origin.Port, new TlsClientOptions
                {
                    ServerName = "localhost",
                    AlpnProtocols = [exotic],
                    CaFile = certPath,
                });
            }
            catch (Exception e) when (e is ArgumentException || e.Message.Contains("ALPN") || e.Message.Contains('Ũ'))
            {
                // Refusing the configuration loudly is the other acceptable resolution. Narrow on
                // purpose: an unrelated failure to start must stay a failure, not a quiet pass.
                return;
            }

            (status, body) = Client.Get(proxy, "/alpn-exotic", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.True(!body.EndsWith("hello over h2"),
                "a client configured to offer only 'U+0168 2' completed a conversation the origin "
                + $"negotiated as h2; body: {body}, origin saw alpn={origin.LastAlpn ?? "none"}");
        });

        runner.Test("tls client: HandshakeTimeoutMs bounds a handshake whose peer accepted and went silent", () =>
        {
            // The option says "how long the handshake may take before the connect fails", but
            // RunHandshakeAsync used to check its deadline only BETWEEN flights. A peer that accepts
            // the TCP connect and then never answers the ClientHello - the one peer a handshake
            // timeout exists for - left the connect parked in RecvAsync, where the deadline was
            // never consulted. Through the pool that surfaced as the ACQUIRE timeout with no
            // reason (the open never failed - it was still parked); for a direct
            // TlsClientContext.ConnectAsync caller there was no second timeout, and the await
            // never completed.
            using var tarpit = new TarpitOrigin();
            (string certPath, _) = TestCert.Ensure();

            int proxy = StartProxy(tarpit.Port, new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = certPath,
                HandshakeTimeoutMs = 750,
            }, acquireTimeoutMs: 4_000);

            (int status, string body) = Client.Get(proxy, "/tarpit", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.True(body.StartsWith("599|"),
                $"nothing should have been served by an origin that never answered, got: {body}");

            // Guard against passing vacuously: the tarpit really was reached and held the socket.
            Assert.True(tarpit.Accepted > 0, "the connect never reached the tarpit, so nothing was proven");

            // The claim: the failure the caller sees names the handshake deadline. It used to be
            // the pool's own acquire timeout with no cause attached, because the open was still
            // parked when it fired.
            Assert.True(body.Contains("did not complete within"),
                $"the handshake deadline should have fired and been named, got: {body}");
        });

        runner.Test("tls client: HandshakeTimeoutMs bounds a direct ConnectAsync whose peer accepted and went silent", () =>
        {
            // The same tarpit without the pool: a direct TlsClientContext.ConnectAsync has no
            // acquire timeout behind it, so the handshake deadline is the only bound it has.
            using var tarpit = new TarpitOrigin();
            (string certPath, _) = TestCert.Ensure();
            TlsClientContext tls = TlsClientContext.Create(new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = certPath,
                HandshakeTimeoutMs = 750,
            });

            int port = TestServer.Start((reactor, connection) => DirectConnectHandler(reactor, connection, tarpit.Port, tls));

            (int status, string body) = Client.Get(port, "/tarpit-direct", timeoutMs: 20_000);
            Assert.Equal(200, status);
            Assert.True(tarpit.Accepted > 0, "the connect never reached the tarpit, so nothing was proven");
            Assert.True(body.Contains("did not complete within 750 ms"),
                $"the handshake deadline should have ended the connect, got: {body}");
        });
    }

    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// An SslStream origin like <see cref="TlsTestOrigin"/>, with the two knobs these tests need
    /// that it does not offer: the certificate to serve, and a protocol-version cap. The response
    /// body names the negotiated version, so a test can assert which TLS actually ran rather than
    /// that a handshake happened.
    /// </summary>
    private sealed class PosturedOrigin : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _certificate;
        private readonly SslProtocols _protocols;
        private readonly CancellationTokenSource _stopping = new();

        public int Port { get; }

        public PosturedOrigin(string certPath, string keyPath, SslProtocols protocols)
        {
            using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            // SslStream on Linux needs the key associated through a PFX round-trip.
            _certificate = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null);
            _protocols = protocols;

            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = AcceptLoopAsync();
        }

        private async Task AcceptLoopAsync()
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
                SslStream? tls = null;
                try
                {
                    tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        ApplicationProtocols = [new SslApplicationProtocol("http/1.1")],
                        EnabledSslProtocols = _protocols,
                    });

                    var request = new byte[8192];
                    while (true)
                    {
                        int n = await tls.ReadAsync(request, _stopping.Token);
                        if (n == 0)
                        {
                            return;   // peer closed
                        }

                        string body = $"hello over {tls.SslProtocol}";
                        byte[] response = Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\n" +
                            $"content-length: {body.Length}\r\n" +
                            "content-type: text/plain\r\n\r\n" +
                            body);
                        await tls.WriteAsync(response, _stopping.Token);
                    }
                }
                catch
                {
                    // A refused handshake is the point of several tests; failure here is data.
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
            _certificate.Dispose();
            _stopping.Dispose();
        }
    }

    /// <summary>
    /// The peer that accepts and then says nothing, ever: no ServerHello, no close. What a stalled
    /// middlebox or a wedged origin looks like, and the case a handshake timeout exists for.
    /// </summary>
    private sealed class TarpitOrigin : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _stopping = new();
        private readonly List<TcpClient> _held = [];

        public int Port { get; }
        public int Accepted;

        public TarpitOrigin()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = AcceptLoopAsync();
        }

        private async Task AcceptLoopAsync()
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

                lock (_held)
                {
                    _held.Add(client);   // held open and never read: the peer went silent, not away
                }
                Interlocked.Increment(ref Accepted);
            }
        }

        public void Dispose()
        {
            _stopping.Cancel();
            _listener.Stop();
            lock (_held)
            {
                foreach (TcpClient client in _held)
                {
                    client.Dispose();
                }
            }
            _stopping.Dispose();
        }
    }

    // A TCP endpoint whose handler fetches from the TLS origin through the pooled client and
    // writes back "<upstream status>|<detail>" - the same shape TlsClientTests uses, duplicated
    // here because its copy is private to that file.
    private static int StartProxy(int originPort, TlsClientOptions tlsOptions, int acquireTimeoutMs = 5_000)
    {
        TlsClientContext tls = TlsClientContext.Create(tlsOptions);

        var options = new HttpClientOptions
        {
            Host = "127.0.0.1",
            Port = (ushort)originPort,
            PoolSize = 1,
            AcquireTimeoutMs = acquireTimeoutMs,
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

    // One TLS connect straight to the origin, no pool, answered with how it ended.
    private static async Task DirectConnectHandler(Reactor reactor, TcpConnection connection, int originPort,
        TlsClientContext tls)
    {
        try
        {
            RecvSnapshot snapshot = await connection.ReadAsync();
            if (snapshot.IsClosed)
            {
                return;
            }
            Wire.ReadPath(connection, snapshot);

            string detail;
            RingSocket socket = RingSocket.CreateTcp(reactor);
            int connected = await socket.ConnectAsync("127.0.0.1", (ushort)originPort);
            if (connected < 0)
            {
                socket.Dispose();
                detail = $"connect failed: errno {-connected}";
            }
            else
            {
                try
                {
                    using TlsClientStream stream = await tls.ConnectAsync(socket);   // owns the socket from here
                    detail = "handshake completed";
                }
                catch (IOException e)
                {
                    detail = e.Message;
                }
            }

            Wire.Write(connection, 200, detail);
            await connection.FlushAsync();
        }
        finally
        {
            connection.DecRef();
        }
    }
}
