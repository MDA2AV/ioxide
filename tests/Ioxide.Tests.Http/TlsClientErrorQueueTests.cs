using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// One pooled upstream connection's failure affecting another, through state they share by being
/// on the same reactor: OpenSSL's error queue belongs to the THREAD, and SSL_get_error consults it
/// BEFORE asking the SSL whether it merely wants more data.
///
/// The client used to poison that queue on teardown: TlsClientStream.Dispose called SSL_shutdown
/// on a handshake that never finished - which every failed handshake does on its way out - and
/// that call fails and leaves "shutdown while in init" (0A000197) on the reactor's queue. Where
/// the residue lands matters, and it is narrower than the folklore version:
///
///   - a later HANDSHAKE is immune, because OpenSSL's own state machine calls ERR_clear_error at
///     entry - verified against this box's libssl 3.0.13, and end to end against the pre-fix
///     build, where every retry still failed with its own error and never the residue;
///   - an ESTABLISHED connection is not: its next SSL_read that merely needs more bytes is
///     classified from the queue first, so the residue turns "want read" into a fatal
///     SSL_ERROR_SSL and a healthy pooled connection dies. Verified against libssl directly:
///     the same blocked read classifies 2 (WANT_READ) on a clean queue and 1 (SSL_ERROR_SSL)
///     with only the residue planted.
///
/// So the regression pin here drives the real victim: an established connection that must survive
/// a neighbouring connection's failed-handshake teardown. The recovery tests around it pin the
/// rest of the behaviour and say what they do NOT pin.
///
/// All of the above is OpenSSL. BoringSSL clears the queue on entry to SSL_read, SSL_write,
/// SSL_shutdown and the handshake, so the victim cannot be produced on it at all; the pins stay
/// for the teardown and the pool.
/// </summary>
internal static class TlsClientErrorQueueTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tls client: another connection's failed handshake does not kill an established connection on the same reactor", () =>
        {
            // The origin serves its FIRST accept properly and answers every later handshake with
            // bytes that are not TLS. A pool of two on the single test reactor then holds exactly
            // one established connection while its second opener fails, is torn down, and is
            // retried behind the backoff gate - a failed-handshake teardown every few hundred
            // milliseconds on the thread whose error queue the established connection shares.
            using var origin = new FlakyTlsOrigin { Mode = FlakyTlsOrigin.OriginMode.Sabotage, ServeFirstAccept = true };
            int proxy = StartProxy(origin.Port, poolSize: 2);

            (int status, string body) = Client.Get(proxy, "/warm", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body == "200|hello over TLS",
                $"the served connection should be established and answering, got: {body}");

            // Require a FRESH sabotaged handshake after that response, so its teardown runs while
            // the established connection sits idle - not before the connection existed, when the
            // next handshake's own entry into OpenSSL would have wiped the queue anyway.
            int seen = origin.SabotagedHandshakes;
            WaitUntil(() => origin.SabotagedHandshakes > seen,
                "the pool stopped retrying its failing second connection, so no failed-handshake "
                + "teardown ran beside the established connection and this test proved nothing");

            // The established connection's next response read begins with an SSL_read on an empty
            // buffer - a classification that happens BEFORE any socket recv - so with the old
            // teardown this request died as "SSL_read failed (error 1): ... shutdown while in
            // init" without the origin misbehaving on this connection at all.
            (status, body) = Client.Get(proxy, "/after-poison", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body == "200|hello over TLS",
                $"the established connection must survive its neighbour's teardown, got: {body}");
        });

        runner.Test("tls client: after every handshake to an origin failed, a later connect on the same reactor succeeds", () =>
        {
            // Recovery, pinned deliberately: repeated failed handshakes (and their teardowns) must
            // leave the reactor able to connect the moment the origin behaves. NOTE what this does
            // not pin: it stayed green even against the pre-fix teardown, because a handshake
            // self-clears the queue on entry - the test above is the one that discriminates.
            using var origin = new FlakyTlsOrigin { Mode = FlakyTlsOrigin.OriginMode.Sabotage };
            int proxy = StartProxy(origin.Port, poolSize: 1);

            (int status, string body) = Client.Get(proxy, "/poison", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body.StartsWith("599|"), $"the sabotaged handshake should have failed, got: {body}");
            Assert.True(body.Contains("TLS handshake to 'localhost' failed"),
                $"the failure should be the TLS handshake itself, not a refused connect or a bare timeout, got: {body}");
            Assert.True(origin.SabotagedHandshakes >= 1,
                "the origin never sabotaged a handshake, so no teardown ran and this test proved nothing");

            origin.Mode = FlakyTlsOrigin.OriginMode.Serve;
            (status, body) = Client.Get(proxy, "/after", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body == "200|hello over TLS",
                $"a fresh connection after the origin recovered must succeed, got: {body}");
        });

        runner.Test("tls client: a connection killed mid-session is replaced cleanly on the same reactor", () =>
        {
            // The other entry into the same teardown: a handshake that COMPLETED and then died on
            // a fatal record. OpenSSL flips such a session back to "in init" when it errors
            // (verified against libssl 3.0.13), so an unconditional SSL_shutdown in Dispose queues
            // the same residue here - this is the case a guard of the form "the handshake
            // finished, so shutdown is safe" would miss. Like the recovery test above, the
            // replacement HANDSHAKE could not be poisoned even pre-fix; this pins that the pool
            // discards the corpse and the reactor keeps serving.
            using var origin = new FlakyTlsOrigin { Mode = FlakyTlsOrigin.OriginMode.Serve };
            int proxy = StartProxy(origin.Port, poolSize: 1);

            origin.ArmInjection();
            (int status, string body) = Client.Get(proxy, "/kill", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body.StartsWith("599|"), $"the injected garbage should have failed the request, got: {body}");
            Assert.True(body.Contains("SSL_read failed"),
                $"the failure should be a fatal TLS record on an established session, got: {body}");
            Assert.True(origin.InjectedSessions == 1,
                "the origin never injected garbage into an established session, so this test proved nothing");

            (status, body) = Client.Get(proxy, "/replaced", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body == "200|hello over TLS",
                $"the pool must replace the killed connection and serve again, got: {body}");
        });
    }

    private static void WaitUntil(Func<bool> condition, string orElse)
    {
        long deadlineMs = Environment.TickCount64 + 20_000;
        while (!condition())
        {
            Assert.True(Environment.TickCount64 < deadlineMs, orElse);
            Thread.Sleep(50);
        }
    }

    // A TCP endpoint whose handler fetches from the flaky TLS origin through the pooled client and
    // writes back "<upstream status>|<detail>" - the shape TlsClientTests uses. The TestServer
    // reactor is single (the harness stamps ReactorCount = 1), so every pooled upstream connection
    // shares one thread, which is what makes its error queue shared state.
    private static int StartProxy(int originPort, int poolSize)
    {
        (string certPath, _) = TestCert.Ensure();

        TlsClientContext tls = TlsClientContext.Create(new TlsClientOptions
        {
            ServerName = "localhost",
            AlpnProtocols = ["http/1.1"],
            CaFile = certPath,          // the origin's cert is self-signed, so it is its own root
        });

        var options = new HttpClientOptions
        {
            Host = "127.0.0.1",
            Port = (ushort)originPort,
            PoolSize = poolSize,
            AcquireTimeoutMs = 4_000,
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

    /// <summary>
    /// A TLS origin whose behaviour the test controls per accept, so one pool aimed at one port
    /// can hold an established connection while its neighbours fail. Serve mode is SslStream, like
    /// TlsTestOrigin - an independent implementation, so agreement means more than agreeing with
    /// ourselves.
    /// </summary>
    private sealed class FlakyTlsOrigin : IDisposable
    {
        public enum OriginMode
        {
            /// <summary>Answer the ClientHello with bytes that are not TLS, then close.</summary>
            Sabotage,

            /// <summary>Behave: handshake and serve one small response per request.</summary>
            Serve,
        }

        private readonly TcpListener _listener;
        private readonly X509Certificate2 _certificate;
        private readonly CancellationTokenSource _stopping = new();
        private int _accepts;
        private int _sabotagedHandshakes;
        private int _injectedSessions;
        private int _injectionArmed;

        // Written by the test thread between phases, read by the accept loop.
        private volatile OriginMode _mode;
        public OriginMode Mode { get => _mode; set => _mode = value; }

        /// <summary>Serve the first accept regardless of <see cref="Mode"/>, so a pool can hold
        /// one established connection while every later handshake is sabotaged.</summary>
        public bool ServeFirstAccept { get; init; }

        public int Port { get; }

        /// <summary>Handshakes answered with non-TLS bytes - the proof a failed-handshake
        /// teardown actually ran on the client.</summary>
        public int SabotagedHandshakes => Volatile.Read(ref _sabotagedHandshakes);

        /// <summary>Established sessions killed by an injected raw record.</summary>
        public int InjectedSessions => Volatile.Read(ref _injectedSessions);

        /// <summary>The next request received on ANY established session is answered with garbage
        /// written under the TLS layer, exactly once, so the client's SSL_read fails fatally.</summary>
        public void ArmInjection() => Interlocked.Exchange(ref _injectionArmed, 1);

        public FlakyTlsOrigin()
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            X509Certificate2 certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);

            // SslStream on Linux needs the private key associated through a PFX round-trip; a
            // PEM-built certificate carries the key in a form AuthenticateAsServerAsync won't use.
            _certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);

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

                bool serve = _mode == OriginMode.Serve
                    || (ServeFirstAccept && Interlocked.Increment(ref _accepts) == 1);
                _ = ServeAsync(client, serve);
            }
        }

        private async Task ServeAsync(TcpClient client, bool serve)
        {
            using (client)
            {
                SslStream? tls = null;
                try
                {
                    NetworkStream raw = client.GetStream();

                    if (!serve)
                    {
                        // Not a bare close: a first byte that cannot be a TLS content type makes
                        // SSL_connect fail deterministically, where a close can surface as either
                        // FIN or RST depending on what was left unread.
                        await raw.WriteAsync("GARBAGE, NOT A TLS RECORD\r\n"u8.ToArray(), _stopping.Token);
                        Interlocked.Increment(ref _sabotagedHandshakes);
                        return;
                    }

                    tls = new SslStream(raw, leaveInnerStreamOpen: false);
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

                        if (Interlocked.Exchange(ref _injectionArmed, 0) == 1)
                        {
                            // Under the TLS layer, so the client's record layer sees it raw.
                            await raw.WriteAsync("GARBAGE, NOT A TLS RECORD\r\n"u8.ToArray(), _stopping.Token);
                            Interlocked.Increment(ref _injectedSessions);
                            return;
                        }

                        const string body = "hello over TLS";
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
                    // A client that walked away from a sabotaged exchange is the point here, so a
                    // failure is data rather than an error to report.
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
}
