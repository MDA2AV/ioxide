using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// WHEN a QUIC peer counts as authenticated, as distinct from whether its chain validated.
/// </summary>
/// <remarks>
/// The native shim (<c>ioxide_ngtcp2_shim.c</c>, <c>iq_verify_certificate</c>) flips
/// <c>peer_authenticated</c> the moment the client Certificate message validates - before
/// CertificateVerify has proved possession of the private key and before the client Finished. The
/// managed accessors (<see cref="QuicEngineConnection.PeerSubject"/> /
/// <see cref="QuicEngineConnection.PeerCommonName"/>) gate on the connection being alive, not on the
/// handshake being complete, and the application holds the connection object from the accept path,
/// which fires pre-handshake.
///
/// The concern is that an identity could be read from a connection whose handshake has not
/// completed. This pass tried to observe exactly that and could not: on the single-threaded reactor
/// the whole Certificate-through-Finished window lives inside one <c>iq_conn_read</c> call, no
/// application-reachable hook fires during it (the h3 handler parks on stream data, which needs
/// 1-RTT keys; 0-RTT is unreachable because the shim installs no ticket encryptor), and the C
/// accessors themselves gate on <c>peer_authenticated</c>, which is unset at every point the
/// application can read. So there is no PEND here - the window is genuine in the native layer but
/// not observable through any supported, deterministic surface.
///
/// What is committed instead pins the reachable half of the guarantee: the identity is absent when
/// the application first holds the connection (the accept/handler-launch point, before the client
/// has even been asked for a certificate) and present only once the handshake has completed. A
/// regression that recorded the identity earlier - at accept, in <c>iq_accept</c>, or by dropping
/// the <c>peer_authenticated</c> gate on the accessors - would turn the accept-time read non-null
/// and fail this test. It does NOT prove the sub-handshake window is closed; nothing deterministic
/// can, and that is stated so the guard is not mistaken for more than it is.
/// </remarks>
internal static class QuicClientCertTimingTests
{
    public static void Register(Runner runner)
    {
        // A valid client (CN=alice) whose chain the server trusts. The handler reads the identity
        // twice on the same connection: synchronously at launch (the accept point, before the first
        // datagram is even fed to ngtcp2 - see Reactor.Quic adopt path) and again inside the request
        // handler once the handshake has completed. Both observations ride back in the response body,
        // so the assertion runs on bytes that crossed the wire rather than on cross-thread field
        // reads. The post-handshake "alice" is what makes the accept-time absence non-vacuous: the
        // certificate path really did produce an identity, so its absence earlier is a real absence.
        runner.Test("mtls/quic: the client identity is absent at accept and present only once the handshake completes", () =>
        {
            (string ca, string serverCert, string serverKey,
             string clientCert, string clientKey, _, _) = TestCert.EnsureMutualTls();

            var engine = TestServer.Own(new QuicEngine(serverCert, serverKey, cidLength: 8, alpn: ["h3"],
                clientCaPemPath: ca, requireClientCertificate: true));

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) =>
                {
                    var qc = conn as QuicEngineConnection;

                    // The accept point: the handler is launched before ngtcp2 is fed the first
                    // packet, and long before the client is asked for a certificate. Nothing here
                    // proved an identity, so nothing must be readable.
                    string acceptSubject = qc?.PeerSubject ?? "<null>";
                    string acceptCommonName = qc?.PeerCommonName ?? "<null>";

                    return new Nghttp3Connection(conn).RunBufferedAsync(
                        _ => new Nghttp3Response
                        {
                            // Read again post-handshake, then hand both moments back. Same reactor
                            // thread, program order, so the request read sees the accept-time values.
                            Body = Encoding.ASCII.GetBytes(
                                $"acceptSubject={acceptSubject};" +
                                $"acceptCommonName={acceptCommonName};" +
                                $"requestSubject={qc?.PeerSubject ?? "<null>"};" +
                                $"requestCommonName={qc?.PeerCommonName ?? "<null>"}"),
                        });
                });

            using var client = new H3TestClient("127.0.0.1", udpPort, clientCert, clientKey);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);

            // Post-handshake: the identity is there and correct. This has to hold first, or the
            // absence below is vacuous - a handler that never saw a certificate would also report
            // <null> at accept.
            Assert.True(body.Contains("requestCommonName=alice"),
                $"once the handshake completed the handler should name the client, got: {body}");
            Assert.True(body.Contains("requestSubject=") && body.Contains("alice"),
                $"the request-time subject should carry the client's DN, got: {body}");

            // At accept - before CertificateVerify, before Finished, before the client was even
            // asked for a certificate - neither accessor may name anyone.
            Assert.True(body.Contains("acceptCommonName=<null>"),
                $"a peer common name was readable at accept, before the handshake completed: {body}");
            Assert.True(body.Contains("acceptSubject=<null>"),
                $"a peer subject was readable at accept, before the handshake completed: {body}");
        });
    }
}
