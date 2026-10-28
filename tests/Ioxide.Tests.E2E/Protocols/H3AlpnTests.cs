using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// ALPN as HTTP/3 requires it, and what the negotiated protocol reads back as. RFC 9001 section
/// 8.1 makes ALPN mandatory for QUIC (no mutual protocol = no_application_protocol, during the
/// handshake); RFC 9114 section 3.1 makes "h3" the token an HTTP/3 server may serve.
/// </summary>
/// <remarks>
/// Two behaviours in this area were examined and could NOT be driven from this suite, so they are
/// recorded here rather than half-tested:
///
/// - Server preference order with a multi-token offer (the shim's iq_on_client_hello walks the
///   allowlist on the outside, so the server's order decides, like the TCP side's
///   AlpnNegotiationTests pins). The shim's client entry points hand picotls exactly ONE token -
///   a single iovec, count = 1 - so no in-tree client can offer several protocols at once.
///
/// - The negotiated token reading back as nothing when it exceeds the 64-byte read-back buffer
///   (iq_conn_get_alpn returns 0 when the token does not fit the buffer
///   QuicEngineConnection.HandshakeCompletedOnce hands it). A legal ALPN token may be 255 bytes,
///   but the shim's client stores its offer in a char[64] via snprintf, truncating it to 63 - so
///   the shortest token that would trip the server's cap cannot be offered from here. The 63-byte
///   test below pins the longest reachable token instead.
/// </remarks>
internal static class H3AlpnTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic/alpn: control - a pinned engine serves an h3 offer and the handler reads back 'h3'", () =>
        {
            // The control for every refusal below: the same engine shape, the same handler, the
            // one offer an HTTP/3 server may accept - and it serves. Also the only place the
            // SERVER-side NegotiatedProtocol value is asserted: the pure-C# stack consumes it in
            // its backstop, but nothing else pins that the shim's read-back (iq_conn_get_alpn)
            // surfaces the very token the client offered.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    _ => Nghttp3Response.Text($"alpn={conn.NegotiatedProtocol ?? "(none)"}")));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/alpn", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("alpn=h3", body);
        });

        runner.Test("quic/alpn: a pinned engine refuses a no-overlap offer during the handshake, with a close", () =>
        {
            // RFC 9001 section 8.1: no mutual protocol fails the handshake with
            // no_application_protocol. The engine-side allowlist is the real fix for serving h3
            // to clients that never claimed it, and every h3 test site now pins ["h3"] - but the
            // refusal itself was one test deep and asserted only "not served". This pins the
            // stronger half: the handshake never completes, and the refusal ARRIVES as a close.
            // PeerClosed is the load-bearing assert - a server that silently dropped the
            // connection would also fail CompleteHandshake, by timeout, and a hang is not a
            // refusal (it is also not the alert RFC 9001 requires).
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    static _ => Nghttp3Response.Text("must never serve")));

            using var client = new H3TestClient("127.0.0.1", udpPort) { Alpn = "echo" };
            client.Connect();
            bool done = client.CompleteHandshake(timeoutMs: 5000);
            Assert.True(!done, "a pinned engine must not complete a handshake with no ALPN overlap");
            Assert.True(client.PeerClosed,
                "the refusal must arrive as a close during the handshake - a timeout is a hang, not a refusal");
        });

        runner.Test("quic/alpn: a pinned engine refuses a client that offered no ALPN at all", () =>
        {
            // The other half of RFC 9001 section 8.1: a client that offers NOTHING. An empty Alpn
            // makes the shim's client omit the extension entirely (it only hands picotls a list
            // for a non-empty token), and a pinned server must treat that as no overlap - not as
            // "nothing to check". The permissive engine's documented default is to confirm even
            // this; pinning is what closes it, so the pinned refusal is the behaviour to hold.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    static _ => Nghttp3Response.Text("must never serve")));

            using var client = new H3TestClient("127.0.0.1", udpPort) { Alpn = "" };
            client.Connect();
            bool done = client.CompleteHandshake(timeoutMs: 5000);
            Assert.True(!done, "RFC 9001 8.1: a pinned engine must refuse a client that offered no ALPN");
            Assert.True(client.PeerClosed,
                "the refusal must arrive as a close during the handshake - a timeout is a hang, not a refusal");
        });

        runner.Test("quic/alpn: a 63-byte token - the longest the harness can offer - reads back whole", () =>
        {
            // The negotiated token reads back through a 64-byte buffer, and iq_conn_get_alpn
            // answers 0 - "no protocol" - for anything that does not fit, so a shrunk buffer
            // would not fail loudly: it would report a legal negotiated token as none at all.
            // 63 bytes is the longest offer the harness client can make (its own char[64] +
            // snprintf truncation - see the file remarks), which makes it the boundary this
            // suite can hold: the whole token, not empty, not clipped.
            //
            // Recorded at handshake completion rather than through a served response, so this
            // stays true even once the nghttp3 layer learns to refuse non-h3 connections.
            string big = new string('a', 63);
            var recorded = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);

            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));   // permissive: confirms the offer

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) =>
                {
                    ((QuicEngineConnection)conn).HandshakeCompleted =
                        () => recorded.TrySetResult(conn.NegotiatedProtocol);
                    return new Nghttp3Connection(conn).RunAsync(
                        static _ => Nghttp3Response.Text("ok"));
                });

            using var client = new H3TestClient("127.0.0.1", udpPort) { Alpn = big };
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            Assert.True(recorded.Task.Wait(5000), "the server never reported handshake completion");
            Assert.Equal(big, recorded.Task.Result);
        });

        runner.Test("h3/nghttp3: control - a permissive engine serves a connection that negotiated h3", () =>
        {
            // The same engine and handler as the refusal below, with the one offer that may be served.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));   // permissive, as below

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    static _ => Nghttp3Response.Text("served-by-nghttp3")));

            using var client = new H3TestClient("127.0.0.1", udpPort);   // offers "h3"
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("served-by-nghttp3", body);
        });

        runner.Test("h3/nghttp3: a connection that did not negotiate h3 is not served", () =>
        {
            // The mirror of Http3Tests' "a connection that did not negotiate h3 is not served", on
            // the OTHER stack: an engine built without an allowlist - the constructor's documented
            // default - confirms "echo", and the h3 layer must refuse it. Its close code is pinned in
            // H3ErrorCodeTests.
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8));   // permissive, on purpose

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    static _ => Nghttp3Response.Text("served-by-nghttp3")));

            using var client = new H3TestClient("127.0.0.1", udpPort) { Alpn = "echo" };
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000),
                "the permissive engine should still complete the handshake - that is the point");

            (int status, string body) = client.Get("/nope", timeoutMs: 3000);
            Assert.True(status != 200, $"an h3 handler must not serve a non-h3 connection, got {status} '{body}'");
        });

        runner.Test("quic/alpn: a non-ascii allow-list token must not admit a protocol nobody configured", () =>
        {
            // QuicEngine.AlpnWire encoded each configured token with Encoding.ASCII, whose
            // fallback substitutes '?' for anything non-ascii - so ["Ũ2"] went on the wire as the
            // allowlist entry "?2". Two consequences: the configured token itself could never
            // negotiate (a client offering the actual bytes of "Ũ2" found no match), and every
            // non-ascii token collapsed onto '?', so a client offering the literal "?2" was
            // admitted, served, and read back NegotiatedProtocol == "?2" - a protocol nobody
            // configured. The TCP side's BuildAlpnWire had the same shape with a worse symptom
            // (UTF-16 units cast to bytes turn "Ũ2" into the real "h2"). A non-ascii token is now
            // refused at construction, like the >255-byte one; encoding it faithfully would also
            // make this body pass.
            (string certPath, string keyPath) = TestCert.Ensure();
            QuicEngine engine;
            try
            {
                engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["Ũ2"]));
            }
            catch (ArgumentException)
            {
                return;   // refused at configuration - the defect is gone
            }

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                    static _ => Nghttp3Response.Text("must never serve")));

            using var client = new H3TestClient("127.0.0.1", udpPort) { Alpn = "?2" };
            client.Connect();
            Assert.True(!client.CompleteHandshake(timeoutMs: 5000),
                "a client offering '?2' completed the handshake against an allow list of 'Ũ2'");
        });
    }
}
