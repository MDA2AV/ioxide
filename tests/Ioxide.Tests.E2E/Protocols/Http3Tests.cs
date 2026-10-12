using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// The pure-C# HTTP/3 implementation (ioxide.http3: frames + QPACK + Huffman, no native code)
/// served over the ngtcp2 QUIC engine, driven by the nghttp3-based test client - a genuine
/// cross-implementation check: nghttp3 encodes (Huffman'd literals, static refs), our parser
/// decodes; our encoder answers, nghttp3 decodes.
/// </summary>
internal static class Http3Tests
{
    public static void Register(Runner runner)
    {
        runner.Test("http3: a connection that did not negotiate h3 is not served", () =>
        {
            // A QuicEngine given no ALPN allow list confirms whatever the client offered, which is
            // the constructor's documented default and what every h3 test here used to build. RFC
            // 9114 requires the "h3" token, so serving HTTP/3 over a connection that negotiated
            // "echo" - or nothing at all - is the server speaking a protocol the client never
            // agreed to. Pinning ["h3"] on the engine is the real fix and refuses this during the
            // handshake; this asserts the h3 layer refuses it even on an engine that did not.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);   // permissive, on purpose

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Http3Connection(conn).RunAsync(
                    static req => Http3Response.Text("served")));

            using var client = new H3TestClient("127.0.0.1", udpPort) { Alpn = "echo" };
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000),
                "the permissive engine should still complete the handshake - that is the point");

            (int status, string body) = client.Get("/nope", timeoutMs: 3000);
            Assert.True(status != 200, $"an h3 handler must not serve a non-h3 connection, got {status} '{body}'");
        });

        runner.Test("http3: pure-C# parser GET vs nghttp3 client (loopback)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Http3Connection(conn).RunAsync(
                    static req => Http3Response.Text(
                        $"pure {Encoding.ASCII.GetString(req.Path.Span)} via {Encoding.ASCII.GetString(req.Method.Span)}")));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            (int status, string body) = client.Get("/pure-cs", timeoutMs: 5000);
            Assert.Equal(200, status);
            Assert.Equal("pure /pure-cs via GET", body);
        });

        runner.Test("http3: pure-C# streaming body upload (paced window)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Http3Connection(conn).RunAsync(
                    static async req =>
                    {
                        long total = 0;
                        while (true)
                        {
                            ReadOnlyMemory<byte> chunk = await req.BodyReader!.ReadAsync();
                            if (chunk.IsEmpty)
                            {
                                break;
                            }
                            total += chunk.Length;
                        }
                        return Http3Response.Text($"pure got {total}");
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // 600 KB > the 256 KB stream window: completes only if the parser's immediate credits
            // + sink hand-out credits keep the peer's window opening mid-flight.
            var body = new byte[600_000];
            new Random(11).NextBytes(body);

            (int status, string text) = client.Request("POST", "/upload", body, timeoutMs: 10_000);
            Assert.Equal(200, status);
            Assert.Equal("pure got 600000", text);
        });

        runner.Test("http3: uploads a streaming handler never reads give their connection credit back", () =>
            UnreadUploadsGiveCreditBack((conn, answer) => new Http3Connection(conn).RunAsync(
                async req => new Http3Response { Status = await answer(req.Path, req.BodyReader!.ReadAsync) })));
    }

    /// <summary>The status a test handler answers once it is done with the body behind <c>readBody</c>.</summary>
    internal delegate ValueTask<int> UploadAnswer(ReadOnlyMemory<byte> path, Func<ValueTask<ReadOnlyMemory<byte>>> readBody);

    // Each upload fits its 256 KiB stream window and five cross the connection's 1 MiB one, so only
    // connection credit that never comes back can wedge them.
    private const int UploadBytes = 250 * 1024;
    private const int Uploads = 5;

    /// <summary>
    /// Uploads on three connections to one server: "/read" reads every body to its end, "/unread"
    /// never touches one, and "/unread-after-a-wait" leaves it after a wait on the ring.
    /// </summary>
    internal static void UnreadUploadsGiveCreditBack(Func<QuicConnection, UploadAnswer, Task> serve)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

        long read = 0;
        int unread = 0;
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (reactor, conn) =>
            {
                var timer = new RingTimer(reactor);
                return serve(conn, async (path, readBody) =>
                {
                    if (path.Span.SequenceEqual("/read"u8))
                    {
                        ReadOnlyMemory<byte> chunk;
                        while (!(chunk = await readBody()).IsEmpty)
                        {
                            Interlocked.Add(ref read, chunk.Length);
                        }
                    }
                    else
                    {
                        Interlocked.Increment(ref unread);
                        if (path.Span.SequenceEqual("/unread-after-a-wait"u8))
                        {
                            await timer.DelayAsync(50);
                        }
                    }
                    return 401;
                });
            });

        UploadsOnOneConnection(udpPort, "/read");   // control: the same uploads cross the window when read
        UploadsOnOneConnection(udpPort, "/unread");
        UploadsOnOneConnection(udpPort, "/unread-after-a-wait");

        Assert.Equal(Uploads * (long)UploadBytes, Interlocked.Read(ref read));
        Assert.Equal(2 * Uploads, Volatile.Read(ref unread));
    }

    /// <summary>The uploads to <paramref name="path"/> on one connection, each answered 401.</summary>
    private static void UploadsOnOneConnection(int udpPort, string path)
    {
        Assert.True(Uploads * (long)UploadBytes > 1024 * 1024 && UploadBytes < 256 * 1024,
            "the uploads must cross the connection window while each fits its stream window");

        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

        var body = new byte[UploadBytes];
        for (int i = 1; i <= Uploads; i++)
        {
            int status;
            try
            {
                (status, _) = client.Request("POST", path, body, timeoutMs: 15_000);
            }
            catch (Exception e)
            {
                throw new Exception($"{path}: upload {i} of {Uploads}, {(i - 1) * UploadBytes / 1024} KiB already sent: {e.Message}");
            }
            Assert.True(status == 401, $"{path}: upload {i} of {Uploads} was answered {status}, not 401");
        }

        Assert.True(!client.PeerClosed, $"{path}: the server closed the connection");
    }
}
