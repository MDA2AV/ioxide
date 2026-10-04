using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// HTTP/3 responses bigger than a connection's send retention: 16 MiB unacknowledged before a
/// producer has to wait, 32 MiB before the connection is closed as one that ignored the wait. A
/// buffered handler hands its body over whole, so the connection has to feed it out as the peer
/// acks it rather than take it all into retention.
/// </summary>
internal static class H3LargeResponseTests
{
    private static readonly byte[] Big = CreateBody(40 << 20);
    private static readonly byte[] OneMiB = CreateBody(1 << 20);

    private static byte[] CreateBody(int length)
    {
        var body = new byte[length];
        body.AsSpan().Fill((byte)'x');
        return body;
    }

    private static readonly string[] Stacks = ["ioxide.http3", "ioxide.http3 async", "nghttp3"];

    private static Func<Reactor, QuicConnection, Task> ServeBuffered(string stack, byte[] body) => stack switch
    {
        "ioxide.http3" => (_, conn) => new Http3Connection(conn).RunAsync(_ => new Http3Response { Body = body }),
        "ioxide.http3 async" => (_, conn) => new Http3Connection(conn).RunAsync(_ => ValueTask.FromResult(new Http3Response { Body = body })),
        _ => (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(_ => new Nghttp3Response { Body = body }),
    };

    public static void Register(Runner runner)
    {
        foreach (string stack in Stacks)
        {
            string s = stack;

            runner.Test($"h3 buffered ({s}): a response past the send-retention ceiling is served whole", () =>
            {
                using H3TestClient client = Connect(s, Big, out QuicEngine engine);
                using QuicEngine _ = engine;

                (int status, string body) = client.Get("/big", timeoutMs: 60_000);
                Assert.True(status == 200 && body.Length == Big.Length,
                    $"got status {status} and {body.Length} of {Big.Length} bytes: the connection was closed at the backstop");
            });

            runner.Test($"h3 buffered ({s}): 40 one-MiB responses at once on one connection are all served", () =>
            {
                // The shape that found it: h2load's 32 streams of 1 MiB each, handed over together.
                using H3TestClient client = Connect(s, OneMiB, out QuicEngine engine);
                using QuicEngine _ = engine;

                (int Status, long BodyLength)[] responses = client.GetConcurrent(
                    Enumerable.Range(0, 40).Select(i => $"/part/{i}").ToArray(), timeoutMs: 60_000);

                int whole = responses.Count(r => r.Status == 200 && r.BodyLength == OneMiB.Length);
                Assert.True(whole == responses.Length,
                    $"{whole} of {responses.Length} responses arrived whole: the connection was closed at the backstop");
            });
        }

        runner.Test("h3 streamed (ioxide.http3): a response past the send-retention high-water completes", () =>
        {
            // The buffered path's capacity callback must not displace the streamed one: a writer
            // parked at the high-water is resumed by it.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            const int Chunks = 320;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: static (_, conn) => new Http3Connection(conn).RunStreamedResponseAsync(
                    static async (_, writer) =>
                    {
                        writer.WriteHeaders(new Http3Response { Status = 200 });
                        for (int i = 0; i < Chunks; i++)
                        {
                            writer.GetSpan(64 * 1024)[..(64 * 1024)].Fill((byte)'x');
                            writer.Advance(64 * 1024);
                            await writer.FlushAsync();
                        }
                    }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5_000), "handshake did not complete");

            (int status, string body) = client.Get("/big", timeoutMs: 30_000);
            Assert.True(status == 200 && body.Length == Chunks * 64 * 1024,
                $"got status {status} and {body.Length} of {Chunks * 64 * 1024} bytes: the response stalled at the high-water");
        });
    }

    private static H3TestClient Connect(string stack, byte[] body, out QuicEngine engine)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: ServeBuffered(stack, body));

        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5_000), "handshake did not complete");
        return client;
    }
}
