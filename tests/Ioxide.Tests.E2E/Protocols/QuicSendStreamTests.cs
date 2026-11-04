using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The QUIC engine's per-stream send state: a connection keeps the state of a stream whose send side is done for
/// the next stream that sends, so a warm connection's responses allocate none of it. ioxide.nghttp3 makes no
/// other garbage per request, so what the reactor allocates across its responses is that state alone.
/// </summary>
internal static class QuicSendStreamTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic: a warm connection's responses allocate no send-stream state (nghttp3)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

            const int warm = 16;
            const int measured = 32;
            Nghttp3Response response = Nghttp3Response.Text("ok");   // shared, so the handler allocates nothing
            long[] marks = new long[2];
            int served = 0;

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicHandle: (_, conn) => new Nghttp3Connection(conn).RunAsync(_ =>
                {
                    // On the reactor's thread: what it allocated between these two requests.
                    int n = ++served;
                    if (n == warm)
                    {
                        marks[0] = GC.GetAllocatedBytesForCurrentThread();
                    }
                    else if (n == warm + measured)
                    {
                        marks[1] = GC.GetAllocatedBytesForCurrentThread();
                    }
                    return response;
                }));

            using var client = new H3TestClient("127.0.0.1", udpPort);
            client.Connect();
            Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

            // One stream after another on one connection, so each reuses the state the one before it left.
            for (int i = 0; i < warm + measured; i++)
            {
                (int status, string body) = client.Get($"/{i}", timeoutMs: 5000);
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }

            long perResponse = (marks[1] - marks[0]) / measured;
            Assert.True(perResponse < 64, $"a response on a warm connection allocated {perResponse} B on the reactor");
        });
    }
}
