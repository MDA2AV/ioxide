using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>The read timeout over QUIC: keep-alive while a response is owed, and only then.</summary>
internal static class QuicReadTimeoutTests
{
    private const int ReadTimeoutMs = 500;

    private const int ExchangeMs = 10_000;

    public static void Register(Runner runner)
    {
        runner.Test("quic read timeout: a request answered after longer than the read timeout still gets its response", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: ReadTimeoutMs,
                quicHandle: SlowEcho(4 * ReadTimeoutMs, torndown));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            client.SendRequest("slow-but-here"u8.ToArray());
            Assert.Equal("slow-but-here", client.WaitForEcho(ExchangeMs));
            Assert.True(!torndown.Task.IsCompleted, "the connection was torn down while its request was being answered");
        });

        runner.Test("quic read timeout: once answered, a peer that only acknowledges is reaped", () =>
        {
            // The client ACKs whatever arrives, so pings that never stopped would keep it alive.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: ReadTimeoutMs,
                quicHandle: SlowEcho(2 * ReadTimeoutMs, torndown));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            client.SendRequest("answered"u8.ToArray());
            Assert.Equal("answered", client.WaitForEcho(ExchangeMs));

            client.Converse(8 * ReadTimeoutMs);
            Assert.True(torndown.Task.IsCompleted,
                "the connection outlived the read timeout with nothing owed - the keep-alive never stopped");
        });
    }

    // Echoes each request once its stream has finished arriving, after delayMs.
    private static Func<Reactor, QuicConnection, Task> SlowEcho(int delayMs, TaskCompletionSource torndown)
        => async (_, conn) =>
        {
            var requests = new Dictionary<long, List<byte>>();
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();

                    var complete = new List<(long StreamId, byte[] Body)>();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data)
                        {
                            if (!requests.TryGetValue(item.StreamId, out List<byte>? body))
                            {
                                requests[item.StreamId] = body = [];
                            }
                            body.AddRange(item.AsSpan());

                            if (item.Fin)
                            {
                                complete.Add((item.StreamId, [.. body]));
                                requests.Remove(item.StreamId);
                            }
                        }
                        conn.ReturnBuffer(in item);
                    }

                    if (snap.IsClosed)
                    {
                        break;
                    }
                    conn.ResetRead();

                    if (complete.Count > 0)
                    {
                        await Task.Delay(delayMs);
                        foreach ((long streamId, byte[] body) in complete)
                        {
                            conn.SendStream(streamId, body, fin: true);
                        }
                    }
                }
            }
            finally
            {
                torndown.TrySetResult();
                conn.DecRef();
            }
        };
}
