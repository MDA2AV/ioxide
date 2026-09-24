using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The read timeout over QUIC, against the real ngtcp2 engine. The transport reaps a connection
/// whose peer has been silent for <see cref="QuicOptions.ReadTimeoutMs"/>, which is right when the
/// connection waits on its peer and wrong when the peer waits on us: a request that takes a while
/// to answer leaves both ends silent. While a response is owed, the engine pings the peer, whose
/// ACKs keep the connection seen; once it is answered the pings stop, and a peer with nothing more
/// to say is reaped as before.
/// </summary>
internal static class QuicReadTimeoutTests
{
    private const int ReadTimeoutMs = 500;

    // Deadlines, not measurements (see tests/README.md).
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

            // The client says nothing more after its request - it only acknowledges what arrives.
            client.SendRequest("slow-but-here"u8.ToArray());
            Assert.Equal("slow-but-here", client.WaitForEcho(ExchangeMs));
            Assert.True(!torndown.Task.IsCompleted, "the connection was torn down while its request was being answered");
        });

        runner.Test("quic read timeout: once answered, a peer that only acknowledges is reaped", () =>
        {
            // The pings must stop with the response. The client here answers anything the server
            // sends, so a keep-alive left running would keep this connection alive indefinitely.
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

    /// <summary>
    /// Echoes each request once its stream has finished arriving, but only after
    /// <paramref name="delayMs"/> - a handler that is busy, with nothing crossing the wire.
    /// </summary>
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
