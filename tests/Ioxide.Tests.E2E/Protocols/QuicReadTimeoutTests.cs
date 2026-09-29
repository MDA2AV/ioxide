using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>The read timeout over QUIC: keep-alive while a response is owed, and only then.</summary>
internal static class QuicReadTimeoutTests
{
    private const int ReadTimeoutMs = 500;

    // At 500 ms the h3 test client's ACKs do not always land inside the timeout - on main as well -
    // with pings on the 250 ms tick. A second leaves room.
    private const int H3ReadTimeoutMs = 1000;

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

        runner.Test("quic read timeout: a handler that leaves without answering does not keep its peer alive", () =>
        {
            // Nobody is left to answer, so pings would keep a peer that only acknowledges alive for good.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var evicted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(_ => new EvictionReporting(engine, evicted)),
                quicReadMs: ReadTimeoutMs,
                quicHandle: LeaveUnanswered(gone));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            client.SendRequest("never-answered"u8.ToArray());
            client.Converse(2 * ReadTimeoutMs);
            Assert.True(gone.Task.IsCompleted, "the handler did not leave");

            client.Converse(8 * ReadTimeoutMs);
            Assert.True(evicted.Task.IsCompleted,
                "the connection outlived the read timeout after its handler left - the keep-alive never stopped");
        });

        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp3" : "ioxide.http3";

            // The h3 layers answer from detached handlers: the connection's handler still holds it meanwhile.
            runner.Test($"quic read timeout ({stack}): a request answered after longer than the read timeout still gets its response", () =>
            {
                (string certPath, string keyPath) = TestCert.Ensure();
                using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

                (_, int udpPort) = TestServer.StartDatagram(
                    onDatagram: null,
                    quicFactory: engine.CreateFactory(),
                    quicReadMs: H3ReadTimeoutMs,
                    quicHandle: ng
                        ? static (_, conn) => new Nghttp3Connection(conn).RunBufferedAsync(static async _ =>
                        {
                            await Task.Delay(3 * H3ReadTimeoutMs);
                            return Nghttp3Response.Text("slow-but-here");
                        })
                        : static (_, conn) => new Http3Connection(conn).RunAsync(static async _ =>
                        {
                            await Task.Delay(3 * H3ReadTimeoutMs);
                            return Http3Response.Text("slow-but-here");
                        }));

                using var client = new H3TestClient("127.0.0.1", udpPort);
                client.Connect();
                Assert.True(client.CompleteHandshake(timeoutMs: ExchangeMs), "handshake did not complete");

                (int status, string body) = client.Get("/", timeoutMs: ExchangeMs);
                Assert.Equal(200, status);
                Assert.Equal("slow-but-here", body);
            });
        }
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

    private sealed class EvictionReporting(QuicEngine engine, TaskCompletionSource evicted) : QuicEngineConnection(engine)
    {
        public override void OnEvicted(QuicEvictReason reason)
        {
            evicted.TrySetResult();
            base.OnEvicted(reason);
        }
    }

    // Reads one whole request, then returns without answering or closing.
    private static Func<Reactor, QuicConnection, Task> LeaveUnanswered(TaskCompletionSource gone)
        => async (_, conn) =>
        {
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();
                    bool fin = false;
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        fin |= item.Kind == QuicStreamEvent.Data && item.Fin;
                        conn.ReturnBuffer(in item);
                    }
                    if (fin || snap.IsClosed)
                    {
                        return;
                    }
                    conn.ResetRead();
                }
            }
            finally
            {
                conn.DecRef();
                gone.TrySetResult();
            }
        };
}
