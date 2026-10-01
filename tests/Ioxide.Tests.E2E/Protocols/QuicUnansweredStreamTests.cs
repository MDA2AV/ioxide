using System.Buffers;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A stream the peer has finished counts as owed, and the read timeout keeps an owed connection alive
/// with pings. One that nothing will answer must be reset instead: the peer is told, and an idle peer
/// is reaped.
/// </summary>
internal static class QuicUnansweredStreamTests
{
    // HTTP/3 needs the longer clock: at 500 ms its setup alone can outrun the read timeout.
    private const int ReadTimeoutMs = 1000;

    private const int ExchangeMs = 10_000;

    private const ulong H3RequestIncomplete = 0x010d;

    public static void Register(Runner runner)
    {
        RegisterHttp3(runner, "an empty request stream", []);
        RegisterHttp3(runner, "a request stream that ends before its HEADERS", [0x21, 0x02, 0xAA, 0xBB]);   // a reserved frame

        runner.Test("quic read timeout: a pipe writer completed with an error resets its stream, and an idle peer is reaped", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: ReadTimeoutMs,
                quicHandle: FailEachResponse(torndown));

            using var client = new TeardownWireClient(udpPort);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            long sid = client.SendRequest("fails"u8.ToArray());
            ConverseUntil(client, torndown);

            bool reset = client.SawReset(sid, out _);
            AssertReaped(torndown, reset);
            Assert.True(reset, $"the peer was never told: no RESET_STREAM on stream {sid}");
        });
    }

    private static void RegisterHttp3(Runner runner, string shape, byte[] request)
    {
        runner.Test($"quic read timeout: http3 resets {shape}, and an idle peer is reaped", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);
            var torndown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: ReadTimeoutMs,
                quicHandle: async (_, conn) =>
                {
                    try
                    {
                        await new Http3Connection(conn).RunAsync(static _ => Http3Response.Text("ok"));
                    }
                    finally
                    {
                        torndown.TrySetResult();
                    }
                });

            using var client = new TeardownWireClient(udpPort, alpn: "h3");
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            long sid = client.SendRequest(request);
            ConverseUntil(client, torndown);

            bool reset = client.SawReset(sid, out ulong code);
            AssertReaped(torndown, reset);
            Assert.True(reset && code == H3RequestIncomplete,
                $"expected RESET_STREAM H3_REQUEST_INCOMPLETE (0x{H3RequestIncomplete:x}) on stream {sid}, got "
                + (reset ? $"0x{code:x}" : "no reset"));
        });
    }

    // Acknowledges whatever arrives, so pings that never stop keep the connection alive to the end.
    private static void ConverseUntil(TeardownWireClient client, TaskCompletionSource torndown)
    {
        for (int i = 0; i < 8 && !torndown.Task.IsCompleted; i++)
        {
            client.Converse(ReadTimeoutMs);
        }
    }

    private static void AssertReaped(TaskCompletionSource torndown, bool reset)
        => Assert.True(torndown.Task.IsCompleted,
            $"the connection outlived the read timeout 8 times over (stream reset: {reset}): an "
            + "unanswered stream stayed owed, and its keep-alive never stopped");

    // Takes each request whole, then fails its response mid-way - while the handler stays on the
    // connection, so only the stream itself can stop being owed.
    private static Func<Reactor, QuicConnection, Task> FailEachResponse(TaskCompletionSource torndown)
        => async (_, conn) =>
        {
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();

                    var finished = new List<long>();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        if (item.Kind == QuicStreamEvent.Data && item.Fin)
                        {
                            finished.Add(item.StreamId);
                        }
                        conn.ReturnBuffer(in item);
                    }

                    if (snap.IsClosed)
                    {
                        break;
                    }
                    conn.ResetRead();

                    foreach (long streamId in finished)
                    {
                        var writer = new QuicConnectionPipeWriter(conn, streamId);
                        writer.Write("partial"u8);
                        await writer.FlushAsync();
                        writer.Complete(new InvalidOperationException("the response failed"));
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
