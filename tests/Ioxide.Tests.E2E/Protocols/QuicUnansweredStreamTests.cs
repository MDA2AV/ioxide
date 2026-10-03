using System.Buffers;
using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
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

    private const ulong H3InternalError = 0x0102;
    private const ulong H3RequestRejected = 0x010b;
    private const ulong H3RequestIncomplete = 0x010d;

    // A GET framed by hand: HEADERS(len 16), field-section prefix 00 00, static-table :method GET,
    // :scheme https, :path /, then :authority "localhost" as a literal on static name 0 - nghttp3
    // refuses the empty authority H3ErrorCodeTests gets away with.
    private static readonly byte[] Get = [0x01, 0x10, 0x00, 0x00, 0xD1, 0xD7, 0xC1, 0x50, 0x09, .."localhost"u8.ToArray()];

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

        RegisterRejectedAfterGoAway(runner);
        RegisterStreamedFault(runner, native: false);
        RegisterStreamedFault(runner, native: true);
        RegisterPingFloor(runner);
    }

    private static void RegisterRejectedAfterGoAway(Runner runner)
    {
        runner.Test("quic read timeout: nghttp3 resets a request that arrives after its GOAWAY, and the connection drains", () =>
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
                    var h3 = new Nghttp3Connection(conn);
                    try
                    {
                        // The first request starts a graceful shutdown: its answer goes out with a GOAWAY.
                        await h3.RunBufferedAsync(_ =>
                        {
                            h3.Shutdown();
                            return Nghttp3Response.Text("bye");
                        });
                    }
                    finally
                    {
                        torndown.TrySetResult();
                    }
                });

            using var client = new TeardownWireClient(udpPort, alpn: "h3");
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            long first = client.SendRequest(Get);
            Assert.True(client.ConverseUntil(() => client.SawFin(first), ExchangeMs), "the first request was never answered");

            long second = client.SendRequest(Get);   // past the GOAWAY: rejected
            ConverseUntil(client, torndown);

            bool reset = client.SawReset(second, out ulong code);
            AssertReaped(torndown, reset);
            Assert.True(reset && code == H3RequestRejected,
                $"expected RESET_STREAM H3_REQUEST_REJECTED (0x{H3RequestRejected:x}) on stream {second}, got "
                + (reset ? $"0x{code:x}" : "no reset"));
        });
    }

    private static void RegisterStreamedFault(Runner runner, bool native)
    {
        string stack = native ? "nghttp3" : "ioxide.http3";
        runner.Test($"http3 ({stack}): a streamed response whose handler fails mid-body is reset, not ended, and the connection serves on", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]);

            // The first response fails after its headers and part of its body; the next one completes.
            int calls = 0;
            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: ReadTimeoutMs,
                quicHandle: native
                    ? (_, conn) => new Nghttp3Connection(conn).RunStreamedResponseAsync(async (_, writer) =>
                    {
                        writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                        writer.Write("partial"u8);
                        await writer.FlushAsync();
                        if (++calls == 1)
                        {
                            throw new InvalidOperationException("the body failed");
                        }
                    })
                    : (_, conn) => new Http3Connection(conn).RunStreamedResponseAsync(async (_, writer) =>
                    {
                        writer.WriteHeaders(new Http3Response { Status = 200 });
                        writer.Write("partial"u8);
                        await writer.FlushAsync();
                        if (++calls == 1)
                        {
                            throw new InvalidOperationException("the body failed");
                        }
                    }));

            using var client = new TeardownWireClient(udpPort, alpn: "h3");
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");

            long failed = client.SendRequest(Get);
            Assert.True(client.ConverseUntil(() => client.SawFin(failed) || client.SawReset(failed, out _), ExchangeMs),
                "the failed response never ended at all");
            Assert.True(!client.SawFin(failed),
                "the failed response ended cleanly: its truncated body cannot be told apart from a whole one");
            Assert.True(client.SawReset(failed, out ulong code) && code == H3InternalError,
                $"expected RESET_STREAM H3_INTERNAL_ERROR (0x{H3InternalError:x}), got 0x{code:x}");

            long next = client.SendRequest(Get);
            Assert.True(client.ConverseUntil(() => client.SawFin(next), ExchangeMs),
                "the connection stopped serving after one response failed");
        });
    }

    private static void RegisterPingFloor(Runner runner)
    {
        runner.Test("quic read timeout: a peer advertising a 1 ms idle timeout does not get pinged at its own pace", () =>
        {
            // Halved as is, its idle timeout would set the keep-alive pinging every PTO (~27 ms on
            // loopback) for as long as a request is owed; floored at a second, at most a few. Engine
            // timers fire only when the reactor wakes, so junk datagrams keep it awake - an idle
            // reactor would hide a flood behind its 250 ms tick.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);

            (_, int udpPort) = TestServer.StartDatagram(
                onDatagram: null,
                quicFactory: engine.CreateFactory(),
                quicReadMs: ReadTimeoutMs,
                quicHandle: HoldEachRequest());

            using var client = new TeardownWireClient(udpPort, idleTimeoutNs: 1_000_000);
            Assert.True(client.CompleteHandshake(ExchangeMs), "handshake did not complete");
            client.SendRequest("owed"u8.ToArray());

            using var stop = new CancellationTokenSource();
            Task noise = Task.Run(() =>
            {
                using var udp = new UdpClient();
                udp.Connect(new IPEndPoint(IPAddress.Loopback, udpPort));
                byte[] junk = [0];
                while (!stop.IsCancellationRequested)
                {
                    udp.Send(junk, junk.Length);
                    Thread.Sleep(1);
                }
            });

            int before = client.DatagramsReceived;
            client.Converse(2000);
            int received = client.DatagramsReceived - before;

            stop.Cancel();
            noise.Wait();

            // About 6 arrive with the floor (the handshake's tail, then the connection idles out);
            // without it, about 2,000.
            Assert.True(received <= 20,
                $"{received} datagrams in 2 s while a request was owed: the keep-alive pinged at the pace "
                + "of the peer's 1 ms idle timeout instead of the 1 s floor");
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

    // Reads every request and answers none, staying on the connection: each stays owed.
    private static Func<Reactor, QuicConnection, Task> HoldEachRequest()
        => async (_, conn) =>
        {
            try
            {
                while (true)
                {
                    QuicRecvSnapshot snap = await conn.ReadAsync();
                    while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                    {
                        conn.ReturnBuffer(in item);
                    }
                    if (snap.IsClosed)
                    {
                        break;
                    }
                    conn.ResetRead();
                }
            }
            finally
            {
                conn.DecRef();
            }
        };

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
