using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A body chunk its handler still holds when the connection goes away, on both HTTP/3 stacks. The
/// chunk is the handler's until its next read or its return, so teardown must not give its pooled
/// buffer back: the next upload on the reactor would be copied into it, under the handler's feet.
/// </summary>
internal static class H3HeldChunkTests
{
    private const int ChunkBytes = 1100;        // one datagram, so the handler is handed one chunk
    private const int UploadBytes = 64 * 1024;  // enough chunks of the same size to reach a freed buffer

    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp3" : "ioxide.http3";

            runner.Test($"h3 ({stack}): a chunk its handler holds when the connection goes away keeps its bytes", () =>
            {
                var holder = new Holder();
                int port = Start(ng, holder);

                using var holding = new RawH3Client("127.0.0.1", port);
                holding.Connect();
                Assert.True(holding.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
                holding.OpenRequestStream();
                holding.Write([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(ChunkBytes),
                    .. Enumerable.Repeat((byte)0xAA, ChunkBytes)], fin: false);
                Assert.True(holding.WaitFor(holder.Held.Task, timeoutMs: 5000), "the handler was never handed its chunk");

                // SETTINGS has no place on a request stream: a connection error, so the connection is
                // torn down while the handler waits on its timer with the chunk in hand.
                holding.Write([0x04, 0x00], fin: false);
                Assert.True(holding.WaitFor(holder.HolderGone.Task, timeoutMs: 5000), "the holder's connection was never torn down");

                using var uploading = new RawH3Client("127.0.0.1", port);
                uploading.Connect();
                Assert.True(uploading.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
                uploading.OpenRequestStream();
                uploading.Write([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(UploadBytes),
                    .. Enumerable.Repeat((byte)0xBB, UploadBytes)], fin: true);
                Assert.True(uploading.WaitFor(holder.Drained.Task, timeoutMs: 5000), "the second upload was never read through");

                Volatile.Write(ref holder.Release, true);
                Assert.True(holder.Outcome.Task.Wait(5000), "the holding handler never looked at its chunk again");
                Assert.Equal("intact", holder.Outcome.Task.Result);
            });
        }
    }

    private sealed class Holder
    {
        public readonly TaskCompletionSource Held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource HolderGone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<string> Outcome = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Release;
        public int Connections;
    }

    private static int Start(bool native, Holder holder)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: async (reactor, conn) =>
            {
                bool first = Interlocked.Increment(ref holder.Connections) == 1;
                var timer = new RingTimer(reactor);
                if (native)
                {
                    await new Nghttp3Connection(conn).RunAsync(async (_, body) =>
                        Nghttp3Response.Text(await Serve(timer, holder, body.ReadAsync)));
                }
                else
                {
                    await new Http3Connection(conn).RunAsync(async (_, body) =>
                        Http3Response.Text(await Serve(timer, holder, body.ReadAsync)));
                }
                if (first)
                {
                    holder.HolderGone.TrySetResult();
                }
            });
        return udpPort;
    }

    // A first chunk of 0xAA is the holder's: kept across a ring wait until the test releases it,
    // then checked against a copy. Any other body is read to its end.
    private static async ValueTask<string> Serve(RingTimer timer, Holder holder, Func<ValueTask<ReadOnlyMemory<byte>>> read)
    {
        ReadOnlyMemory<byte> chunk = await read();
        if (chunk.IsEmpty || chunk.Span[0] != 0xAA)
        {
            while (!(await read()).IsEmpty)
            {
            }
            holder.Drained.TrySetResult();
            return "drained";
        }

        byte[] copy = chunk.ToArray();
        holder.Held.TrySetResult();
        for (int waited = 0; !Volatile.Read(ref holder.Release) && waited < 10_000; waited += 5)
        {
            await timer.DelayAsync(5);
        }

        holder.Outcome.TrySetResult(chunk.Span.SequenceEqual(copy)
            ? "intact"
            : $"overwritten: {chunk.Span.Count((byte)0xBB)} of its {chunk.Length} bytes came from the other connection's upload");
        return "held";
    }
}
