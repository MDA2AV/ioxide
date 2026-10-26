using System.Buffers;
using ioxide;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// Backpressure on the nghttp2 server's streamed responses (#409). nghttp2 frames a stream's bytes only
/// when its windows and the connection's single drain let it, so a flush that returned before that
/// gave a writer that keeps writing no reason to stop: it never yielded its reactor, and nghttp2
/// buffered without bound. A flush now waits once nghttp2 holds 64 KiB of the stream unframed.
/// </summary>
internal static class Nghttp2StreamedResponseTests
{
    // RFC 9113's initial stream and connection windows. The raw client never raises them.
    private const int Window = 65535;
    private const int Chunk = 16 * 1024;

    // What a writer may hand nghttp2 beyond what it has framed before a flush waits (Nghttp2Connection.MaxUnframed).
    private const int Ahead = 64 * 1024;

    // Only so a build without the fix ends its run: its writer would otherwise buffer until memory runs out.
    private const long Budget = 32L * 1024 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("nghttp2 streamed response: a writer whose peer keeps its window shut waits 64 KiB past it, and the reactor serves on (#409)", () =>
        {
            var feed = new Feed();
            int port = Start(feed);
            using var client = new H2cClient(port, timeoutMs: 10_000);
            client.Open();
            client.Request(streamId: 1, path: "/feed");

            var bytes = new Dictionary<int, long>();
            bool spent = client.ReadData(bytes, [], () => bytes.GetValueOrDefault(1) >= Window, credit: false);
            Assert.True(spent, $"the feed sent {bytes.GetValueOrDefault(1)} bytes, not its {Window}-byte window");

            // Answered on the same reactor, so that reactor has run everything it could meanwhile.
            using var other = new H2cClient(port);
            other.Open();
            other.Request(streamId: 1, path: "/");
            Assert.True(other.AwaitResponse(1), "the reactor never answered another connection");

            long written = Interlocked.Read(ref feed.Written);
            Assert.True(written <= Window + Ahead + Chunk, $"the writer handed nghttp2 {written} bytes while its peer had room for {Window}");
        });

        runner.Test("nghttp2 streamed response: an endless response and a short one on one connection both get through, the endless writer kept to what goes out (#409)", () =>
        {
            const long Enough = 1024 * 1024;

            var feed = new Feed();
            int port = Start(feed);
            using var client = new H2cClient(port, timeoutMs: 10_000);
            client.Open();
            client.Request(streamId: 1, path: "/feed");
            client.Request(streamId: 3, path: "/");

            var bytes = new Dictionary<int, long>();
            var ended = new HashSet<int>();
            bool through = client.ReadData(bytes, ended, () => ended.Contains(3) && bytes.GetValueOrDefault(1) >= Enough, credit: true);
            long fed = bytes.GetValueOrDefault(1);
            long written = Interlocked.Read(ref feed.Written);

            Assert.True(through, $"the short response {(ended.Contains(3) ? "ended" : "never ended")}, and the feed sent {fed} bytes");
            Assert.True(written - fed <= Enough, $"the writer handed nghttp2 {written} bytes while {fed} reached the peer");
        });

        runner.Test("nghttp2 streamed response: a writer waiting on a shut window hears its connection close (#409)", () =>
        {
            var feed = new Feed();
            int port = Start(feed);
            using (var client = new H2cClient(port, timeoutMs: 10_000))
            {
                client.Open();
                client.Request(streamId: 1, path: "/feed");

                var bytes = new Dictionary<int, long>();
                Assert.True(client.ReadData(bytes, [], () => bytes.GetValueOrDefault(1) >= Window, credit: false),
                    $"the feed sent {bytes.GetValueOrDefault(1)} bytes, not its {Window}-byte window");
            }

            Assert.True(feed.Heard.Wait(5_000),
                $"the writer never heard its connection close, after handing nghttp2 {Interlocked.Read(ref feed.Written)} bytes");
        });
    }

    /// <summary>What the "/feed" writer did: bytes handed to nghttp2, and whether a flush told it the peer was gone.</summary>
    private sealed class Feed
    {
        public long Written;
        public readonly ManualResetEventSlim Heard = new();
    }

    // "/feed" writes 16 KiB chunks until a flush says the peer is gone, or Budget runs out; "/" answers 1 KiB.
    private static int Start(Feed feed) => TestServer.Start(async (_, conn) =>
    {
        try
        {
            await new Nghttp2Connection(conn).RunAsync(async (request, writer) =>
            {
                writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                if (!request.Path.Span.SequenceEqual("/feed"u8))
                {
                    writer.Write(new byte[1024]);
                    return;
                }

                while (Interlocked.Read(ref feed.Written) < Budget)
                {
                    writer.GetSpan(Chunk)[..Chunk].Fill((byte)'x');
                    writer.Advance(Chunk);
                    Interlocked.Add(ref feed.Written, Chunk);
                    if ((await writer.FlushAsync()).IsCompleted)
                    {
                        feed.Heard.Set();
                        return;
                    }
                }
            });
        }
        finally
        {
            conn.DecRef();
        }
    });
}
