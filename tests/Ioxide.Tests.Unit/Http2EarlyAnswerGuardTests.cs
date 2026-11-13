using ioxide.http2;
using static Ioxide.Tests.Http2EarlyAnswerTests;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>Where an early answer's RST_STREAM(NO_ERROR) must not go: ahead of the answer's END_STREAM, or after another reset (RFC 9113 5.1, 5.4.2).</summary>
internal static class Http2EarlyAnswerGuardTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 early answer: a buffered answer parked on credit is not reset ahead of its END_STREAM", () =>
        {
            // Past the peer's stream window the rest waits for a WINDOW_UPDATE, and the stream is retired before it ends.
            byte[] answer = new byte[64 * 1024];

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(new Http2Response { Status = 413, Body = answer }));

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.Equal(16384, Frame.Body(frames, 1).Length);       // one stream window, then parked

            client.Feed(WindowUpdate(1, 1 << 20));
            frames.AddRange(client.Drain());

            List<Frame> stream = frames.Where(f => f.StreamId == 1).ToList();
            int end = stream.FindIndex(f => f.EndStream && f.Type is Frame.Data or Frame.Headers);
            int reset = stream.FindIndex(f => f.Type == RstStreamFrame);

            Assert.True(end >= 0, "the parked answer never ended");
            Assert.True(reset < 0 || reset > end,
                $"RST_STREAM was frame {reset} on the stream and its END_STREAM frame {end}: the client loses the rest of the answer");
            Assert.Equal(answer.Length, Frame.Body(stream, 1).Length);

            client.Close(run);
        });

        runner.Test("h2 early answer: a buffered answer to an upload the peer reset gets no reset back", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _) =>
            {
                await later.Task;
                return Http2Response.Text("too late", 413);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false), .. RstStream(1, Cancel)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            Assert.True(!frames.Any(f => f.StreamId == 1), "frames went out on stream 1 after the peer had reset it");

            client.Close(run);
        });

        runner.Test("h2 early answer: a streamed answer to an upload the peer reset gets no reset back", () =>
        {
            // Its writer completes all the same, with nobody to send to.
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                await later.Task;
                await Answer(writer, "too late");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false), .. RstStream(1, Cancel)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            Assert.True(!frames.Any(f => f.StreamId == 1), "frames went out on stream 1 after the peer had reset it");

            client.Close(run);
        });

        runner.Test("h2 early answer: the peer's reset arriving while the answer's END_STREAM is in flight gets no reset back", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                await later.Task;
                await Answer(writer, "too large");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();

            later.SetResult();   // outside a pass, so the answer's own flush is real
            Assert.True(client.PendingFlushes == 1, "the answer's flush is not in flight");
            client.Feed(RstStream(1, Cancel));
            frames.AddRange(client.Drain());

            Assert.True(frames.Any(f => f.StreamId == 1 && f.EndStream), "the answer never ended");
            Assert.True(Resets(frames, 1).Length == 0, "stream 1 was reset after the peer had reset it");

            client.Close(run);
        });

        runner.Test("h2 early answer: a buffered answer to a stream the stack reset is not reset again", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _) =>
            {
                await later.Task;
                return Http2Response.Text("late", 413);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 100, endStream: false), .. WindowUpdate(1, 0x7FFFFFFF)]);   // past 2^31-1
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertResetOnce(frames, FlowControlError);

            client.Close(run);
        });

        runner.Test("h2 early answer: a stream the stack reset after its answer's END_STREAM is not reset again when its handler returns", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                await Answer(writer, "too large");
                await later.Task;
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1)]);
            List<Frame> frames = client.Drain();
            Assert.True(frames.Any(f => f.StreamId == 1 && f.EndStream), "the answer never ended");

            client.Feed(WindowUpdate(1, 0x7FFFFFFF));   // past 2^31-1
            frames.AddRange(client.Drain());

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertResetOnce(frames, FlowControlError);

            client.Close(run);
        });

        runner.Test("h2 early answer: a handler that fails after its headers, its upload still arriving, is reset once, with INTERNAL_ERROR", () =>
        {
            // A NO_ERROR reset behind the stack's own would be a frame on a closed stream (RFC 9113 5.1).
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await writer.FlushAsync();
                throw new InvalidOperationException("the handler gave up mid-body");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertResetOnce(client.Drain(), InternalError);

            client.Close(run);
        });
    }

    private static void AssertResetOnce(List<Frame> frames, uint code)
    {
        uint[] resets = Resets(frames, 1);
        Assert.True(resets.SequenceEqual([code]),
            $"stream 1 was reset with [{string.Join(", ", resets.Select(c => $"0x{c:x}"))}], where the stack's own reset is one 0x{code:x}");
    }
}
