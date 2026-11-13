using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// An answer that ends before its request does (#571): the client is asked to stop uploading with
/// RST_STREAM(NO_ERROR), and only once the answer's END_STREAM is out (RFC 9113 8.1). RST_STREAM ends
/// a stream both ways, so ahead of END_STREAM it would cut the answer off. Watched on the wire, where
/// the order shows; Ioxide.Tests.E2E's EarlyAnswerTests has the same with a real client.
/// </summary>
internal static class Http2EarlyAnswerTests
{
    private const uint NoError = 0x0;
    private const uint InternalError = 0x2;

    public static void Register(Runner runner)
    {
        runner.Test("h2 early answer: a buffered answer to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(Http2Response.Text("too large", 413)));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), streamId: 1, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: a streamed answer to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _, writer) => Answer(writer, "too large"));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), streamId: 1, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: a handler that runs on after its answer is reset once it returns, and the reset is written", () =>
        {
            // A handler still running may still read its body, so the client is asked to stop only
            // when it returns - here outside the pass, with no flush running and no unread body whose
            // credit would start one: the retire that stages the reset has to write it.
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
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "the stream was reset while its handler, which may still read its body, ran on");

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredThenStopped(frames, streamId: 1, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: the 500 of a handler that faulted with its upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            // The buffered dispatch answers a fault for the handler, from its catch.
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => FaultLater(later.Task));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredThenStopped(frames, streamId: 1, "");

            client.Close(run);
        });

        runner.Test("control: an answer to a request that has ended is not followed by a reset", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                while (!(await body.ReadAsync()).IsEmpty)
                {
                }
                await Answer(writer, "read it all");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: true)]);
            List<Frame> frames = client.Drain();

            Assert.Equal("read it all", Encoding.UTF8.GetString(Frame.Body(frames, 1)));
            Assert.True(frames.Any(f => f.StreamId == 1 && f.EndStream), "the answer never ended");
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "a stream both sides had ended was reset");

            client.Close(run);
        });

        runner.Test("h2 early answer: a buffered answer parked on credit is not reset ahead of its END_STREAM", () =>
        {
            // Past the peer's stream window, the rest of the answer waits for a WINDOW_UPDATE - and
            // the stream is retired before it does, with the answer's end still to go out.
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
            // RFC 9113 5.4.2: never in answer to a RST_STREAM - and the client already stopped.
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

        runner.Test("h2 early answer: a handler that fails after its headers, its upload still arriving, is reset once, with INTERNAL_ERROR", () =>
        {
            // The stack's own reset for a response it cannot finish. A RST_STREAM closes the stream,
            // so a NO_ERROR one behind it would be a frame on a closed stream (RFC 9113 5.1).
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await writer.FlushAsync();
                throw new InvalidOperationException("the handler gave up mid-body");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();

            uint[] resets = frames.Where(f => f.StreamId == 1 && f.Type == RstStreamFrame)
                                  .Select(f => BinaryPrimitives.ReadUInt32BigEndian(f.Payload)).ToArray();
            Assert.True(resets.SequenceEqual([InternalError]),
                $"stream 1 was reset with [{string.Join(", ", resets.Select(c => $"0x{c:x}"))}], where its handler's failure is one INTERNAL_ERROR");

            client.Close(run);
        });
    }

    // The answer whole - its HEADERS, its body, its END_STREAM - and RST_STREAM(NO_ERROR) after it,
    // as the stream's last frame.
    private static void AssertAnsweredThenStopped(List<Frame> frames, int streamId, string body)
    {
        List<Frame> stream = frames.Where(f => f.StreamId == streamId).ToList();
        int end = stream.FindIndex(f => f.EndStream && f.Type is Frame.Data or Frame.Headers);
        int reset = stream.FindIndex(f => f.Type == RstStreamFrame);

        Assert.True(end >= 0, "the answer never ended");
        Assert.Equal(body, Encoding.UTF8.GetString(Frame.Body(stream, streamId)));
        Assert.True(reset >= 0,
            "the answer ended with its request still arriving, and no RST_STREAM asked the client to stop uploading");
        Assert.True(reset > end && reset == stream.Count - 1,
            $"RST_STREAM was frame {reset} of the stream's {stream.Count} and its END_STREAM frame {end}: a reset ahead of the end cuts the answer off");

        uint code = BinaryPrimitives.ReadUInt32BigEndian(stream[reset].Payload);
        Assert.True(code == NoError, $"the stream was reset with 0x{code:x}, where NO_ERROR leaves the client its answer");
    }

    private static async ValueTask<Http2Response> FaultLater(Task later)
    {
        await later;
        throw new InvalidOperationException("the handler gave up");
    }

    private static ValueTask Answer(Http2ResponseWriter writer, string body)
    {
        writer.WriteHeaders(new Http2Response { Status = 413 });
        writer.Write(Encoding.UTF8.GetBytes(body));
        return writer.CompleteAsync();
    }

    // A POST that opens a stream with its body still to come. Static-table HPACK only: 0x83 :method
    // POST, 0x86 :scheme http, 0x84 :path /.
    private static byte[] Post(int streamId) => FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84]);

    private static byte[] Data(int streamId, int length, bool endStream)
        => FrameBytes(0x0, endStream ? (byte)0x1 : (byte)0x0, streamId, new byte[length]);
}
