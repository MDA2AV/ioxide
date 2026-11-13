using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>An answer that ends before its request does is followed by RST_STREAM(NO_ERROR) after its END_STREAM (RFC 9113 8.1), watched on the wire.</summary>
internal static class Http2EarlyAnswerTests
{
    internal const uint NoError = 0x0;
    internal const uint InternalError = 0x2;
    internal const uint FlowControlError = 0x3;

    public static void Register(Runner runner)
    {
        RegisterResets(runner);
        RegisterControls(runner);
        RegisterCredit(runner);
    }

    private static void RegisterResets(Runner runner)
    {
        runner.Test("h2 early answer: a buffered answer to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(Http2Response.Text("too large", 413)));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), streamId: 1, 413, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: a streamed answer to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _, writer) => Answer(writer, "too large"));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), streamId: 1, 413, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: a handler that runs on after its answer is reset once it returns, and the reset is written", () =>
        {
            // No flush is running when it returns, and no unread body's credit would start one.
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
            AssertAnsweredThenStopped(frames, streamId: 1, 413, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: with a flush in flight, the reset still follows END_STREAM, once", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (request, _, writer) =>
            {
                if (request.StreamId == 1)
                {
                    await later.Task;
                }
                await Answer(writer, request.StreamId == 1 ? "too large" : "other");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false), .. Get(3)]);
            Assert.True(client.PendingFlushes == 1, "the pass flush is not in flight");

            later.SetResult();   // answered outside the pass, behind that flush
            AssertAnsweredThenStopped(client.Drain(), streamId: 1, 413, "too large");

            client.Close(run);
        });

        runner.Test("h2 early answer: the 500 of a handler that faulted with its upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => FaultLater(later.Task));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredThenStopped(frames, streamId: 1, 500, "");

            client.Close(run);
        });

        runner.Test("h2 early answer: a buffered response that cannot be written is answered 500, and the reset follows it", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _) =>
            {
                await later.Task;
                return null!;
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredThenStopped(frames, streamId: 1, 500, "");

            client.Close(run);
        });
    }

    private static void RegisterControls(Runner runner)
    {
        runner.Test("control: an answer to a request its last DATA ended is not followed by a reset", () =>
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
            AssertAnsweredNotReset(client.Drain(), "read it all");

            client.Close(run);
        });

        runner.Test("control: an answer to a request its trailers ended is not followed by a reset", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _) =>
            {
                await later.Task;
                return Http2Response.Text("late", 413);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 100, endStream: false), .. Trailers(1)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredNotReset(frames, "late");

            client.Close(run);
        });

        runner.Test("control: an answer to a request an empty DATA ended is not followed by a reset", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                await later.Task;
                await Answer(writer, "late");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 100, endStream: false), .. Data(1, 0, endStream: true)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredNotReset(frames, "late");

            client.Close(run);
        });
    }

    private static void RegisterCredit(Runner runner)
    {
        runner.Test("h2 early answer: DATA in flight after the reset is credited on the connection, never on its closed stream", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(Http2Response.Text("too large", 413)));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), streamId: 1, 413, "too large");

            client.Feed(Data(1, 16384, endStream: false));   // sent before the client saw the reset
            List<Frame> after = client.Drain();

            Assert.Equal(16384, Credit(after, 0));
            Assert.True(!after.Any(f => f.StreamId == 1),
                $"after its RST_STREAM, stream 1 was sent [{string.Join(", ", after.Where(f => f.StreamId == 1).Select(f => $"type {f.Type}"))}] (RFC 9113 5.1)");

            client.Close(run);
        });

        runner.Test("h2 early answer: an upload still arriving while a buffered answer is parked on credit is credited on both windows", () =>
        {
            // A client that credits its answer only once its upload ends can then end it.
            byte[] answer = new byte[64 * 1024];

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(new Http2Response { Status = 413, Body = answer }));

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.Equal(16384, Frame.Body(frames, 1).Length);   // one stream window, then parked

            client.Feed(Data(1, 16384, endStream: false));
            List<Frame> credited = client.Drain();
            Assert.Equal(16384, Credit(credited, 0));
            Assert.Equal(16384, Credit(credited, 1));

            client.Feed(WindowUpdate(1, 1 << 20));
            frames.AddRange(credited);
            frames.AddRange(client.Drain());
            Assert.Equal(answer.Length, Frame.Body(frames, 1).Length);

            client.Close(run);
        });
    }

    // The answer whole and RST_STREAM(NO_ERROR) after its END_STREAM, as the stream's last frame.
    internal static void AssertAnsweredThenStopped(List<Frame> frames, int streamId, int status, string body)
    {
        List<Frame> stream = frames.Where(f => f.StreamId == streamId).ToList();
        int end = stream.FindIndex(f => f.EndStream && f.Type is Frame.Data or Frame.Headers);
        int reset = stream.FindIndex(f => f.Type == RstStreamFrame);

        Assert.True(end >= 0, "the answer never ended");
        Assert.Equal(status, Status(stream));
        Assert.Equal(body, Encoding.UTF8.GetString(Frame.Body(stream, streamId)));
        Assert.True(reset >= 0,
            "the answer ended with its request still arriving, and no RST_STREAM asked the client to stop uploading");
        Assert.True(reset > end && reset == stream.Count - 1,
            $"RST_STREAM was frame {reset} of the stream's {stream.Count} and its END_STREAM frame {end}: a reset ahead of the end cuts the answer off");

        uint code = BinaryPrimitives.ReadUInt32BigEndian(stream[reset].Payload);
        Assert.True(code == NoError, $"the stream was reset with 0x{code:x}, where NO_ERROR leaves the client its answer");
    }

    private static void AssertAnsweredNotReset(List<Frame> frames, string body)
    {
        Assert.Equal(body, Encoding.UTF8.GetString(Frame.Body(frames, 1)));
        Assert.True(frames.Any(f => f.StreamId == 1 && f.EndStream), "the answer never ended");
        Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "a request that had ended was reset");
    }

    // :status as the encoder writes it first in the block: indexed for 200 and 500, a literal with its static name otherwise.
    private static int Status(List<Frame> stream)
    {
        byte[] block = stream.First(f => f.Type == Frame.Headers).Payload;
        return block[0] switch
        {
            0x88 => 200,
            0x8E => 500,
            0x08 => int.Parse(Encoding.ASCII.GetString(block, 2, block[1])),
            _ => -1,
        };
    }

    internal static uint[] Resets(List<Frame> frames, int streamId)
        => frames.Where(f => f.StreamId == streamId && f.Type == RstStreamFrame)
                 .Select(f => BinaryPrimitives.ReadUInt32BigEndian(f.Payload)).ToArray();

    private static async ValueTask<Http2Response> FaultLater(Task later)
    {
        await later;
        throw new InvalidOperationException("the handler gave up");
    }

    internal static ValueTask Answer(Http2ResponseWriter writer, string body)
    {
        writer.WriteHeaders(new Http2Response { Status = 413 });
        writer.Write(Encoding.UTF8.GetBytes(body));
        return writer.CompleteAsync();
    }

    // A POST that opens a stream with its body still to come. Static-table HPACK only: 0x83 :method POST, 0x86 :scheme http, 0x84 :path /.
    internal static byte[] Post(int streamId) => FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84]);

    internal static byte[] Data(int streamId, int length, bool endStream)
        => FrameBytes(0x0, endStream ? (byte)0x1 : (byte)0x0, streamId, new byte[length]);

    // 0x90 is static 16, accept-encoding: gzip, deflate - a regular field, as trailers carry.
    private static byte[] Trailers(int streamId) => FrameBytes(0x1, 0x5, streamId, [0x90]);
}
