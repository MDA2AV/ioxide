using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using ioxide.http2;
using ioxide.nghttp2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>An nghttp2 answer that ends before its request does is followed by RST_STREAM(NO_ERROR) after its END_STREAM (RFC 9113 8.1), watched on the wire.</summary>
internal static class Nghttp2EarlyAnswerTests
{
    private const uint NoError = 0x0, InternalError = 0x2;
    private const byte GoAwayFrame = 0x7;

    public static void Register(Runner runner)
    {
        RegisterResets(runner);
        RegisterControls(runner);
        RegisterGuards(runner);
    }

    private static void RegisterResets(Runner runner)
    {
        runner.Test("nghttp2 early answer: a buffered answer to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync((_, _) => new ValueTask<Nghttp2Response>(Nghttp2Response.Text("too large", 413)));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), 413, "too large");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: a bodyless answer, END_STREAM on its HEADERS, to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync((_, _) => new ValueTask<Nghttp2Response>(new Nghttp2Response { Status = 413 }));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.True(frames.Any(f => f.StreamId == 1 && f.Type == Frame.Headers && f.EndStream), "the answer's END_STREAM did not ride its HEADERS");
            AssertAnsweredThenStopped(frames, 413, "");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: a streamed answer to an upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync((_, _, writer) => Answer(writer, "too large"));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), 413, "too large");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: the 500 of a handler that faulted with its upload still arriving is followed by RST_STREAM(NO_ERROR)", () =>
        {
            // Parked, so the 500 is written by its own drain rather than a read pass's.
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync((_, _) => FaultLater(later.Task));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.True(!frames.Any(f => f.StreamId == 1), "the stream was answered or reset while its handler ran");

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredThenStopped(frames, 500, "");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: with a flush in flight, the reset still follows END_STREAM, once", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (request, _, writer) =>
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
            AssertAnsweredThenStopped(client.Drain(), 413, "too large");

            Close(client, connection, run);
        });
    }

    private static void RegisterControls(Runner runner)
    {
        runner.Test("nghttp2 early answer: control: an answer to a request its last DATA ended is not followed by a reset", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (_, body, writer) =>
            {
                while (!(await body.ReadAsync()).IsEmpty)
                {
                }
                await Answer(writer, "read it all");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: true)]);
            AssertAnsweredNotReset(client.Drain(), "read it all");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: control: an answer to a request its trailers ended is not followed by a reset", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (_, _) =>
            {
                await later.Task;
                return Nghttp2Response.Text("late", 413);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 100, endStream: false), .. Trailers(1)]);
            List<Frame> frames = client.Drain();

            later.SetResult();
            frames.AddRange(client.Drain());
            AssertAnsweredNotReset(frames, "late");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: control: an answer to a request an empty DATA ended is not followed by a reset", () =>
        {
            var later = new TaskCompletionSource();

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (_, _, writer) =>
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

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: control: an answer to a GET, END_STREAM on its HEADERS, is not followed by a reset", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync((_, _) => new ValueTask<Nghttp2Response>(Nghttp2Response.Text("got it")));

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Get(1)]);
            AssertAnsweredNotReset(client.Drain(), "got it");

            Close(client, connection, run);
        });
    }

    private static void RegisterGuards(Runner runner)
    {
        runner.Test("nghttp2 early answer: a buffered answer parked on credit is reset only after its END_STREAM, and arrives whole", () =>
        {
            // Past the peer's stream window the rest waits for a WINDOW_UPDATE, while the upload goes on and is credited.
            byte[] answer = new byte[64 * 1024];

            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync((_, _) => new ValueTask<Nghttp2Response>(new Nghttp2Response { Status = 413, Body = answer }));

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.Equal(16384, Frame.Body(frames, 1).Length);   // one stream window, then parked
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "the stream was reset with its answer parked on credit");

            client.Feed(Data(1, 16384, endStream: false));
            frames.AddRange(client.Drain());
            client.Feed(WindowUpdate(1, 1 << 20));
            frames.AddRange(client.Drain());

            Assert.Equal(answer.Length, Frame.Body(frames, 1).Length);
            AssertAnsweredThenStopped(frames, 413, Encoding.UTF8.GetString(answer));

            Close(client, connection, run);
        });

        foreach (bool streamed in new[] { false, true })
        {
            bool stream = streamed;
            runner.Test($"nghttp2 early answer: a {(stream ? "streamed" : "buffered")} answer to an upload the peer reset gets nothing back", () =>
            {
                var later = new TaskCompletionSource();

                using var client = new StrictClient();
                var connection = new Nghttp2Connection(client);
                Task run = stream
                    ? connection.RunAsync(async (_, _, writer) =>
                    {
                        await later.Task;
                        await Answer(writer, "too late");
                    })
                    : connection.RunAsync(async (_, _) =>
                    {
                        await later.Task;
                        return Nghttp2Response.Text("too late", 413);
                    });

                client.ReleaseFlush();
                client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false), .. RstStream(1, Cancel)]);
                List<Frame> frames = client.Drain();

                later.SetResult();
                frames.AddRange(client.Drain());
                Assert.True(!frames.Any(f => f.StreamId == 1),
                    $"after the peer reset stream 1, it was sent [{string.Join(", ", frames.Where(f => f.StreamId == 1).Select(f => $"type {f.Type}"))}] (RFC 9113 5.4.2)");

                Close(client, connection, run);
            });
        }

        runner.Test("nghttp2 early answer: a handler that fails after its headers, its upload still arriving, is reset once, with INTERNAL_ERROR", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                await writer.FlushAsync();
                throw new InvalidOperationException("the handler gave up mid-body");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            uint[] resets = Resets(client.Drain(), 1);
            Assert.True(resets.SequenceEqual([InternalError]),
                $"stream 1 was reset with [{string.Join(", ", resets.Select(c => $"0x{c:x}"))}], where the stack's own reset is one 0x{InternalError:x}");

            Close(client, connection, run);
        });

        runner.Test("nghttp2 early answer: DATA in flight after the reset comes back on the connection, never on its closed stream", () =>
        {
            // What a client had in flight when the reset reached it fills the connection window: only its credit lets stream 3's body in.
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(async (request, body) =>
            {
                if (request.StreamId == 1)
                {
                    return Nghttp2Response.Text("too large", 413);
                }
                long read = 0;
                ReadOnlyMemory<byte> chunk;
                while (!(chunk = await body.ReadAsync()).IsEmpty)
                {
                    read += chunk.Length;
                }
                return Nghttp2Response.Text($"read {read}");
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            AssertAnsweredThenStopped(client.Drain(), 413, "too large");

            client.Feed(Fill(1, 65535 - 1000));
            List<Frame> after = client.Drain();
            Assert.True(!after.Any(f => f.StreamId == 1),
                $"after its RST_STREAM, stream 1 was sent [{string.Join(", ", after.Where(f => f.StreamId == 1).Select(f => $"type {f.Type}"))}] (RFC 9113 5.1)");

            client.Feed([.. Post(3), .. Data(3, 16384, endStream: true)]);
            after.AddRange(client.Drain());
            Assert.True(!after.Any(f => f.Type == GoAwayFrame), "the connection went away: the DATA after the reset was never credited on it");
            Assert.Equal("read 16384", Encoding.UTF8.GetString(Frame.Body(after, 3)));

            Close(client, connection, run);
        });
    }

    // The answer whole and RST_STREAM(NO_ERROR) after its END_STREAM, as the stream's last frame.
    private static void AssertAnsweredThenStopped(List<Frame> frames, int status, string body)
    {
        List<Frame> stream = frames.Where(f => f.StreamId == 1).ToList();
        int end = stream.FindIndex(f => f.EndStream && f.Type is Frame.Data or Frame.Headers);
        int reset = stream.FindIndex(f => f.Type == RstStreamFrame);

        Assert.True(end >= 0, "the answer never ended");
        Assert.Equal(status, Status(frames, 1));
        Assert.Equal(body, Encoding.UTF8.GetString(Frame.Body(stream, 1)));
        Assert.True(reset >= 0,
            "the answer ended with its request still arriving, and no RST_STREAM asked the client to stop uploading");
        Assert.True(reset > end && reset == stream.Count - 1,
            $"RST_STREAM was frame {reset} of the stream's {stream.Count} and its END_STREAM frame {end}: a reset ahead of the end cuts the answer off");
        Assert.True(Resets(frames, 1).Length == 1, $"stream 1 was reset {Resets(frames, 1).Length} times");

        uint code = BinaryPrimitives.ReadUInt32BigEndian(stream[reset].Payload);
        Assert.True(code == NoError, $"the stream was reset with 0x{code:x}, where NO_ERROR leaves the client its answer");
    }

    private static void AssertAnsweredNotReset(List<Frame> frames, string body)
    {
        Assert.Equal(body, Encoding.UTF8.GetString(Frame.Body(frames, 1)));
        Assert.True(frames.Any(f => f.StreamId == 1 && f.EndStream), "the answer never ended");
        Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "a request that had ended was reset");
    }

    // A stream's :status, decoded in wire order through one table, as nghttp2's encoder indexes across responses.
    private static int Status(List<Frame> frames, int streamId)
    {
        var decoder = new HpackDecoder();
        byte[] scratch = new byte[4096];
        var statuses = new Dictionary<int, int>();
        foreach (Frame frame in frames.Where(f => f.Type == Frame.Headers))
        {
            decoder.Decode(frame.Payload, scratch, (statuses, frame.StreamId), static (state, name, value) =>
            {
                if (name.SequenceEqual(":status"u8))
                {
                    state.statuses[state.StreamId] = int.Parse(Encoding.ASCII.GetString(value));
                }
            });
        }
        return statuses.GetValueOrDefault(streamId, -1);
    }

    private static uint[] Resets(List<Frame> frames, int streamId)
        => frames.Where(f => f.StreamId == streamId && f.Type == RstStreamFrame)
                 .Select(f => BinaryPrimitives.ReadUInt32BigEndian(f.Payload)).ToArray();

    private static async ValueTask<Nghttp2Response> FaultLater(Task later)
    {
        await later;
        throw new InvalidOperationException("the handler gave up");
    }

    private static ValueTask Answer(Nghttp2ResponseWriter writer, string body)
    {
        writer.WriteHeaders(new Nghttp2Response { Status = 413 });
        writer.Write(Encoding.UTF8.GetBytes(body));
        return ValueTask.CompletedTask;   // the connection completes the writer once its handler returns
    }

    private static void Close(StrictClient client, Nghttp2Connection connection, Task run)
    {
        client.Close(run);
        connection.Dispose();
    }

    // nghttp2 wants an :authority. Static-table HPACK otherwise: 0x83 POST / 0x82 GET, 0x86 :scheme http, 0x84 :path /.
    private static byte[] Post(int streamId) => FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84, 0x01, 9, .. "a.example"u8]);

    private static byte[] Get(int streamId) => FrameBytes(0x1, 0x5, streamId, [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8]);

    // 0x90 is static 16, accept-encoding: gzip, deflate - a regular field, as trailers carry.
    private static byte[] Trailers(int streamId) => FrameBytes(0x1, 0x5, streamId, [0x90]);
}
