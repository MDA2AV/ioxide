using System.Buffers;
using System.Runtime.CompilerServices;
using ioxide.http2;
using static Ioxide.Tests.Http2EarlyAnswerTests;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// An early answer past the client's stream window, to an upload its handler did not read: a client that credits the
/// answer only once its upload has ended needs the upload credited first. The handler is not held on that credit, what
/// it left unread is credited and dropped once it returns, and RST_STREAM(NO_ERROR) follows the answer's END_STREAM if
/// the upload is still arriving then (RFC 9113 8.1).
/// </summary>
internal static class Http2EarlyAnswerParkedTests
{
    // The client's stream window, as it is until its SETTINGS say otherwise; the answer is twice that, so it parks.
    private const int ClientWindow = 65535;
    private const int AnswerLength = 2 * ClientWindow;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_writerPool")]
    private static extern ref Stack<Http2ResponseWriter> WriterPool(Http2Connection connection);

    public static void Register(Runner runner)
    {
        RegisterDrain(runner);
        RegisterReset(runner);
    }

    private static void RegisterDrain(Runner runner)
    {
        runner.Test("h2 early answer: a buffered answer past the client's window, returned once the upload filled its stream window, credits what it left unread", () =>
        {
            var stalled = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _) =>
            {
                await stalled.Task;
                return new Http2Response { Status = 413, Body = new byte[AnswerLength] };
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow)]);
            Assert.Equal(0, Credit(client.Drain(), 1));              // unread, so not credited yet

            stalled.SetResult();                                     // answered outside the pass, the upload stalled
            List<Frame> frames = client.Drain();
            Assert.Equal(ClientWindow, Frame.Body(frames, 1).Length);   // one client window of the answer, then parked
            int credited = Credit(frames, 1);
            Assert.True(credited == StreamWindow,
                $"the handler returned with {StreamWindow} bytes unread and {credited} came back on its stream: a client that credits the answer only once its upload ends has no window left to end it");

            AssertUploadEndsThenAnswerEnds(client, frames);
            client.Close(run);
        });

        runner.Test("h2 early answer: CompleteAsync past the client's window returns without its credit, and the unread upload is credited once the handler returns", () =>
        {
            bool returned = false;

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 413 });
                writer.Write(new byte[AnswerLength]);
                await writer.CompleteAsync();
                returned = writer.IsCompleted;
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow)]);
            List<Frame> frames = client.Drain();
            Assert.True(returned, "CompleteAsync held the handler on credit that a client reading its answer only once its upload ends gives only then");
            Assert.Equal(ClientWindow, Frame.Body(frames, 1).Length);
            int credited = Credit(frames, 1);
            Assert.True(credited == StreamWindow,
                $"the handler returned with {StreamWindow} bytes unread and {credited} came back on its stream");

            AssertUploadEndsThenAnswerEnds(client, frames);
            client.Close(run);
        });

        runner.Test("h2 early answer: a streamed answer past the client's window that its handler leaves the stack to complete credits the unread upload", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 413 });
                writer.Write(new byte[AnswerLength]);
                return default;
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow)]);
            List<Frame> frames = client.Drain();
            Assert.Equal(ClientWindow, Frame.Body(frames, 1).Length);
            int credited = Credit(frames, 1);
            Assert.True(credited == StreamWindow,
                $"the handler returned with {StreamWindow} bytes unread and {credited} came back on its stream");

            AssertUploadEndsThenAnswerEnds(client, frames);
            client.Close(run);
        });

        runner.Test("h2 early answer: a handler that reads its body after CompleteAsync parked its answer gets all of it", () =>
        {
            // Only a handler that has returned is done with its body: nothing is drained from under one still reading.
            var read = new Tally();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 413 });
                writer.Write(new byte[AnswerLength]);
                await writer.CompleteAsync();
                await ReadAll(body, read);
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Fill(1, StreamWindow)]);
            List<Frame> frames = client.Drain();
            Assert.True(read.Bytes == StreamWindow, $"the handler read {read.Bytes} of the {StreamWindow} bytes sent with its request, its answer parked");
            Assert.Equal(StreamWindow, Credit(frames, 1));          // credited as read, once

            client.Feed(Data(1, 0, endStream: true));                // the handler reads to the end and returns
            client.Feed([.. WindowUpdate(0, 1 << 20), .. WindowUpdate(1, 1 << 20)]);
            frames.AddRange(client.Drain());
            Assert.Equal(AnswerLength, Frame.Body(frames, 1).Length);
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "a stream whose request had ended was reset");

            client.Close(run);
        });

        runner.Test("h2 early answer: a FlushAsync after CompleteAsync parked the answer reports it ended, and the answer goes out once", () =>
        {
            // The parked end sends from the writer's staging: a flush that took it up again would wait on the same credit, and send it twice.
            string? flushed = null;

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 413 });
                writer.Write(new byte[AnswerLength]);
                await writer.CompleteAsync();
                flushed = (await writer.FlushAsync()).IsCompleted ? "ended" : "not ended";
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.True(flushed == "ended", $"a flush after the response had completed returned {flushed ?? "nothing, still waiting on credit"}");

            client.Feed([.. WindowUpdate(0, 1 << 20), .. WindowUpdate(1, 1 << 20)]);
            frames.AddRange(client.Drain());
            Assert.Equal(AnswerLength, Frame.Body(frames, 1).Length);
            Assert.Equal(1, frames.Count(f => f.StreamId == 1 && f.EndStream));

            client.Close(run);
        });

        runner.Test("h2 early answer: a streamed answer parked on credit lets go of its writer when the client closes the connection", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 413 });
                writer.Write(new byte[AnswerLength]);
                return writer.CompleteAsync();
            });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
            Assert.Equal(ClientWindow, Frame.Body(client.Drain(), 1).Length);
            Assert.True(WriterPool(client.Connection).Count == 0, "precondition: the answer was meant to be parked, its writer out");

            client.Close(run);
            Assert.True(WriterPool(client.Connection).Count == 1, "the connection ended with the parked answer still holding its writer");
        });
    }

    private static void RegisterReset(Runner runner)
    {
        foreach (bool streamed in new[] { false, true })
        {
            bool stream = streamed;
            runner.Test($"h2 early answer: a {(stream ? "streamed" : "buffered")} answer parked on credit, its END_STREAM out with the upload still arriving, is followed by RST_STREAM(NO_ERROR)", () =>
            {
                // A client that reads while it uploads credits the answer; once it has ended, the upload is asked to stop.
                string answer = new('x', AnswerLength);

                using var client = new StrictClient();
                Task run = stream
                    ? client.Connection.RunAsync((_, _, writer) => Answer(writer, answer))
                    : client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(Http2Response.Text(answer, 413)));

                client.ReleaseFlush();
                client.Feed([.. Open(), .. Post(1), .. Data(1, 1000, endStream: false)]);
                List<Frame> frames = client.Drain();
                Assert.Equal(ClientWindow, Frame.Body(frames, 1).Length);

                client.Feed([.. Data(1, 16384, endStream: false), .. WindowUpdate(0, 1 << 20), .. WindowUpdate(1, 1 << 20)]);
                frames.AddRange(client.Drain());
                AssertAnsweredThenStopped(frames, streamId: 1, 413, answer);
                Assert.Equal(1000 + 16384, Credit(frames, 1));      // drained while the answer waited

                client.Close(run);
            });
        }
    }

    // The upload goes on with the credit the drain gave it, then ends; credited, the answer then ends whole, and no reset follows.
    private static void AssertUploadEndsThenAnswerEnds(StrictClient client, List<Frame> frames)
    {
        client.Feed(Data(1, 16384, endStream: false));
        int credited = Credit(client.Drain(), 1);
        Assert.True(credited == 16384, $"16384 more bytes of the unread upload arrived and {credited} were credited");

        client.Feed([.. Data(1, 16384, endStream: true), .. WindowUpdate(0, 1 << 20), .. WindowUpdate(1, 1 << 20)]);
        List<Frame> after = client.Drain();
        frames.AddRange(after);
        Assert.Equal(0, Credit(after, 1));                           // an ended request is owed none

        Assert.Equal(AnswerLength, Frame.Body(frames, 1).Length);
        Assert.True(frames.Last(f => f.StreamId == 1).EndStream, "the answer never ended");
        Assert.True(!frames.Any(f => f.Type == RstStreamFrame), "a stream whose request had ended was reset");
    }
}
