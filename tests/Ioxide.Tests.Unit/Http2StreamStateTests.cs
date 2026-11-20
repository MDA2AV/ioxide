using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// Frames on streams that are not open (RFC 9113 5.1, 5.1.1). On an idle stream, or one a client
/// could never have opened, they are a connection error. After the peer's END_STREAM they are its
/// error, of the stream while the response is still going and of the connection once it is closed,
/// and nothing of them reaches a body reader. After this side's own reset they are dropped: the peer
/// sent them before it could know.
/// </summary>
internal static class Http2StreamStateTests
{
    private const byte Data = 0x0, Headers = 0x1, RstStream = 0x3, WindowUpdate = 0x8;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    public static void Register(Runner runner)
    {
        // After stream 1, served and closed both ways.
        foreach ((string name, byte[] frame, string expected) in new[]
        {
            ("an RST_STREAM on an idle stream", Frame(RstStream, 0, 3, [0, 0, 0, 8]), "GOAWAY 1 0x1"),
            ("a WINDOW_UPDATE on an idle stream", Frame(WindowUpdate, 0, 3, [0, 0, 0, 1]), "GOAWAY 1 0x1"),
            ("a WINDOW_UPDATE on an even stream, which only a server could open,", Frame(WindowUpdate, 0, 2, [0, 0, 0, 1]), "GOAWAY 1 0x1"),
            ("HEADERS on an even stream", Frame(Headers, EndHeaders | EndStream, 2, [0x82, 0x86, 0x84]), "GOAWAY 1 0x1"),
            ("a DATA after the stream closed both ways", Frame(Data, EndStream, 1, [1]), "GOAWAY 1 0x5"),
            ("HEADERS after the stream closed both ways", Frame(Headers, EndHeaders | EndStream, 1, [0x82, 0x86, 0x84]), "GOAWAY 1 0x5"),
        })
        {
            string shape = name;
            byte[] bad = frame;
            string answer = expected;
            runner.Test($"h2 stream states: {shape} ends the connection", () =>
            {
                (List<Frame> frames, List<int> served) = Exchange([.. Http2FlowControlTests.Get(1)], bad);

                Assert.Equal(answer, Http2ControlFrameTests.Errors(frames));
                Assert.True(served.SequenceEqual([1]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }

        runner.Test("h2 stream states: control: a WINDOW_UPDATE, an RST_STREAM and a PRIORITY on a stream closed both ways take nothing down", () =>
        {
            (List<Frame> frames, List<int> served) = Exchange([.. Http2FlowControlTests.Get(1)],
            [
                .. Frame(WindowUpdate, 0, 1, [0, 0, 0, 1]),   // sent before the client saw the END_STREAM, as RFC 9113 5.1 allows
                .. Frame(RstStream, 0, 1, [0, 0, 0, 8]),
                .. Frame(0x2, 0, 1, [0, 0, 0, 0, 15]),
            ]);

            Assert.Equal("", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual([1, 7]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 stream states: HEADERS on a stream below one already opened, and never opened itself, end the connection", () =>
        {
            (List<Frame> frames, List<int> served) = Exchange([.. Http2FlowControlTests.Get(5)], Http2FlowControlTests.Get(1));

            Assert.Equal("GOAWAY 5 0x1", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual([5]), $"the handler was handed: {string.Join(", ", served)}");
        });

        // RFC 9113 5.1: after the peer's RST_STREAM, a stream error; the stream is then this side's, so a second frame is dropped.
        runner.Test("h2 stream states: a DATA after the peer's RST_STREAM resets the stream with STREAM_CLOSED, once, and the connection goes on", () =>
        {
            (List<Frame> frames, List<int> served) = Exchange([], [.. Post(1), .. Frame(RstStream, 0, 1, [0, 0, 0, 8]), .. Frame(Data, 0, 1, [1]), .. Frame(Data, EndStream, 1, [1])]);

            Assert.Equal("RST_STREAM 1 0x5", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual([7]), $"the handler was handed: {string.Join(", ", served)}");
        });

        // The issue's own case: no content-length, so nothing else would tell the reader the bytes are not the body's.
        runner.Test("h2 stream states: a DATA after END_STREAM, with the handler still reading, resets the stream, and its body reader hands out none of it", () =>
        {
            using var client = new StrictClient();
            var gate = new TaskCompletionSource();
            var read = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task run = client.Connection.RunAsync(async (request, body) =>
            {
                if (request.StreamId != 1)
                {
                    return Http2Response.Text("ok");
                }
                await gate.Task;   // reads only once every frame below is in
                var bytes = new List<byte>();
                try
                {
                    for (ReadOnlyMemory<byte> chunk = await body.ReadAsync(); !chunk.IsEmpty; chunk = await body.ReadAsync())
                    {
                        bytes.AddRange(chunk.ToArray());
                    }
                }
                catch (IOException)
                {
                    bytes.AddRange("|reset"u8.ToArray());   // as after the peer's own reset: the stream is gone under it
                }
                read.TrySetResult(Encoding.ASCII.GetString([.. bytes]));
                return Http2Response.Text("ok");
            });
            client.SendRequests();
            client.Drain();

            client.Feed([.. Post(1), .. Frame(Data, EndStream, 1, "body"u8), .. Frame(Data, 0, 1, "late"u8)]);
            client.Feed(Http2FlowControlTests.Get(3));   // the connection goes on
            gate.SetResult();
            List<Frame> frames = client.Drain();

            Assert.True(read.Task.Wait(2_000), "the handler never finished reading");
            Assert.Equal("|reset", read.Task.Result);
            Assert.Equal("RST_STREAM 1 0x5", Http2ControlFrameTests.Errors(frames));
            Assert.Equal(1, frames.Count(f => f.Type == Headers && f.StreamId == 3));
            client.Close(run);
        });

        runner.Test("h2 stream states: HEADERS after END_STREAM, with the answer still to come, reset the stream, and HPACK stays in step", () =>
        {
            using var client = new StrictClient();
            var gate = new TaskCompletionSource();
            var served = new List<string>();
            Task run = client.Connection.RunAsync(async request =>
            {
                served.Add($"{request.StreamId} {Http2ControlFrameTests.Fields(request)}");
                if (request.StreamId == 1)
                {
                    await gate.Task;
                }
                return Http2Response.Text("ok");
            });
            client.SendRequests(1);   // its handler parks: half-closed (remote), the answer still to come
            client.Drain();

            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, Http2TrailerTests.Field("x-b", "w", index: true)));
            client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, 0xBE]));
            gate.SetResult();
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x5", Http2ControlFrameTests.Errors(frames));
            Assert.Equal(0, frames.Count(f => f.Type == Headers && f.StreamId == 1));   // the reset ends the answer too
            Assert.True(served.SequenceEqual(["1 ", "3 x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        // RFC 9113 5.1: what follows this side's own reset was sent before the peer knew of it.
        runner.Test("h2 stream states: control: DATA and trailers on a stream this side reset are dropped, and the connection goes on", () =>
        {
            using var client = new StrictClient();
            var served = new List<int>();
            Task run = client.Connection.RunAsync((request, body) =>
            {
                served.Add(request.StreamId);
                return ValueTask.FromResult(Http2Response.Text("early"));   // answered unread: the upload is reset with NO_ERROR
            });
            client.SendRequests();
            client.Drain();

            client.Feed(Post(1));
            client.Feed(Frame(Data, 0, 1, new byte[10]));
            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, Http2TrailerTests.Field("x-b", "w", index: true)));
            client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, 0xBE]));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x0", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual([1, 3]), $"the handler was handed: {string.Join(", ", served)}");
        });
    }

    // The opening frames, then the one under test, then stream 7's GET.
    private static (List<Frame> Frames, List<int> Served) Exchange(byte[] before, byte[] frame)
    {
        using var client = new StrictClient();
        var served = new List<int>();
        Task run = client.Connection.RunAsync(request =>
        {
            served.Add(request.StreamId);
            return Http2Response.Text("ok");
        });
        client.SendRequests();
        List<Frame> frames = client.Drain();
        client.Feed(before);
        frames.AddRange(client.Drain());
        client.Feed(frame);
        client.Feed(Http2FlowControlTests.Get(7));
        frames.AddRange(client.Drain());
        client.Close(run);
        return (frames, served);
    }

    // A POST, its body still to come.
    private static byte[] Post(int streamId) => Frame(Headers, EndHeaders, streamId, [0x83, 0x86, 0x84]);

    private static byte[] Frame(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);
}
