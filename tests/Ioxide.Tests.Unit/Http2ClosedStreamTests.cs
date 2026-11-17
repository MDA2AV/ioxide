using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// What the connection remembers of closed streams, and what it does when it does not. A stream this
/// side reset or stopped reading takes the peer's late frames without complaint (RFC 9113 5.1), and so
/// does one closed too long ago to be remembered: a client whose frames were only late is never
/// refused for them. Each block is still decoded, so HPACK stays in step.
/// </summary>
internal static class Http2ClosedStreamTests
{
    private const byte Data = 0x0, Headers = 0x1, Priority = 0x2, Continuation = 0x9;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    public static void Register(Runner runner)
    {
        runner.Test("h2 closed streams: trailers on a stream answered early, after more closes than the connection remembers, are dropped and the connection goes on", () =>
        {
            using var client = new StrictClient();
            var served = new List<int>();
            Task run = client.Connection.RunAsync((request, _) =>
            {
                served.Add(request.StreamId);
                return ValueTask.FromResult(Http2Response.Text("ok"));   // answered unread: stream 1's upload is reset with NO_ERROR
            });
            client.SendRequests();
            client.Drain();

            client.Feed(Post(1));
            for (int stream = 3; stream <= 263; stream += 2)
            {
                client.Feed(Http2FlowControlTests.Get(stream));   // 131 closes, past what the connection remembers
            }
            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, Insert));   // stream 1's trailers, sent before the client saw the reset
            client.Feed(Frame(Headers, EndHeaders | EndStream, 265, [0x82, 0x86, 0x84, 0xBE]));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x0", Http2ControlFrameTests.Errors(frames));
            Assert.Equal(133, served.Count);
            Assert.Equal(265, served[^1]);
        });

        // A buffered request ready, so closed by the peer's END_STREAM, then reset by this side: the later wins.
        runner.Test("h2 closed streams: DATA on a stream the peer ended and this side then reset is dropped, not refused with the connection", () =>
        {
            using var client = new StrictClient();
            var gate = new TaskCompletionSource();
            Task run = client.Connection.RunAsync(async request =>
            {
                if (request.StreamId == 1)
                {
                    await gate.Task;
                }
                return Http2Response.Text("ok");
            });
            client.SendRequests(1);
            client.Drain();

            client.Feed(Frame(Priority, 0, 1, [0, 0, 0, 3]));   // a stream error: this side resets it
            client.Feed(Frame(Data, EndStream, 1, [1]));
            client.Feed(Http2FlowControlTests.Get(3));
            gate.SetResult();
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x6", Http2ControlFrameTests.Errors(frames));
            Assert.Equal(1, frames.Count(f => f.Type == Headers && f.StreamId == 3));
        });

        // RetireStream with the answer parked on the client's credit: no reset yet, but the upload is dropped.
        runner.Test("h2 closed streams: DATA and trailers behind an answer parked on credit are dropped, and the answer still ends whole", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((request, _) => ValueTask.FromResult(request.StreamId == 1
                ? new Http2Response { Status = 200, Body = new byte[70_000] }   // past the client's 65535-byte window, unread
                : Http2Response.Text("ok")));
            client.SendRequests();
            List<Frame> frames = client.Drain();

            client.Feed(Post(1));
            frames.AddRange(client.Drain());
            client.Feed(Frame(Data, 0, 1, new byte[10]));
            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, Insert));
            client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, 0xBE]));
            frames.AddRange(client.Drain());
            client.SendWindowUpdate(1, 70_000);
            client.SendWindowUpdate(0, 70_000);
            frames.AddRange(client.Drain());
            client.Close(run);

            Assert.Equal(0, frames.Count(f => f.Type == 0x7));
            Assert.Equal(70_000, Ioxide.Tests.Frame.Body(frames, 1).Length);
            Assert.Equal(1, frames.Count(f => f.Type == Headers && f.StreamId == 3));
        });

        foreach (bool halfClosed in new[] { false, true })
        {
            bool answering = halfClosed;
            runner.Test($"h2 closed streams: HEADERS continued in CONTINUATION on a stream {(answering ? "the peer ended, its answer still to come, reset the stream" : "this side reset are dropped")}, and HPACK stays in step", () =>
            {
                using var client = new StrictClient();
                var gate = new TaskCompletionSource();
                var served = new List<string>();
                Task run = client.Connection.RunAsync(async (request, _) =>
                {
                    served.Add($"{request.StreamId} {Http2ControlFrameTests.Fields(request)}");
                    if (request.StreamId == 1 && answering)
                    {
                        await gate.Task;
                    }
                    return Http2Response.Text("ok");   // unread: an upload still arriving is reset with NO_ERROR
                });
                client.SendRequests();
                client.Drain();

                client.Feed(answering ? Http2FlowControlTests.Get(1) : Post(1));
                client.Feed(Frame(Headers, EndStream, 1, Insert[..3]));
                client.Feed(Frame(Continuation, EndHeaders, 1, Insert[3..]));
                client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, 0xBE]));
                gate.SetResult();
                List<Frame> frames = client.Drain();
                client.Close(run);

                Assert.Equal(answering ? "RST_STREAM 1 0x5" : "RST_STREAM 1 0x0", Http2ControlFrameTests.Errors(frames));
                Assert.True(served.SequenceEqual(["1 ", "3 x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }
    }

    // Inserts x-b: w into the dynamic table, which a later GET names by index.
    private static byte[] Insert => Http2TrailerTests.Field("x-b", "w", index: true);

    // A POST, its body still to come.
    private static byte[] Post(int streamId) => Frame(Headers, EndHeaders, streamId, [0x83, 0x86, 0x84]);

    private static byte[] Frame(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);
}
