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
    private const byte Data = 0x0, Headers = 0x1, Priority = 0x2, RstStream = 0x3, Continuation = 0x9;
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

        // A buffered request in, so ended by the peer, its answer parked; then the peer's reset. The END_STREAM
        // came first, and DATA after one is a connection error (RFC 7540 5.1), whatever the peer sent between.
        runner.Test("h2 closed streams: DATA after the peer reset a stream it had ended, its answer still going, ends the connection with STREAM_CLOSED", () =>
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

            client.Feed([.. Frame(RstStream, 0, 1, [0, 0, 0, 8]), .. Frame(Data, 0, 1, [1]), .. Frame(Data, EndStream, 1, [1])]);
            client.Feed(Http2FlowControlTests.Get(3));
            gate.SetResult();
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("GOAWAY 1 0x5", Http2ControlFrameTests.Errors(frames));
            Assert.Equal(0, frames.Count(f => f.Type == Headers && f.StreamId == 3));
        });

        runner.Test("h2 closed streams: HEADERS after the peer's RST_STREAM reset the stream with STREAM_CLOSED, and HPACK stays in step", () =>
        {
            (List<Frame> frames, List<string> served) = Exchange(
                Post(1), Frame(RstStream, 0, 1, [0, 0, 0, 8]), Frame(Headers, EndHeaders | EndStream, 1, Insert),
                Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, 0xBE]));

            Assert.Equal("RST_STREAM 1 0x5", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual(["3 x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 closed streams: HEADERS on a stream the peer ended, closed more streams ago than the connection remembers, are dropped, and HPACK stays in step", () =>
        {
            var frames = new List<byte[]> { Http2FlowControlTests.Get(1) };
            for (int stream = 3; stream <= 263; stream += 2)
            {
                frames.Add(Http2FlowControlTests.Get(stream));
            }
            frames.Add(Frame(Headers, EndHeaders | EndStream, 1, Insert));
            frames.Add(Frame(Headers, EndHeaders | EndStream, 265, [0x82, 0x86, 0x84, 0xBE]));
            (List<Frame> wire, List<string> served) = Exchange([.. frames]);

            Assert.Equal("", Http2ControlFrameTests.Errors(wire));
            Assert.Equal("265 x-b=w", served[^1]);
        });

        // Opening 7 after 1 skips 3 and 5: both ends of the range are refused, and 7, just above it, is not.
        foreach (int skipped in new[] { 3, 5 })
        {
            int id = skipped;
            runner.Test($"h2 closed streams: HEADERS on stream {id}, skipped below one opened, end the connection, while trailers on the stream just above the skip are dropped", () =>
            {
                (List<Frame> frames, _) = Exchange(true,
                    Http2FlowControlTests.Get(1), Post(7), Frame(Headers, EndHeaders | EndStream, 7, Insert), Http2FlowControlTests.Get(id));

                Assert.Equal("RST_STREAM 7 0x0, GOAWAY 7 0x1", Http2ControlFrameTests.Errors(frames));
            });
        }

        runner.Test("h2 closed streams: past the skips the connection remembers, HEADERS on the oldest are dropped and on a newer one still end the connection", () =>
        {
            var frames = new List<byte[]>();
            for (int stream = 1; stream <= 73; stream += 4)
            {
                frames.Add(Http2FlowControlTests.Get(stream));   // 18 skips, of 3, 7, ... 71
            }
            frames.Add(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, .. Insert]));   // forgotten: dropped, and decoded
            frames.Add(Frame(Headers, EndHeaders | EndStream, 75, [0x82, 0x86, 0x84, 0xBE]));
            frames.Add(Http2FlowControlTests.Get(11));                                               // the third skip, still remembered
            (List<Frame> wire, List<string> served) = Exchange([.. frames]);

            Assert.Equal("GOAWAY 75 0x1", Http2ControlFrameTests.Errors(wire));
            Assert.Equal("75 x-b=w", served[^1]);
        });

        runner.Test("h2 closed streams: a stream refused past MaxConcurrentStreams skips the ids below it too", () =>
        {
            using var client = new StrictClient(new Http2Options { MaxConcurrentStreams = 1 });
            Task run = client.Connection.RunAsync(_ => Http2Response.Text("ok"));
            client.SendRequests();
            client.Drain();

            client.Feed(Post(1));                              // open, its body still to come
            client.Feed(Http2FlowControlTests.Get(5));         // refused, and skips 3
            client.Feed(Http2FlowControlTests.Get(3));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 5 0x7, GOAWAY 5 0x1", Http2ControlFrameTests.Errors(frames));
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

    // Each frame in a pass of its own, against a handler that answers at once; with earlyAnswer it takes
    // a body reader, so a request still arriving is answered unread and reset with NO_ERROR.
    private static (List<Frame> Frames, List<string> Served) Exchange(params byte[][] frames) => Exchange(false, frames);

    private static (List<Frame> Frames, List<string> Served) Exchange(bool earlyAnswer, params byte[][] frames)
    {
        using var client = new StrictClient();
        var served = new List<string>();
        ValueTask<Http2Response> Handle(Http2Request request)
        {
            served.Add($"{request.StreamId} {Http2ControlFrameTests.Fields(request)}".TrimEnd());
            return ValueTask.FromResult(Http2Response.Text("ok"));
        }
        Task run = earlyAnswer ? client.Connection.RunAsync((request, _) => Handle(request)) : client.Connection.RunAsync(Handle);
        client.SendRequests();
        List<Frame> wire = client.Drain();
        foreach (byte[] frame in frames)
        {
            client.Feed(frame);
        }
        wire.AddRange(client.Drain());
        client.Close(run);
        return (wire, served);
    }

    // Inserts x-b: w into the dynamic table, which a later GET names by index.
    private static byte[] Insert => Http2TrailerTests.Field("x-b", "w", index: true);

    // A POST, its body still to come.
    private static byte[] Post(int streamId) => Frame(Headers, EndHeaders, streamId, [0x83, 0x86, 0x84]);

    private static byte[] Frame(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);
}
