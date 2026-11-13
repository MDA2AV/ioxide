using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// A request's content-length against the DATA that carries its body. RFC 9113 8.1.1 makes a request
/// malformed when they disagree - a body that runs past it or ends short of it, HEADERS that end the
/// stream while declaring one - and so is a content-length that is no number or comes twice: a stream
/// error of PROTOCOL_ERROR. A buffered request is never dispatched. A streamed one may already be
/// running, so its next read raises instead of ending, and nothing more goes out on its stream.
/// </summary>
internal static class Http2ContentLengthTests
{
    private const byte Data = 0x0, Headers = 0x1, RstStream = 0x3, GoAway = 0x7, WindowUpdate = 0x8, Continuation = 0x9;
    private const byte EndStream = 0x1, EndHeaders = 0x4, Padded = 0x8;

    public static void Register(Runner runner)
    {
        runner.Test("h2 content-length: control: a buffered body that adds up to its content-length is served whole, padding aside", () =>
        {
            using var client = new StrictClient();
            var served = new List<string>();
            Task run = client.Connection.RunAsync(request =>
            {
                served.Add($"{request.StreamId} {request.Body.Length}");
                return Http2Response.Text("ok");
            });
            client.SendRequests();
            client.Drain();

            // Each way a request can end: on its last DATA, on trailers, and on HEADERS declaring no body.
            client.Feed(FrameBytes(Headers, EndHeaders, 1, Post("10")));
            client.Feed(PaddedBody(1, 4, padding: 40));   // flow-controlled, padding and all, but only four bytes of body
            client.Feed(Body(1, 6, endStream: true));
            client.Feed(FrameBytes(Headers, EndHeaders, 3, Post("10")));
            client.Feed(Body(3, 10, endStream: false));
            client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 3, Http2TrailerTests.Field("x-checksum", "abc")));
            client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 5, Post("0")));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("", Errors(frames));
            Assert.True(served.SequenceEqual(["1 10", "3 10", "5 0"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 content-length: a buffered body that runs past its content-length is reset at the frame that does, and no handler runs", () =>
        {
            using var client = new StrictClient();
            var served = new List<string>();
            Task run = client.Connection.RunAsync(request =>
            {
                served.Add($"{request.StreamId} {request.Body.Length}");
                return Http2Response.Text("ok");
            });
            client.SendRequests();
            client.Drain();

            client.Feed(FrameBytes(Headers, EndHeaders, 1, Post("10")));
            client.Feed(Body(1, 6, endStream: false));
            client.Feed(Body(1, 6, endStream: false));   // twelve of ten, with the stream still open
            List<Frame> atOverrun = client.Drain();

            client.Feed(Body(1, 6, endStream: true));    // sent before the client learns of the reset
            client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 3, Post()));
            List<Frame> after = client.Drain();
            client.Close(run);

            Assert.True(Errors(atOverrun) == "1 PROTOCOL_ERROR",
                $"twelve bytes arrived under content-length: 10 and the server wrote [{Errors(atOverrun)}]: no reset at the frame that ran past");
            Assert.Equal("", Errors(after));
            Assert.True(served.SequenceEqual(["3 0"]), $"the handler was handed: {string.Join(", ", served)}");

            // The refused frame never reached the body, but it used the connection's window like the
            // rest, so it is credited back with them, or the window would shrink by it for good.
            Assert.Equal(18, Credit([.. atOverrun, .. after], 0));
        });

        foreach (bool onTrailers in new[] { false, true })
        {
            bool trailers = onTrailers;
            runner.Test($"h2 content-length: a buffered body that ends short of its content-length {(trailers ? "at its trailers" : "at its last DATA")} is reset, and no handler runs", () =>
            {
                using var client = new StrictClient();
                var served = new List<string>();
                Task run = client.Connection.RunAsync(request =>
                {
                    served.Add($"{request.StreamId} {request.Body.Length}");
                    return Http2Response.Text("ok");
                });
                client.SendRequests();
                client.Drain();

                client.Feed(FrameBytes(Headers, EndHeaders, 1, Post("100")));
                client.Feed(Body(1, 10, endStream: !trailers));
                if (trailers)
                {
                    client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 1, Http2TrailerTests.Field("x-checksum", "abc")));
                }
                client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 3, Post()));
                List<Frame> frames = client.Drain();
                client.Close(run);

                Assert.Equal("1 PROTOCOL_ERROR", Errors(frames));
                Assert.True(served.SequenceEqual(["3 0"]),
                    $"ten bytes ended a request that declared a hundred, and the handler was handed: {string.Join(", ", served)}");
            });
        }

        foreach (bool withReader in new[] { false, true })
        {
            bool reader = withReader;
            runner.Test($"h2 content-length: HEADERS that end the stream while declaring a body reset it before any handler{(reader ? " taking a body reader" : "")} runs", () =>
            {
                using var client = new StrictClient();
                var served = new List<int>();
                ValueTask<Http2Response> Serve(Http2Request request)
                {
                    served.Add(request.StreamId);
                    return ValueTask.FromResult(Http2Response.Text("ok"));
                }
                Task run = reader
                    ? client.Connection.RunAsync((request, _) => Serve(request))
                    : client.Connection.RunAsync(Serve);
                client.SendRequests();
                client.Drain();

                // One block whole, then the same block finished by a CONTINUATION, with END_STREAM on
                // its HEADERS either way; and a control declaring the empty body it sends.
                byte[] block = Post("10");
                client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 1, block));
                client.Feed(FrameBytes(Headers, EndStream, 3, block[..3]));
                client.Feed(FrameBytes(Continuation, EndHeaders, 3, block[3..]));
                client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 5, Post("0")));
                List<Frame> frames = client.Drain();
                client.Close(run);

                Assert.Equal("1 PROTOCOL_ERROR, 3 PROTOCOL_ERROR", Errors(frames));
                Assert.True(served.SequenceEqual([5]), $"the handler was handed streams {string.Join(", ", served)}");
            });
        }

        foreach (bool withReader in new[] { false, true })
        {
            bool reader = withReader;
            runner.Test($"h2 content-length: one that is no number, or comes twice, resets the stream before any handler{(reader ? " taking a body reader" : "")} runs, and HPACK stays in step", () =>
            {
                // Each with the ten bytes it claims, so only the field is wrong. A repeat is refused even
                // when the values agree, as nghttp2 refuses it.
                foreach (string[] fields in new string[][]
                {
                    ["ten"], ["-10"], ["+10"], ["10 "], [""], ["10, 10"], ["9223372036854775808"], ["10", "10"], ["10", "11"], ["11", "10"],
                })
                {
                    string outcome = MalformedOutcome(reader, fields);
                    Assert.True(outcome == "reset 1 PROTOCOL_ERROR, served 3 x-b=w",
                        $"content-length {string.Join(" + ", fields.Select(f => $"'{f}'"))}: {outcome}");
                }
            });
        }

        runner.Test("h2 content-length: control: a streamed body that adds up to its content-length reads as a clean end", () =>
        {
            (string end, string trace) = StreamedOutcome("10", Body(1, 4, endStream: true));

            Assert.Equal("ended after 10", end);
            Assert.Equal("HEADERS, DATA", trace);
        });

        runner.Test("h2 content-length: a streamed body that runs past its content-length raises on read at the frame that does, and its response never goes out", () =>
        {
            (string end, string trace) = StreamedOutcome("10", Body(1, 6, endStream: false));   // twelve of ten, the stream still open

            Assert.True(end.StartsWith("raised after 6: ") && end.Contains("past its content-length"),
                $"the body ran past its content-length under a handler reading it, and its read {end}");
            Assert.Equal("RST_STREAM PROTOCOL_ERROR", trace);
        });

        foreach (bool onTrailers in new[] { false, true })
        {
            bool trailers = onTrailers;
            runner.Test($"h2 content-length: a streamed body that ends short of its content-length {(trailers ? "at its trailers" : "at its last DATA")} raises on read instead of ending", () =>
            {
                byte[] ending = trailers
                    ? FrameBytes(Headers, EndHeaders | EndStream, 1, Http2TrailerTests.Field("x-checksum", "abc"))
                    : Body(1, 4, endStream: true);
                (string end, string trace) = StreamedOutcome("100", ending);

                Assert.True(end.StartsWith("raised after 6: ") && end.Contains("short of its content-length"),
                    $"the body ended short of its content-length under a handler reading it, and its read {end}");
                Assert.Equal("RST_STREAM PROTOCOL_ERROR", trace);
            });
        }

        foreach (bool inOnePass in new[] { true, false })
        {
            bool samePass = inOnePass;
            runner.Test($"h2 content-length: a streamed response whose body is refused {(samePass ? "before it runs" : "while it runs")} finds its stream gone, and sends nothing after the reset", () =>
            {
                (string outcome, string trace) = StreamedResponseOutcome(samePass);

                Assert.Equal("body raised, flush completed", outcome);
                Assert.Equal(samePass ? "RST_STREAM PROTOCOL_ERROR" : "HEADERS, RST_STREAM PROTOCOL_ERROR", trace);
            });
        }

        runner.Test("h2 content-length: a streamed response parked on credit when its body is refused wakes to find its stream gone", () =>
        {
            // The peer will not credit a stream it knows is reset, so a writer waiting on that credit
            // has to be woken by the reset itself, or it waits for the connection to end.
            using var client = new StrictClient();
            string outcome = "the handler never got past its flush";
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write(new byte[64 * 1024]);
                bool gone = (await writer.FlushAsync()).IsCompleted;

                string end;
                try
                {
                    while (!(await body.ReadAsync()).IsEmpty)
                    {
                    }
                    end = "ended";
                }
                catch (IOException)
                {
                    end = "raised";
                }
                outcome = $"flush {(gone ? "completed" : "not completed")}, body {end}";
            });

            client.ReleaseFlush();   // the server's SETTINGS
            client.Feed([
                .. Http2FlowControlTests.Open((Http2FlowControlTests.InitialWindowSize, 16384)),
                .. Http2FlowControlTests.WindowUpdate(0, 1 << 20),
                .. FrameBytes(Headers, EndHeaders, 1, Post("10")),
            ]);
            List<Frame> frames = client.Drain();
            Assert.True(Frame.Body(frames, 1).Length == 16384 && outcome == "the handler never got past its flush",
                $"{Frame.Body(frames, 1).Length} body bytes went out and the handler {outcome}: it was not parked on the stream window");

            client.Feed(Body(1, 12, endStream: true));   // twelve of ten
            frames.AddRange(client.Drain());
            string seen = outcome;
            client.Close(run);

            Assert.Equal("flush completed, body raised", seen);
            Assert.Equal("HEADERS, DATA, RST_STREAM PROTOCOL_ERROR", Trace(frames, 1));
        });
    }

    /// <summary>
    /// A POST declaring <paramref name="contentLength"/> to a handler that takes a body reader, with
    /// six body bytes it reads while the stream is open, then <paramref name="rest"/>. Reports how the
    /// handler's read ended - "ended after N", or "raised after N: why" - and what went out on the stream.
    /// </summary>
    /// <remarks>
    /// The six bytes are drained before the rest is sent, so the handler is dispatched and reading
    /// BEFORE the body breaks its length. Fed with the rest, the refusal would land before dispatch,
    /// which the buffered tests already cover.
    /// </remarks>
    private static (string End, string Trace) StreamedOutcome(string contentLength, params byte[][] rest)
    {
        using var client = new StrictClient();
        string end = "never ended";
        long read = 0;
        Task run = client.Connection.RunAsync(async (_, body) =>
        {
            try
            {
                ReadOnlyMemory<byte> chunk;
                while (!(chunk = await body.ReadAsync()).IsEmpty)
                {
                    read += chunk.Length;
                }
                end = $"ended after {read}";
            }
            catch (IOException exception)
            {
                end = $"raised after {read}: {exception.Message}";
            }
            return Http2Response.Text("done");
        });
        client.SendRequests();
        List<Frame> frames = client.Drain();

        client.Feed(FrameBytes(Headers, EndHeaders, 1, Post(contentLength)));
        client.Feed(Body(1, 6, endStream: false));
        frames.AddRange(client.Drain());
        Assert.True(read == 6, $"the handler had read {read} of the six bytes sent ahead of the rest, so it was not reading yet");

        foreach (byte[] frame in rest)
        {
            client.Feed(frame);
        }
        frames.AddRange(client.Drain());
        string seen = end;   // before the close, which would end a body still waiting on its own terms
        client.Close(run);

        return (seen, Trace(frames, 1));
    }

    /// <summary>
    /// A streamed response whose request body runs past its content-length, refused in the pass that
    /// dispatched it or once its handler is running, and what that handler saw: how its body read
    /// ended, and whether the flush after it said the stream was gone.
    /// </summary>
    private static (string Outcome, string Trace) StreamedResponseOutcome(bool samePass)
    {
        using var client = new StrictClient();
        string outcome = "the handler never got past its body";
        Task run = client.Connection.RunAsync(async (_, body, writer) =>
        {
            writer.WriteHeaders(new Http2Response { Status = 200 });

            string end;
            try
            {
                while (!(await body.ReadAsync()).IsEmpty)
                {
                }
                end = "ended";
            }
            catch (IOException)
            {
                end = "raised";
            }

            writer.Write("after"u8);
            bool gone = (await writer.FlushAsync()).IsCompleted;
            outcome = $"body {end}, flush {(gone ? "completed" : "not completed")}";
        });
        client.SendRequests();
        List<Frame> frames = client.Drain();

        byte[] headers = FrameBytes(Headers, EndHeaders, 1, Post("10"));
        byte[] overrun = Body(1, 100, endStream: true);
        if (samePass)
        {
            client.Feed([.. headers, .. overrun]);
        }
        else
        {
            client.Feed(headers);
            frames.AddRange(client.Drain());   // its HEADERS go out, and it parks on its body
            client.Feed(overrun);
        }
        frames.AddRange(client.Drain());
        string seen = outcome;
        client.Close(run);

        return (seen, Trace(frames, 1));
    }

    /// <summary>
    /// A POST under the given content-length fields, with the ten body bytes they claim, then a request
    /// that reads back the field the first one's block inserted. Reports the resets and what was served.
    /// </summary>
    private static string MalformedOutcome(bool reader, string[] contentLengths)
    {
        using var client = new StrictClient();
        var served = new List<string>();
        ValueTask<Http2Response> Serve(Http2Request request)
        {
            served.Add($"{request.StreamId} {Fields(request)}");
            return ValueTask.FromResult(Http2Response.Text("ok"));
        }
        Task run = reader
            ? client.Connection.RunAsync((request, _) => Serve(request))
            : client.Connection.RunAsync(Serve);
        client.SendRequests();
        client.Drain();

        // x-b exists for stream 3's reference only if the refused block was decoded whole.
        client.Feed(FrameBytes(Headers, EndHeaders, 1, [.. Post(contentLengths), .. Http2TrailerTests.Field("x-b", "w", index: true)]));
        client.Feed(Body(1, 10, endStream: true));
        client.Feed(FrameBytes(Headers, EndHeaders | EndStream, 3, [.. Post(), 0xBE]));
        List<Frame> frames = client.Drain();
        client.Close(run);

        return $"reset {Errors(frames)}, served {string.Join(", ", served)}";
    }

    // :method POST, :scheme http and :path / from the static table, and a content-length field per value.
    private static byte[] Post(params string[] contentLengths)
    {
        var block = new List<byte> { 0x83, 0x86, 0x84 };
        foreach (string contentLength in contentLengths)
        {
            block.AddRange(Http2TrailerTests.Field("content-length", contentLength));
        }
        return [.. block];
    }

    private static byte[] Body(int streamId, int bytes, bool endStream)
        => FrameBytes(Data, endStream ? EndStream : 0, streamId, Enumerable.Repeat((byte)'z', bytes).ToArray());

    // A pad-length octet, the body, then the padding: all of it flow-controlled, only the body counted.
    private static byte[] PaddedBody(int streamId, int bytes, int padding)
        => FrameBytes(Data, Padded, streamId, [(byte)padding, .. Enumerable.Repeat((byte)'z', bytes), .. new byte[padding]]);

    private static byte[] FrameBytes(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);

    private static string Fields(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Encoding.ASCII.GetString(field.Key.Span)}={Encoding.ASCII.GetString(field.Value.Span)}");
        }
        return string.Join(' ', fields);
    }

    /// <summary>Every RST_STREAM as "stream CODE", and every GOAWAY as "GOAWAY CODE", in wire order.</summary>
    private static string Errors(IEnumerable<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type is RstStream or GoAway)
        .Select(f => f.Type == RstStream
            ? $"{f.StreamId} {ErrorName(f.Payload.AsSpan(0, 4))}"
            : $"GOAWAY {ErrorName(f.Payload.AsSpan(4, 4))}"));

    /// <summary>What went out on one stream, flow control aside: its response, and how it ended.</summary>
    private static string Trace(IEnumerable<Frame> frames, int streamId) => string.Join(", ", frames
        .Where(f => f.StreamId == streamId && f.Type != WindowUpdate)
        .Select(f => f.Type switch
        {
            Headers => "HEADERS",
            Data => "DATA",
            RstStream => $"RST_STREAM {ErrorName(f.Payload.AsSpan(0, 4))}",
            byte other => $"frame 0x{other:x}",
        }));

    private static int Credit(IEnumerable<Frame> frames, int streamId) => frames
        .Where(f => f.Type == WindowUpdate && f.StreamId == streamId)
        .Sum(f => (int)(BinaryPrimitives.ReadUInt32BigEndian(f.Payload) & 0x7FFFFFFF));

    private static string ErrorName(ReadOnlySpan<byte> code) => BinaryPrimitives.ReadUInt32BigEndian(code) switch
    {
        0x1 => "PROTOCOL_ERROR",
        uint other => $"0x{other:x}",
    };
}
