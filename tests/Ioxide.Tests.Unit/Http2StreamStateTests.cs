using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// Frames a stream's state rules out. Past a request's END_STREAM its stream is half-closed (remote), and RFC 9113 5.1
/// makes DATA or HEADERS on it a stream error of STREAM_CLOSED while its answer is still under way; 8.1 makes HEADERS
/// without END_STREAM after a request's opening block malformed, a stream error of PROTOCOL_ERROR. Either way the stream
/// is reset once, only after a header block has been decoded whole so HPACK stays in step, nothing of its answer goes
/// out after the reset, and the connection serves on.
/// </summary>
internal static class Http2StreamStateTests
{
    private const byte GoAwayFrame = 0x7;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_writerPool")]
    private static extern ref Stack<Http2ResponseWriter> WriterPool(Http2Connection connection);

    // Inserts x-late: 1 into the dynamic table at 62 (RFC 7541 6.2.1), so a later request can show the block was decoded.
    private static readonly byte[] LateBlock = Http2TrailerTests.Field("x-late", "1", index: true);

    // A GET on stream 3 that carries index 62: with the late block skipped rather than decoded, the connection ends in COMPRESSION_ERROR.
    private static readonly byte[] NextGet = HeadersFrame(3, [0x82, 0x86, 0x84, 0x80 | 62], endStream: true);

    public static void Register(Runner runner)
    {
        RegisterBuffered(runner);
        RegisterBodyReader(runner);
        RegisterAnswers(runner);
        RegisterControls(runner);
    }

    private static void RegisterBuffered(Runner runner)
    {
        foreach (bool parked in new[] { false, true })
        {
            string when = parked ? "while its handler is parked" : "in the same read";

            runner.Test($"h2 half-closed: DATA after a buffered request's END_STREAM, {when}, resets its stream with STREAM_CLOSED, and its answer never goes out", () =>
            {
                foreach ((string ending, byte[] request, string before) in Requests())
                {
                    foreach ((string name, byte[] late) in LateData())
                    {
                        string label = $"{name} came after a request's END_STREAM on {ending}";
                        (List<Frame> frames, _) = Buffered(request, [late], parked, Get(3));

                        Assert.True(Errors(frames) == "1 STREAM_CLOSED", $"{label}, and the server wrote [{Errors(frames)}]");
                        Assert.True(Trace(frames, 1) == $"{before}RST_STREAM STREAM_CLOSED", $"{label}, and stream 1 carried [{Trace(frames, 1)}]");
                        Assert.True(frames.Any(f => f.StreamId == 3 && f.EndStream), $"{label}, and the next request went unanswered");
                    }
                }
            });

            runner.Test($"h2 half-closed: HEADERS after a buffered request's END_STREAM, {when}, resets its stream with STREAM_CLOSED once its block is decoded", () =>
            {
                foreach ((string ending, byte[] request, string before) in Requests())
                {
                    foreach ((string name, byte[][] late) in LateHeaders())
                    {
                        string label = $"{name} came after a request's END_STREAM on {ending}";
                        (List<Frame> frames, string next) = Buffered(request, late, parked, NextGet);

                        Assert.True(Errors(frames) == "1 STREAM_CLOSED", $"{label}, and the server wrote [{Errors(frames)}]");
                        Assert.True(Trace(frames, 1) == $"{before}RST_STREAM STREAM_CLOSED", $"{label}, and stream 1 carried [{Trace(frames, 1)}]");
                        Assert.True(next == "x-late: 1", $"{label}, and the next request was served with [{next}]");
                    }
                }
            });
        }

        runner.Test("h2 half-closed: HEADERS after a request's END_STREAM, split over CONTINUATION, is reset only once its block is whole", () =>
        {
            foreach (bool reader in new[] { false, true })
            {
                using var client = new StrictClient();
                var gate = new TaskCompletionSource();
                string next = "never served";
                Func<Http2Request, ValueTask<Http2Response>> answer = async request =>
                {
                    if (request.StreamId == 1)
                    {
                        await gate.Task;
                    }
                    else
                    {
                        next = Fields(request);
                    }
                    return Http2Response.Text("done");
                };
                Task run = reader ? client.Connection.RunAsync((request, _) => answer(request)) : client.Connection.RunAsync(answer);
                client.SendRequests();
                client.Drain();

                string label = reader ? "with a body reader" : "buffered";
                client.Feed(Get(1));
                List<Frame> frames = client.Drain();
                client.Feed(HeadersFrame(1, LateBlock[..3], endStream: true, endHeaders: false));
                frames.AddRange(client.Drain());
                Assert.True(Errors(frames) == "", $"{label}, the stream was reset with [{Errors(frames)}] before its block's CONTINUATION came");

                client.Feed(ContinuationFrame(1, LateBlock[3..]));
                frames.AddRange(client.Drain());
                gate.SetResult();
                frames.AddRange(client.Drain());
                client.Feed(NextGet);
                frames.AddRange(client.Drain());
                client.Close(run);

                Assert.True(Errors(frames) == "1 STREAM_CLOSED", $"{label}, and the server wrote [{Errors(frames)}]");
                Assert.True(Trace(frames, 1) == "RST_STREAM STREAM_CLOSED", $"{label}, and stream 1 carried [{Trace(frames, 1)}]");
                Assert.True(next == "x-late: 1", $"{label}, and the next request was served with [{next}]");
            }
        });
    }

    private static void RegisterBodyReader(Runner runner)
    {
        foreach (bool running in new[] { false, true })
        {
            string when = running ? "while its handler runs" : "in the same read";

            runner.Test($"h2 half-closed: HEADERS after a body-reader request's END_STREAM, {when}, resets its stream with STREAM_CLOSED once its block is decoded", () =>
            {
                foreach ((string ending, byte[] request, string body) in BodyRequests())
                {
                    foreach ((string name, byte[][] late) in LateHeaders())
                    {
                        string label = $"{name} came after a request's END_STREAM on {ending}";
                        (List<Frame> frames, List<string> reads, string next) = WithReader(request, late, running, readTwice: true);

                        Assert.True(Errors(frames) == "1 STREAM_CLOSED", $"{label}, and the server wrote [{Errors(frames)}]");
                        Assert.True(Trace(frames, 1) == "RST_STREAM STREAM_CLOSED", $"{label}, and stream 1 carried [{Trace(frames, 1)}]");
                        Assert.True(!running || reads.SequenceEqual([$"ended '{body}'", "ended ''"]),
                            $"{label}, and its handler's reads {string.Join(", then ", reads)}");
                        Assert.True(next == "x-late: 1", $"{label}, and the next request was served with [{next}]");
                    }
                }
            });

            runner.Test($"h2 malformed: HEADERS without END_STREAM while a body-reader request's body arrives, {when}, resets its stream with PROTOCOL_ERROR, and its read raises", () =>
            {
                foreach ((string name, byte[][] late) in new (string, byte[][])[]
                {
                    ("one HEADERS", [HeadersFrame(1, LateBlock, endStream: false)]),
                    ("a HEADERS and its CONTINUATION", [HeadersFrame(1, LateBlock[..3], endStream: false, endHeaders: false), ContinuationFrame(1, LateBlock[3..])]),
                })
                {
                    string label = $"{name} without END_STREAM came while the body arrived";
                    byte[] rest = DataFrame(1, "bbbbb", endStream: true);   // after the reset: dropped, and never credited
                    (List<Frame> frames, List<string> reads, string next) = WithReader(
                        [.. Post(1), .. DataFrame(1, "aaaaa", endStream: false)], [.. late, rest], running, readTwice: false);

                    Assert.True(Errors(frames) == "1 PROTOCOL_ERROR", $"{label}, and the server wrote [{Errors(frames)}]");
                    Assert.True(Trace(frames, 1) == (running ? "WINDOW_UPDATE +5, " : "") + "RST_STREAM PROTOCOL_ERROR",
                        $"{label}, and stream 1 carried [{Trace(frames, 1)}]");
                    Assert.True(reads.SequenceEqual([running ? "raised 'aaaaa'" : "raised ''"]), $"{label}, and its handler's reads {string.Join(", then ", reads)}");
                    Assert.True(next == "x-late: 1", $"{label}, and the next request was served with [{next}]");
                }
            });
        }
    }

    private static void RegisterAnswers(Runner runner)
    {
        runner.Test("h2 half-closed: a streamed response whose request gets a frame after its END_STREAM finds its stream gone, and sends nothing after the reset", () =>
        {
            foreach ((string label, bool reader, byte[] request, byte[] late) in new (string, bool, byte[], byte[])[]
            {
                ("DATA, without a body reader", false, Get(1), DataFrame(1, "late!", endStream: false)),
                ("HEADERS, without a body reader", false, Get(1), HeadersFrame(1, LateBlock, endStream: true)),
                ("HEADERS, with a body reader", true, [.. Post(1), .. DataFrame(1, "aaaaa", endStream: true)], HeadersFrame(1, LateBlock, endStream: true)),
            })
            {
                using var client = new StrictClient();
                var gate = new TaskCompletionSource();
                string outcome = "never got past its gate";
                Func<Http2ResponseWriter, ValueTask> respond = async writer =>
                {
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    writer.Write("part1"u8);
                    await writer.FlushAsync();
                    await gate.Task;

                    writer.Write("part2"u8);
                    outcome = (await writer.FlushAsync()).IsCompleted ? "flush completed" : "flush not completed";
                };
                Task run = reader
                    ? client.Connection.RunAsync(async (_, body, writer) =>
                    {
                        await ReadAll(body);
                        await respond(writer);
                    })
                    : client.Connection.RunAsync((_, writer) => respond(writer));
                client.SendRequests();
                List<Frame> frames = client.Drain();

                client.Feed(request);
                frames.AddRange(client.Drain());   // its headers and first part go out, and it parks on the gate
                client.Feed(late);
                frames.AddRange(client.Drain());
                gate.SetResult();
                frames.AddRange(client.Drain());
                string seen = outcome;
                client.Close(run);

                Assert.True(seen == "flush completed", $"{label} came after the request's END_STREAM, and the handler's next flush: {seen}");
                Assert.True(Trace(frames, 1) == "HEADERS, DATA, RST_STREAM STREAM_CLOSED", $"{label} came after the request's END_STREAM, and stream 1 carried [{Trace(frames, 1)}]");
                Assert.Equal("part1", Encoding.ASCII.GetString(Frame.Body(frames, 1)));
            }
        });

        runner.Test("h2 half-closed: a buffered answer parked on credit when its request gets a frame after its END_STREAM stops there, and its writer goes back to the pool", () =>
        {
            // The client will not credit a stream it knows is reset, so the reset itself has to wake the parked rest.
            foreach ((string label, byte[] late) in new (string, byte[])[]
            {
                ("DATA", DataFrame(1, "late!", endStream: true)),
                ("HEADERS", HeadersFrame(1, LateBlock, endStream: true)),
            })
            {
                using var client = new StrictClient();
                Task run = client.Connection.RunAsync(request => new Http2Response { Status = 200, Body = new byte[request.StreamId == 1 ? 64 * 1024 : 10] });

                client.ReleaseFlush();   // the server's SETTINGS
                client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
                List<Frame> frames = client.Drain();
                Assert.True(Frame.Body(frames, 1).Length == 16384, $"{Frame.Body(frames, 1).Length} body bytes went out: the answer was not parked on its stream window");

                client.Feed(late);
                frames.AddRange(client.Drain());
                Assert.True(WriterPool(client.Connection).Count == 1, $"{label} came after the request's END_STREAM, and its parked answer was left waiting on credit");

                client.Feed([.. WindowUpdate(1, 1 << 20), .. Get(3)]);
                frames.AddRange(client.Drain());
                client.Close(run);

                Assert.True(Trace(frames, 1) == "HEADERS, DATA, RST_STREAM STREAM_CLOSED", $"{label} came after the request's END_STREAM, and stream 1 carried [{Trace(frames, 1)}]");
                Assert.True(Frame.Body(frames, 3).Length == 10, $"{label} came after the request's END_STREAM, and the next request was answered with {Frame.Body(frames, 3).Length} body bytes");
            }
        });

        runner.Test("h2 half-closed: a streamed response parked on credit when its request gets HEADERS after its END_STREAM wakes to find its stream gone", () =>
        {
            using var client = new StrictClient();
            string outcome = "never got past its flush";
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                string read = await ReadAll(body);
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write(new byte[64 * 1024]);
                bool gone = (await writer.FlushAsync()).IsCompleted;
                outcome = $"read {read}, flush {(gone ? "completed" : "not completed")}";
            });

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Post(1), .. DataFrame(1, "aaaaa", endStream: true)]);
            List<Frame> frames = client.Drain();
            Assert.True(Frame.Body(frames, 1).Length == 16384 && outcome == "never got past its flush",
                $"{Frame.Body(frames, 1).Length} body bytes went out and the handler {outcome}: it was not parked on the stream window");

            client.Feed(HeadersFrame(1, LateBlock, endStream: true));
            frames.AddRange(client.Drain());
            string seen = outcome;   // before the close, which wakes every parked writer
            client.Close(run);

            Assert.Equal("read ended 'aaaaa', flush completed", seen);
            Assert.Equal("HEADERS, DATA, RST_STREAM STREAM_CLOSED", Trace(frames, 1));
        });
    }

    private static void RegisterControls(Runner runner)
    {
        runner.Test("h2 half-closed: control: DATA and HEADERS after the answer has ended find the stream closed, and are dropped without a reset or credit", () =>
        {
            using var client = new StrictClient();
            string next = "never served";
            Task run = client.Connection.RunAsync(request =>
            {
                if (request.StreamId == 3)
                {
                    next = Fields(request);
                }
                return Http2Response.Text("done");
            });
            client.SendRequests();
            client.Drain();

            client.Feed(Get(1));
            List<Frame> frames = client.Drain();
            Assert.True(frames.Any(f => f.StreamId == 1 && f.EndStream), "precondition: stream 1 was meant to be answered before the late frames");

            client.Feed([.. DataFrame(1, "late!", endStream: false), .. HeadersFrame(1, LateBlock, endStream: true), .. NextGet]);
            frames.AddRange(client.Drain());
            client.Close(run);

            Assert.True(Errors(frames) == "", $"frames on a closed stream drew [{Errors(frames)}]");
            Assert.True(Trace(frames, 1) == "HEADERS, DATA", $"stream 1 carried [{Trace(frames, 1)}]");
            Assert.True(next == "x-late: 1", $"the next request was served with [{next}]");
        });

        runner.Test("h2 half-closed: control: with a body reader, an upload behind a buffered answer parked on credit still ends with its trailers, unreset", () =>
        {
            byte[] answer = new byte[64 * 1024];

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync((_, _) => new ValueTask<Http2Response>(new Http2Response { Status = 413, Body = answer }));

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Post(1), .. DataFrame(1, "aaaaa", endStream: false)]);
            List<Frame> frames = client.Drain();
            Assert.True(Frame.Body(frames, 1).Length == 16384, $"{Frame.Body(frames, 1).Length} body bytes went out: the answer was not parked on its stream window");

            client.Feed([.. DataFrame(1, "bbbbb", endStream: false), .. HeadersFrame(1, Http2TrailerTests.Field("x-checksum", "abc"), endStream: true)]);
            frames.AddRange(client.Drain());
            client.Feed(WindowUpdate(1, 1 << 20));
            frames.AddRange(client.Drain());
            client.Close(run);

            Assert.True(Errors(frames) == "", $"an upload that ended with its trailers drew [{Errors(frames)}]");
            Assert.True(Frame.Body(frames, 1).Length == answer.Length, $"{Frame.Body(frames, 1).Length} of the answer's {answer.Length} body bytes went out");
            Assert.True(frames.Last(f => f.StreamId == 1 && f.Type is Frame.Data or Frame.Headers).EndStream, "the answer never ended");
        });
    }

    /// <summary>Stream 1's request in each way one ends, and the credit the server writes on stream 1 before the late frame.</summary>
    private static (string Ending, byte[] Request, string Before)[] Requests() =>
    [
        ("its HEADERS", Get(1), ""),
        ("its last DATA", [.. Post(1), .. DataFrame(1, "aaaaa", endStream: true)], ""),
        ("its trailers", [.. Post(1), .. DataFrame(1, "aaaaa", endStream: false), .. HeadersFrame(1, Http2TrailerTests.Field("x-checksum", "abc"), endStream: true)],
            "WINDOW_UPDATE +5, "),
    ];

    /// <summary>The same, for a handler with a body reader, and the body it reads.</summary>
    private static (string Ending, byte[] Request, string Body)[] BodyRequests() =>
    [
        ("its HEADERS", Get(1), ""),
        ("its last DATA", [.. Post(1), .. DataFrame(1, "aaaaa", endStream: true)], "aaaaa"),
        ("its trailers", [.. Post(1), .. DataFrame(1, "aaaaa", endStream: false), .. HeadersFrame(1, Http2TrailerTests.Field("x-checksum", "abc"), endStream: true)],
            "aaaaa"),
    ];

    private static (string Name, byte[] Frame)[] LateData() =>
    [
        ("DATA with END_STREAM", DataFrame(1, "late!", endStream: true)),
        ("DATA without END_STREAM", DataFrame(1, "late!", endStream: false)),
        ("an empty DATA", DataFrame(1, "", endStream: false)),
    ];

    private static (string Name, byte[][] Frames)[] LateHeaders() =>
    [
        ("HEADERS with END_STREAM", [HeadersFrame(1, LateBlock, endStream: true)]),
        ("HEADERS without END_STREAM", [HeadersFrame(1, LateBlock, endStream: false)]),
        ("a HEADERS and its CONTINUATION", [HeadersFrame(1, LateBlock[..3], endStream: true, endHeaders: false), ContinuationFrame(1, LateBlock[3..])]),
    ];

    /// <summary>
    /// A buffered handler, <paramref name="request"/> on stream 1, then <paramref name="late"/> in the same read or
    /// once its handler is parked with its answer still to come, then <paramref name="nextRequest"/> on stream 3,
    /// whose fields come back.
    /// </summary>
    private static (List<Frame> Frames, string Next) Buffered(byte[] request, byte[][] late, bool parked, byte[] nextRequest)
    {
        using var client = new StrictClient();
        var gate = new TaskCompletionSource();
        string next = "never served";
        Task run = client.Connection.RunAsync(async request =>
        {
            if (request.StreamId == 1)
            {
                await (parked ? gate.Task : Task.CompletedTask);
            }
            else
            {
                next = Fields(request);
            }
            return Http2Response.Text("done");
        });
        client.SendRequests();
        client.Drain();

        List<Frame> frames;
        if (parked)
        {
            client.Feed(request);
            frames = client.Drain();
            Assert.True(!frames.Any(f => f.StreamId == 1 && f.Type == Frame.Headers), "precondition: the handler was meant to be parked, its answer still to come");
            foreach (byte[] frame in late)
            {
                client.Feed(frame);
                frames.AddRange(client.Drain());
            }
        }
        else
        {
            client.Feed([.. request, .. late.SelectMany(frame => frame)]);
            frames = client.Drain();
        }
        gate.SetResult();
        frames.AddRange(client.Drain());

        client.Feed(nextRequest);
        frames.AddRange(client.Drain());
        client.Close(run);
        return (frames, next);
    }

    /// <summary>
    /// A handler with a body reader, <paramref name="request"/> on stream 1, then <paramref name="late"/> in the same read
    /// or once its handler has read its body as far as it came, then a GET on stream 3 whose fields come back. Stream 1's
    /// handler reads its body, and with <paramref name="readTwice"/> waits until the late frames are in and reads again.
    /// </summary>
    private static (List<Frame> Frames, List<string> Reads, string Next) WithReader(byte[] request, byte[][] late, bool running, bool readTwice)
    {
        using var client = new StrictClient();
        var gate = new TaskCompletionSource();
        var reads = new List<string>();
        string next = "never served";
        Task run = client.Connection.RunAsync(async (request, body) =>
        {
            if (request.StreamId == 1)
            {
                reads.Add(await ReadAll(body));
                if (readTwice)
                {
                    await gate.Task;
                    reads.Add(await ReadAll(body));   // after the end, and after the frames past it
                }
            }
            else
            {
                next = Fields(request);
            }
            return Http2Response.Text("done");
        });
        client.SendRequests();
        client.Drain();

        List<Frame> frames;
        if (running)
        {
            client.Feed(request);
            frames = client.Drain();
            Assert.True(readTwice ? reads.Count == 1 : reads.Count == 0,
                "precondition: the handler was meant to have read its body as far as it came before the late frames");
            foreach (byte[] frame in late)
            {
                client.Feed(frame);
                frames.AddRange(client.Drain());
            }
        }
        else
        {
            client.Feed([.. request, .. late.SelectMany(frame => frame)]);
            frames = client.Drain();
        }
        gate.SetResult();
        frames.AddRange(client.Drain());

        client.Feed(NextGet);
        frames.AddRange(client.Drain());
        client.Close(run);
        return (frames, reads, next);
    }

    // The body as read, and how it ended: "ended '...'" at a clean end, "raised '...'" when it was cut off.
    private static async Task<string> ReadAll(Http2BodyReader body)
    {
        var text = new StringBuilder();
        try
        {
            ReadOnlyMemory<byte> chunk;
            while (!(chunk = await body.ReadAsync()).IsEmpty)
            {
                text.Append(Encoding.ASCII.GetString(chunk.Span));
            }
            return $"ended '{text}'";
        }
        catch (IOException)
        {
            return $"raised '{text}'";
        }
    }

    private static string Fields(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Encoding.ASCII.GetString(field.Key.Span)}: {Encoding.ASCII.GetString(field.Value.Span)}");
        }
        return string.Join(", ", fields);
    }

    private static byte[] DataFrame(int streamId, string body, bool endStream)
        => FrameBytes(0x0, endStream ? (byte)0x1 : (byte)0x0, streamId, Encoding.ASCII.GetBytes(body));

    private static byte[] HeadersFrame(int streamId, byte[] block, bool endStream, bool endHeaders = true)
        => FrameBytes(0x1, (byte)((endStream ? 0x1 : 0) | (endHeaders ? 0x4 : 0)), streamId, block);

    private static byte[] ContinuationFrame(int streamId, byte[] block) => FrameBytes(0x9, 0x4, streamId, block);

    /// <summary>Every RST_STREAM as "stream CODE" and every GOAWAY as "GOAWAY CODE", in wire order.</summary>
    private static string Errors(IEnumerable<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type is RstStreamFrame or GoAwayFrame)
        .Select(f => f.Type == RstStreamFrame ? $"{f.StreamId} {ErrorName(f.Payload.AsSpan(0, 4))}" : $"GOAWAY {ErrorName(f.Payload.AsSpan(4, 4))}"));

    /// <summary>Every frame on one stream, credit included, in wire order.</summary>
    private static string Trace(IEnumerable<Frame> frames, int streamId) => string.Join(", ", frames
        .Where(f => f.StreamId == streamId)
        .Select(f => f.Type switch
        {
            Frame.Headers => "HEADERS",
            Frame.Data => "DATA",
            RstStreamFrame => $"RST_STREAM {ErrorName(f.Payload.AsSpan(0, 4))}",
            Frame.WindowUpdate => $"WINDOW_UPDATE +{BinaryPrimitives.ReadUInt32BigEndian(f.Payload) & 0x7FFFFFFF}",
            byte other => $"frame 0x{other:x}",
        }));

    private static string ErrorName(ReadOnlySpan<byte> code) => BinaryPrimitives.ReadUInt32BigEndian(code) switch
    {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x5 => "STREAM_CLOSED",
        0x9 => "COMPRESSION_ERROR",
        uint other => $"0x{other:x}",
    };
}
