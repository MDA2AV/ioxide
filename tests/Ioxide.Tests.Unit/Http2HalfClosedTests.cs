using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// DATA on a stream whose request has ended, at its last DATA, its HEADERS or its trailers. The stream is then
/// half-closed (remote), and RFC 9113 5.1 makes DATA on it a stream error of STREAM_CLOSED: the stream is reset
/// once, its handler reads none of that DATA, nothing more of its response goes out, and the connection serves on.
/// </summary>
internal static class Http2HalfClosedTests
{
    private const byte Data = 0x0, Headers = 0x1, RstStream = 0x3, GoAway = 0x7, WindowUpdate = 0x8;
    private const byte EndStream = 0x1, EndHeaders = 0x4;
    private const byte Get = 0x82, Post = 0x83;

    // More body after the end, in two frames: the second comes after the reset, before the client has heard of it.
    private static readonly byte[] Late = [.. Bytes(Data, 0, 1, "bbbbb"u8), .. Bytes(Data, 0, 1, "bbbbb"u8)];

    public static void Register(Runner runner)
    {
        foreach (bool inOneRead in new[] { true, false })
        {
            bool samePass = inOneRead;
            runner.Test(samePass
                ? "h2 half-closed: DATA after a request's END_STREAM, in the same read, resets its stream with STREAM_CLOSED, and its handler reads none of it"
                : "h2 half-closed: DATA after a request's END_STREAM, while its handler runs, resets its stream with STREAM_CLOSED, and a read after the end finds none of it", () =>
            {
                foreach (bool declared in new[] { false, true })
                {
                    foreach ((string ending, byte[] sent, string body) in Requests(declared))
                    {
                        string label = $"DATA came after a request's END_STREAM on {ending}{(declared ? ", under a content-length" : "")}";
                        (List<Frame> frames, List<string> reads) = Outcome(sent, samePass);

                        Assert.True(Errors(frames) == "1 STREAM_CLOSED", $"{label}, and the server wrote [{Errors(frames)}]");
                        Assert.True(Trace(frames, 1) == "RST_STREAM STREAM_CLOSED", $"{label}, and stream 1 carried [{Trace(frames, 1)}]");
                        Assert.True(samePass ? reads.All(read => !read.Contains("bbbbb")) : reads.SequenceEqual([$"ended '{body}'", "ended ''"]),
                            $"{label}, and its handler's reads {string.Join(", then ", reads)}");
                        Assert.True(frames.Any(f => f.StreamId == 3 && f.EndStream), $"{label}, and the next request went unanswered");
                    }
                }
            });
        }

        runner.Test("h2 half-closed: a streamed response whose request gets DATA after its END_STREAM finds its stream gone, and sends nothing after the reset", () =>
        {
            using var client = new StrictClient();
            var gate = new TaskCompletionSource();
            string outcome = "never got past its gate";
            Task run = client.Connection.RunAsync(async (_, body, writer) =>
            {
                string first = await ReadAll(body);
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write("part1"u8);
                await writer.FlushAsync();
                await gate.Task;

                string second = await ReadAll(body);
                writer.Write("part2"u8);
                bool gone = (await writer.FlushAsync()).IsCompleted;
                outcome = $"read {first}, then {second}, flush {(gone ? "completed" : "not completed")}";
            });
            client.SendRequests();
            List<Frame> frames = client.Drain();

            client.Feed([.. Opening(Post, contentLength: null), .. Bytes(Data, EndStream, 1, "aaaaa"u8)]);
            frames.AddRange(client.Drain());   // its headers and first part go out, and it parks on the gate
            client.Feed(Late);
            frames.AddRange(client.Drain());
            gate.SetResult();
            frames.AddRange(client.Drain());
            string seen = outcome;
            client.Close(run);

            Assert.Equal("read ended 'aaaaa', then ended '', flush completed", seen);
            Assert.Equal("HEADERS, DATA, RST_STREAM STREAM_CLOSED", Trace(frames, 1));
            Assert.Equal("part1", Encoding.ASCII.GetString(Frame.Body(frames, 1)));
        });

        runner.Test("h2 half-closed: a streamed response parked on credit when its request gets DATA after its END_STREAM wakes to find its stream gone", () =>
        {
            // The client will not credit a stream it knows is reset, so the reset itself has to wake the writer.
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

            client.ReleaseFlush();   // the server's SETTINGS
            client.Feed([
                .. Http2FlowControlTests.Open((Http2FlowControlTests.InitialWindowSize, 16384)),
                .. Http2FlowControlTests.WindowUpdate(0, 1 << 20),
                .. Opening(Post, contentLength: null), .. Bytes(Data, EndStream, 1, "aaaaa"u8),
            ]);
            List<Frame> frames = client.Drain();
            Assert.True(Frame.Body(frames, 1).Length == 16384 && outcome == "never got past its flush",
                $"{Frame.Body(frames, 1).Length} body bytes went out and the handler {outcome}: it was not parked on the stream window");

            client.Feed(Late);
            frames.AddRange(client.Drain());
            string seen = outcome;   // before the close, which wakes every parked writer
            client.Close(run);

            Assert.Equal("read ended 'aaaaa', flush completed", seen);
            Assert.Equal("HEADERS, DATA, RST_STREAM STREAM_CLOSED", Trace(frames, 1));
        });
    }

    /// <summary>
    /// Stream 1's request in each way one ends, and the body its handler should read. Declared, it carries a
    /// content-length that matches that body, and which the late DATA would also run past.
    /// </summary>
    private static (string Ending, byte[] Sent, string Body)[] Requests(bool declared) =>
    [
        ("its last DATA", [.. Opening(Post, declared ? "5" : null), .. Bytes(Data, EndStream, 1, "aaaaa"u8)], "aaaaa"),
        ("its HEADERS", Bytes(Headers, EndHeaders | EndStream, 1, Block(Get, declared ? "0" : null)), ""),
        ("its trailers", [
            .. Opening(Post, declared ? "5" : null), .. Bytes(Data, 0, 1, "aaaaa"u8),
            .. Bytes(Headers, EndHeaders | EndStream, 1, Http2TrailerTests.Field("x-checksum", "abc")),
        ], "aaaaa"),
    ];

    /// <summary>
    /// <paramref name="sent"/>, then <see cref="Late"/> in the same read or once stream 1's handler is running, then a
    /// GET on stream 3. Stream 1's handler reads its body, waits until the late DATA is in, and reads again.
    /// </summary>
    private static (List<Frame> Frames, List<string> Reads) Outcome(byte[] sent, bool samePass)
    {
        using var client = new StrictClient();
        var gate = new TaskCompletionSource();
        var reads = new List<string>();
        Task run = client.Connection.RunAsync(async (request, body) =>
        {
            if (request.StreamId == 1)
            {
                reads.Add(await ReadAll(body));
                await gate.Task;
                reads.Add(await ReadAll(body));   // after the end, and after the DATA past it
            }
            return Http2Response.Text("done");
        });
        client.SendRequests();
        client.Drain();

        List<Frame> frames;
        if (samePass)
        {
            client.Feed([.. sent, .. Late]);
            frames = client.Drain();
        }
        else
        {
            client.Feed(sent);
            frames = client.Drain();
            Assert.True(reads.Count == 1, "precondition: the handler was meant to have read to its body's end before the late DATA");
            client.Feed(Late);
            frames.AddRange(client.Drain());
        }
        gate.SetResult();
        frames.AddRange(client.Drain());

        client.Feed(Http2FlowControlTests.Get(3));
        frames.AddRange(client.Drain());
        client.Close(run);

        return (frames, reads);
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

    private static byte[] Opening(byte method, string? contentLength) => Bytes(Headers, EndHeaders, 1, Block(method, contentLength));

    // The method, :scheme http and :path / from the static table, and a content-length when given.
    private static byte[] Block(byte method, string? contentLength) => contentLength is null
        ? [method, 0x86, 0x84]
        : [method, 0x86, 0x84, .. Http2TrailerTests.Field("content-length", contentLength)];

    private static byte[] Bytes(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);

    /// <summary>Every RST_STREAM as "stream CODE" and every GOAWAY as "GOAWAY CODE", in wire order.</summary>
    private static string Errors(IEnumerable<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type is RstStream or GoAway)
        .Select(f => f.Type == RstStream ? $"{f.StreamId} {ErrorName(f.Payload.AsSpan(0, 4))}" : $"GOAWAY {ErrorName(f.Payload.AsSpan(4, 4))}"));

    /// <summary>Every frame on one stream, credit included, in wire order.</summary>
    private static string Trace(IEnumerable<Frame> frames, int streamId) => string.Join(", ", frames
        .Where(f => f.StreamId == streamId)
        .Select(f => f.Type switch
        {
            Headers => "HEADERS",
            Data => "DATA",
            RstStream => $"RST_STREAM {ErrorName(f.Payload.AsSpan(0, 4))}",
            WindowUpdate => $"WINDOW_UPDATE +{BinaryPrimitives.ReadUInt32BigEndian(f.Payload) & 0x7FFFFFFF}",
            byte other => $"frame 0x{other:x}",
        }));

    private static string ErrorName(ReadOnlySpan<byte> code) => BinaryPrimitives.ReadUInt32BigEndian(code) switch
    {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x5 => "STREAM_CLOSED",
        uint other => $"0x{other:x}",
    };
}
