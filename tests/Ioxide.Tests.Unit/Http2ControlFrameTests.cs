using System.Buffers.Binary;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// The framing of PRIORITY, PUSH_PROMISE, RST_STREAM, SETTINGS and PING (RFC 9113 6.3-6.7), and the
/// GOAWAY a connection error is answered with (6.8). A malformed control frame is the peer's error, of
/// the stream or of the connection as the RFC names it, and never something taken as it came.
/// </summary>
internal static class Http2ControlFrameTests
{
    private const byte Headers = 0x1, Priority = 0x2, RstStream = 0x3, Settings = 0x4, PushPromise = 0x5, Ping = 0x6, GoAway = 0x7;
    private const byte EndStream = 0x1, Ack = 0x1, EndHeaders = 0x4, PriorityFlag = 0x20;

    public static void Register(Runner runner)
    {
        // Each one follows stream 1, served, so the GOAWAY has a stream to name; stream 3 comes after it.
        foreach ((string name, byte[] frame, string expected) in new[]
        {
            ("a PRIORITY on stream 0", Frame(Priority, 0, 0, Dependency(1)), "GOAWAY 1 0x1"),
            ("a PRIORITY of four octets on an idle stream", Frame(Priority, 0, 5, [0, 0, 0, 1]), "GOAWAY 1 0x6"),
            ("a PRIORITY on an idle stream that depends on itself", Frame(Priority, 0, 5, Dependency(5)), "GOAWAY 1 0x1"),
            ("a PUSH_PROMISE", Frame(PushPromise, EndHeaders, 1, [0, 0, 0, 2, 0x82, 0x86, 0x84]), "GOAWAY 1 0x1"),
            ("an RST_STREAM on stream 0", Frame(RstStream, 0, 0, [0, 0, 0, 8]), "GOAWAY 1 0x1"),
            ("an RST_STREAM of three octets", Frame(RstStream, 0, 1, [0, 0, 8]), "GOAWAY 1 0x6"),
            ("a SETTINGS ACK with a payload", Frame(Settings, Ack, 0, [0, 4, 0, 0, 0xff, 0xff]), "GOAWAY 1 0x6"),
            ("a SETTINGS on stream 1", Frame(Settings, 0, 1, []), "GOAWAY 1 0x1"),
            ("SETTINGS_ENABLE_PUSH 2", Http2FlowControlTests.Settings((0x2, 2)), "GOAWAY 1 0x1"),
            ("a PING on stream 1", Frame(Ping, 0, 1, new byte[8]), "GOAWAY 1 0x1"),
            ("a DATA on an idle stream", Frame(0x0, 0, 9, [1]), "GOAWAY 1 0x1"),
        })
        {
            string shape = name;
            byte[] bad = frame;
            string answer = expected;
            runner.Test($"h2 control frames: {shape} ends the connection, and its GOAWAY names the last stream served", () =>
            {
                (List<Frame> frames, List<int> served) = Exchange(bad);

                Assert.Equal(answer, Errors(frames));
                Assert.True(served.SequenceEqual([1]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }

        runner.Test("h2 control frames: control: a well-formed PRIORITY, SETTINGS_ENABLE_PUSH 0 and 1, an empty SETTINGS ACK and a PING take nothing down", () =>
        {
            (List<Frame> frames, List<int> served) = Exchange(
            [
                .. Frame(Priority, 0, 1, Dependency(0)),     // a closed stream
                .. Frame(Priority, 0, 7, Dependency(1)),     // an idle one, which it leaves idle
                .. Http2FlowControlTests.Settings((0x2, 0)),
                .. Http2FlowControlTests.Settings((0x2, 1)),
                .. Frame(Settings, Ack, 0, []),
                .. Frame(Ping, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]),
            ]);

            Assert.Equal("", Errors(frames));
            Assert.True(served.SequenceEqual([1, 3]), $"the handler was handed: {string.Join(", ", served)}");
            Assert.Equal(1, frames.Count(f => f.Type == Ping && f.Flags == Ack && f.Payload.SequenceEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })));
        });

        // A request still arriving, so the stream is open when the frame names it.
        foreach ((string name, byte[] frame, string expected) in new[]
        {
            ("a PRIORITY of four octets", Frame(Priority, 0, 1, [0, 0, 0, 3]), "RST_STREAM 1 0x6"),
            ("a PRIORITY that depends on its own stream", Frame(Priority, 0, 1, Dependency(1)), "RST_STREAM 1 0x1"),
        })
        {
            string shape = name;
            byte[] bad = frame;
            string answer = expected;
            runner.Test($"h2 control frames: {shape} resets a request still arriving, and the next is served", () =>
            {
                using var client = new StrictClient();
                var served = new List<int>();
                Task run = client.Connection.RunAsync(request =>
                {
                    served.Add(request.StreamId);
                    return Http2Response.Text("ok");
                });
                client.SendRequests();
                client.Drain();

                client.Feed(Frame(Headers, EndHeaders, 1, [0x83, 0x86, 0x84]));   // a POST, its body still to come
                client.Feed(bad);
                client.Feed(Http2FlowControlTests.Get(3));
                List<Frame> frames = client.Drain();
                client.Close(run);

                Assert.Equal(answer, Errors(frames));
                Assert.True(served.SequenceEqual([3]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }

        // RFC 7540 5.3.1, which h2spec and nghttp2 still hold a server to.
        runner.Test("h2 control frames: HEADERS whose priority depends on their own stream are reset before any handler runs, and HPACK stays in step", () =>
        {
            using var client = new StrictClient();
            var served = new List<string>();
            Task run = client.Connection.RunAsync(request =>
            {
                served.Add($"{request.StreamId} {Fields(request)}");
                return Http2Response.Text("ok");
            });
            client.SendRequests();
            client.Drain();

            byte[] insert = Http2TrailerTests.Field("x-b", "w", index: true);   // only counts if the block was decoded
            client.Feed(Frame(Headers, EndHeaders | EndStream | PriorityFlag, 1, [.. Dependency(1), 0x82, 0x86, 0x84, .. insert]));
            client.Feed(Frame(Headers, EndHeaders | EndStream | PriorityFlag, 3, [.. Dependency(1), 0x82, 0x86, 0x84, 0xBE]));   // control: on another stream
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x1", Errors(frames));
            Assert.True(served.SequenceEqual(["3 x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
        });
    }

    // Stream 1 served, the frame, then stream 3.
    private static (List<Frame> Frames, List<int> Served) Exchange(byte[] frame)
    {
        using var client = new StrictClient();
        var served = new List<int>();
        Task run = client.Connection.RunAsync(request =>
        {
            served.Add(request.StreamId);
            return Http2Response.Text("ok");
        });
        client.SendRequests(1);
        List<Frame> frames = client.Drain();
        client.Feed(frame);
        client.Feed(Http2FlowControlTests.Get(3));
        frames.AddRange(client.Drain());
        client.Close(run);
        return (frames, served);
    }

    private static byte[] Dependency(int streamId)
    {
        byte[] priority = new byte[5];
        BinaryPrimitives.WriteInt32BigEndian(priority, streamId);
        priority[4] = 15;
        return priority;
    }

    private static byte[] Frame(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);

    internal static string Fields(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{System.Text.Encoding.ASCII.GetString(field.Key.Span)}={System.Text.Encoding.ASCII.GetString(field.Value.Span)}");
        }
        return string.Join(' ', fields);
    }

    // Every RST_STREAM and GOAWAY, in wire order: a GOAWAY by its last stream id and code.
    internal static string Errors(List<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type is RstStream or GoAway)
        .Select(f => f.Type == RstStream
            ? $"RST_STREAM {f.StreamId} 0x{BinaryPrimitives.ReadUInt32BigEndian(f.Payload):x}"
            : $"GOAWAY {BinaryPrimitives.ReadUInt32BigEndian(f.Payload)} 0x{BinaryPrimitives.ReadUInt32BigEndian(f.Payload.AsSpan(4)):x}"));
}
