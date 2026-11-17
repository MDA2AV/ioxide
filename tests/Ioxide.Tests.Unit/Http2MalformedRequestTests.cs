using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// RFC 9113 8.1.1: a malformed request is a stream error of PROTOCOL_ERROR, and the server must not
/// process it. Malformed here are a field name with uppercase letters (8.2.1), a connection-specific
/// field or a te other than "trailers" (8.2.2), and a request without :method, :scheme or a :path that
/// is not empty (8.3.1). A transfer-encoding that reached a handler, or a proxy behind it, would frame
/// the body a second way.
/// </summary>
internal static class Http2MalformedRequestTests
{
    private const byte Headers = 0x1;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    // :method GET, :scheme http and :path / from the static table.
    private static readonly byte[] Get = [0x82, 0x86, 0x84];

    public static void Register(Runner runner)
    {
        foreach ((string name, byte[] malformed) in new[]
        {
            ("a field name with uppercase letters", (byte[])[.. Get, .. Field("X-Trace", "1")]),
            ("connection", [.. Get, .. Field("connection", "keep-alive")]),
            ("keep-alive", [.. Get, .. Field("keep-alive", "timeout=5")]),
            ("proxy-connection", [.. Get, .. Field("proxy-connection", "keep-alive")]),
            ("transfer-encoding", [.. Get, .. Field("transfer-encoding", "chunked")]),
            ("upgrade", [.. Get, .. Field("upgrade", "websocket")]),
            ("a te other than trailers", [.. Get, .. Field("te", "gzip")]),
            ("no :method", [0x86, 0x84]),
            ("no :scheme", [0x82, 0x84]),
            ("no :path", [0x82, 0x86]),
            ("an empty :path", [0x82, 0x86, 0x04, 0x00]),
        })
        {
            string shape = name;
            byte[] block = malformed;
            runner.Test($"h2 malformed request: {shape} resets the stream before the handler runs, and HPACK stays in step", () =>
            {
                List<string> served = Serve([.. block, .. Insert], out List<Frame> frames, withReader: true);

                Assert.Equal("RST_STREAM 1 0x1", Http2ControlFrameTests.Errors(frames));
                Assert.True(served.SequenceEqual(["3 GET / x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }

        // The buffered dispatch decodes through the same checks; one case stands for them.
        runner.Test("h2 malformed request: transfer-encoding resets the stream before a buffered handler runs too", () =>
        {
            List<string> served = Serve([.. Get, .. Field("transfer-encoding", "chunked"), .. Insert], out List<Frame> frames, withReader: false);

            Assert.Equal("RST_STREAM 1 0x1", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual(["3 GET / x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 malformed request: control: te: trailers, lowercase fields and a CONNECT with only :authority are served", () =>
        {
            // :method CONNECT and :authority as literals on their static names; CONNECT carries no :scheme or :path (RFC 9113 8.5).
            byte[] connect = [0x02, 7, .. "CONNECT"u8, 0x01, 15, .. "example.com:443"u8];
            List<string> served = Serve([.. Get, .. Field("te", "trailers"), .. Field("x-trace", "1"), .. Insert], out List<Frame> frames, withReader: true, last: connect);

            Assert.Equal("", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual(["1 GET / te=trailers x-trace=1 x-b=w", "3 GET / x-b=w", "5 CONNECT"]),
                $"the handler was handed: {string.Join(", ", served)}");
        });
    }

    // Inserts x-b: w into the dynamic table, which stream 3 then names by index: it only resolves if the block was decoded whole.
    private static byte[] Insert => Http2TrailerTests.Field("x-b", "w", index: true);

    private static byte[] Field(string name, string value) => Http2TrailerTests.Field(name, value);

    // The block on stream 1, a GET on stream 3 naming the inserted field, then `last` on stream 5, if given.
    private static List<string> Serve(byte[] block, out List<Frame> frames, bool withReader, byte[]? last = null)
    {
        using var client = new StrictClient();
        var served = new List<string>();
        ValueTask<Http2Response> Handle(Http2Request request)
        {
            served.Add($"{request.StreamId} {Ascii(request.Method)} {Ascii(request.Path)} {Http2ControlFrameTests.Fields(request)}".TrimEnd());
            return ValueTask.FromResult(Http2Response.Text("ok"));
        }
        Task run = withReader
            ? client.Connection.RunAsync((request, _) => Handle(request))
            : client.Connection.RunAsync(Handle);
        client.SendRequests();
        client.Drain();

        client.Feed(Http2FlowControlTests.FrameBytes(Headers, EndHeaders | EndStream, 1, block));
        client.Feed(Http2FlowControlTests.FrameBytes(Headers, EndHeaders | EndStream, 3, [.. Get, 0xBE]));
        if (last is not null)
        {
            client.Feed(Http2FlowControlTests.FrameBytes(Headers, EndHeaders | EndStream, 5, last));
        }
        frames = client.Drain();
        client.Close(run);
        return served;
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);
}
