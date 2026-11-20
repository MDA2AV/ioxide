using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// The bytes a field may carry (RFC 9113 8.2.1), and the pseudo-headers a request needs filled
/// (8.3.1, 8.5). A CR or LF in a value is what turns one field into two at an HTTP/1.1 hop behind the
/// handler, and a name outside visible ASCII is no token any hop agrees on; either makes the request
/// malformed, a stream error of PROTOCOL_ERROR before any handler runs.
/// </summary>
internal static class Http2FieldValidityTests
{
    // :method GET, :scheme http and :path / from the static table.
    private static readonly byte[] Get = [0x82, 0x86, 0x84];

    public static void Register(Runner runner)
    {
        foreach ((string name, byte[] malformed) in new[]
        {
            ("a field name with a space", (byte[])[.. Get, .. Raw("x a"u8, "1"u8)]),
            ("a field name with a byte past ASCII", [.. Get, .. Raw([(byte)'x', 0xE9], "1"u8)]),
            ("a field value with CR LF and a second field after it", [.. Get, .. Raw("x-a"u8, "b\r\ntransfer-encoding: chunked"u8)]),
            ("a field value with a NUL", [.. Get, .. Raw("x-a"u8, "b\0c"u8)]),
            ("a field value with a leading space", [.. Get, .. Raw("x-a"u8, " b"u8)]),
            ("a field value with a trailing tab", [.. Get, .. Raw("x-a"u8, "b\t"u8)]),
            ("a :path with LF", [0x82, 0x86, 0x04, 3, .. "/\na"u8]),
            ("an empty :method", [0x02, 0x00, 0x86, 0x84]),
            ("an empty :scheme", [0x82, 0x07, 0x00, 0x84]),
            ("a CONNECT with :scheme and :path", [0x02, 7, .. "CONNECT"u8, 0x86, 0x84, 0x01, 15, .. "example.com:443"u8]),
            ("a CONNECT without :authority", [0x02, 7, .. "CONNECT"u8]),
            ("a CONNECT with an empty :authority", [0x02, 7, .. "CONNECT"u8, 0x01, 0x00]),
            ("a :protocol, which nothing here takes", [0x02, 7, .. "CONNECT"u8, .. Raw(":protocol"u8, "websocket"u8), 0x86, 0x84, 0x01, 11, .. "example.com"u8]),
        })
        {
            string shape = name;
            byte[] block = malformed;
            runner.Test($"h2 field validity: {shape} resets the stream before the handler runs, and HPACK stays in step", () =>
            {
                List<string> served = Http2MalformedRequestTests.Serve([.. block, .. Http2TrailerTests.Field("x-b", "w", index: true)], out List<Frame> frames, withReader: true);

                Assert.Equal("RST_STREAM 1 0x1", Http2ControlFrameTests.Errors(frames));
                Assert.True(served.SequenceEqual(["3 GET / x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }

        runner.Test("h2 field validity: control: te: TRAILERS, spaces inside a value and visible punctuation in a name are served", () =>
        {
            List<string> served = Http2MalformedRequestTests.Serve(
                [.. Get, .. Raw("te"u8, "TRAILERS"u8), .. Raw("x-a"u8, "b c"u8), .. Raw("x-!#$%&'*+.^_`|~"u8, "1"u8), .. Http2TrailerTests.Field("x-b", "w", index: true)],
                out List<Frame> frames, withReader: true);

            Assert.Equal("", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual(["1 GET / te=TRAILERS x-a=b c x-!#$%&'*+.^_`|~=1 x-b=w", "3 GET / x-b=w"]),
                $"the handler was handed: {string.Join(", ", served)}");
        });
    }

    // A literal field without indexing, its name and value as raw bytes.
    private static byte[] Raw(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
        => [0x00, (byte)name.Length, .. name, (byte)value.Length, .. value];
}
