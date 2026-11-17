using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// Header blocks that RFC 7541 calls decoding errors: a dynamic table size update after a field of
/// the block (4.2), and a Huffman string whose padding is not the most significant bits of EOS, that
/// is, not all ones (5.2). Either ends the connection with COMPRESSION_ERROR, since a peer that
/// encodes like this is out of step with the decoder for every later block. Each refusal has a
/// control that differs only in the octet under test.
/// </summary>
internal static class Http2HpackDecodeTests
{
    private const byte Headers = 0x1, GoAway = 0x7;
    private const byte EndStream = 0x1, EndHeaders = 0x4;
    private const uint CompressionError = 0x9;

    // :method GET, :scheme http, :path / - static table only.
    private static readonly byte[] Get = [0x82, 0x86, 0x84];

    // A literal without indexing, new name "x-a", its value Huffman-coded as one octet: 'a' is the
    // 5-bit code 00011, so 0x1f pads it with ones, as EOS's prefix does, and 0x18 pads it with zeros.
    private static byte[] Field(byte huffmanOctet) => [0x00, 0x03, (byte)'x', (byte)'-', (byte)'a', 0x81, huffmanOctet];

    public static void Register(Runner runner)
    {
        runner.Test("h2 hpack: control: a dynamic table size update that opens the block is applied, and the request served", () =>
        {
            (string goAway, List<string> served) = Exchange([0x20, .. Get]);
            Assert.Equal("", goAway);
            Assert.True(served.SequenceEqual(["1"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 hpack: a dynamic table size update after a field of the block ends the connection with COMPRESSION_ERROR", () =>
        {
            (string goAway, List<string> served) = Exchange([Get[0], 0x20, Get[1], Get[2]]);
            Assert.True(goAway == "COMPRESSION_ERROR",
                $"a size update after :method was taken, and the server wrote [{goAway}] (RFC 7541 4.2 allows one only at the start of a block)");
            Assert.True(served.Count == 0, $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 hpack: control: a Huffman string padded with ones decodes", () =>
        {
            (string goAway, List<string> served) = Exchange([.. Get, .. Field(0x1f)]);
            Assert.Equal("", goAway);
            Assert.True(served.SequenceEqual(["1 x-a=a"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 hpack: a Huffman string padded with zeros ends the connection with COMPRESSION_ERROR", () =>
        {
            (string goAway, List<string> served) = Exchange([.. Get, .. Field(0x18)]);
            Assert.True(goAway == "COMPRESSION_ERROR",
                $"padding 000 after 'a' was taken as the end of the string, and the server wrote [{goAway}] (RFC 7541 5.2 wants the bits of EOS, all ones)");
            Assert.True(served.Count == 0, $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("http3 qpack: the Huffman decoder takes padding of ones and refuses padding of zeros", () =>
        {
            // QPACK uses HPACK's Huffman code and its padding rule (RFC 9204 4.1.2); ioxide.http3 has its own copy.
            Span<byte> output = stackalloc byte[8];
            Assert.Equal(1, ioxide.http3.Huffman.Decode([0x1f], output));
            Assert.True(output[0] == (byte)'a', $"0x1f decoded to 0x{output[0]:x2}, not 'a'");
            Assert.Equal(-1, ioxide.http3.Huffman.Decode([0x18], output));
        });
    }

    // One GET on stream 1 with the given block; what GOAWAY came back, and what was served ("stream name=value ...").
    private static (string GoAway, List<string> Served) Exchange(byte[] block)
    {
        using var client = new StrictClient();
        var served = new List<string>();
        Task run = client.Connection.RunAsync(request =>
        {
            var line = new StringBuilder(request.StreamId.ToString());
            foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
            {
                line.Append(' ').Append(Encoding.ASCII.GetString(field.Key.Span)).Append('=').Append(Encoding.ASCII.GetString(field.Value.Span));
            }
            served.Add(line.ToString());
            return Http2Response.Text("ok");
        });
        client.SendRequests();
        client.Drain();

        client.Feed(Http2FlowControlTests.FrameBytes(Headers, EndHeaders | EndStream, 1, block));
        List<Frame> frames = client.Drain();
        client.Close(run);

        string goAway = string.Join(", ", frames.Where(f => f.Type == GoAway).Select(f =>
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(f.Payload.AsSpan(4, 4)) == CompressionError
                ? "COMPRESSION_ERROR"
                : $"0x{System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(f.Payload.AsSpan(4, 4)):x}"));
        return (goAway, served);
    }
}
