using System.Buffers.Binary;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// A pseudo-header out of place makes a request malformed (RFC 9113 8.1, 8.3). Stored as it came, it
/// would replace what a proxy in front of this server decided on, sending a handler to another path.
/// </summary>
internal static class Http2PseudoHeaderTests
{
    private const byte Headers = 0x1, Data = 0x0, RstStream = 0x3, GoAway = 0x7;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    public static void Register(Runner runner)
    {
        foreach ((string name, byte[] trailers) in new[] { (":path, which the request has", Path("/admin")), (":authority, which it lacks", [0x81]) })
        {
            string pseudo = name;
            byte[] block = trailers;
            runner.Test($"h2 pseudo-header: {pseudo}, in trailers resets the stream, and no handler runs", () =>
            {
                using var client = new StrictClient();
                var served = new List<string>();
                Task run = client.Connection.RunAsync(request =>
                {
                    served.Add(Ascii(request.Path));
                    return Http2Response.Text("ok");
                });
                client.SendRequests();                   // preface and SETTINGS
                client.Drain();

                client.Feed(Frame(Headers, EndHeaders, 1, Request("/public")));
                client.Feed(Frame(Data, 0, 1, new byte[10]));
                client.Feed(Frame(Headers, EndHeaders | EndStream, 1, block));
                client.Feed(Frame(Headers, EndHeaders | EndStream, 3, Request("/next")));
                List<Frame> frames = client.Drain();
                client.Close(run);

                Assert.Equal("1 0x1", Resets(frames));
                Assert.Equal(0, frames.Count(f => f.Type == GoAway));
                Assert.True(served.SequenceEqual(["/next"]), $"the handler was handed: {string.Join(", ", served)}");
            });
        }

        // Each block inserts x-b as well, which only counts if the block was decoded whole.
        byte[] insert = Http2TrailerTests.Field("x-b", "w", index: true);
        foreach ((string name, byte[] malformed) in new[]
        {
            ("a repeated :path", (byte[])[.. Request("/public"), .. Path("/admin"), .. insert]),
            ("one after a regular field", (byte[])[.. Request("/public"), .. insert, 0x81]),
            ("an unknown one", (byte[])[.. Request("/public"), .. Http2TrailerTests.Field(":x", "v"), .. insert]),
        })
        {
            string shape = name;
            byte[] block = malformed;

            foreach (bool withReader in new[] { false, true })
            {
                bool reader = withReader;
                runner.Test($"h2 pseudo-header: {shape} resets the stream before any handler{(reader ? " taking a body reader" : "")} runs, and HPACK stays in step", () =>
                {
                    using var client = new StrictClient();
                    var served = new List<string>();
                    ValueTask<Http2Response> Serve(Http2Request request)
                    {
                        served.Add($"{Ascii(request.Path)} {Fields(request)}");
                        return ValueTask.FromResult(Http2Response.Text("ok"));
                    }
                    Task run = reader
                        ? client.Connection.RunAsync((request, _) => Serve(request))
                        : client.Connection.RunAsync(Serve);
                    client.SendRequests();
                    client.Drain();

                    client.Feed(Frame(Headers, EndHeaders | EndStream, 1, block));
                    client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [.. Request("/next"), 0xBE]));
                    List<Frame> frames = client.Drain();
                    client.Close(run);

                    Assert.Equal("1 0x1", Resets(frames));
                    Assert.Equal(0, frames.Count(f => f.Type == GoAway));
                    Assert.True(served.SequenceEqual(["/next x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
                });
            }
        }
    }

    // :method POST and :scheme http from the static table, and :path.
    private static byte[] Request(string path) => [0x83, 0x86, .. Path(path)];

    // :path as a literal on its static name, without indexing.
    private static byte[] Path(string path) => [0x04, (byte)path.Length, .. Encoding.ASCII.GetBytes(path)];

    private static byte[] Frame(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);

    private static string Fields(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Ascii(field.Key)}={Ascii(field.Value)}");
        }
        return string.Join(' ', fields);
    }

    private static string Resets(List<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type == RstStream)
        .Select(f => $"{f.StreamId} 0x{BinaryPrimitives.ReadUInt32BigEndian(f.Payload):x}"));
}
