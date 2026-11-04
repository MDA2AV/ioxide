using System.Text;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// ioxide.nghttp2 keeps a retired request whose body arrived whole, with its header list and field ranges, for
/// the next stream: the next request must come back holding nothing of the one before, and a warm connection's
/// request allocates none of the parser's objects. Driven over the strict test transport, like the managed stack.
/// </summary>
internal static class Nghttp2RequestReuseTests
{
    public static void Register(Runner runner)
    {
        runner.Test("nghttp2 request: the next stream's request holds nothing of the one before", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var seen = new List<(Nghttp2Request Request, string Fields)>();
            Task run = connection.RunAsync(request =>
            {
                seen.Add((request, Describe(request)));
                return Nghttp2Response.Text("ok");
            });

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed(Request(1, post: true, "/first", "a.example", [("x-one", "1"), ("x-two", "2")], body: "hello"));
            client.Drain();
            client.Feed(Request(3, post: false, "/", "b.example", [], body: null));   // nghttp2 refuses a request with no authority
            client.Drain();
            Close(client, connection, run);

            Assert.Equal(2, seen.Count);
            Assert.Equal("1 POST /first a.example [x-one=1 x-two=2] hello", seen[0].Fields);
            Assert.Equal("3 GET / b.example [] -", seen[1].Fields);
            Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request), "the second stream reuses the first one's request");
        });

        runner.Test("nghttp2 request: a warm connection's request allocates none of the parser's objects", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            Nghttp2Response response = Nghttp2Response.Text("ok");   // shared, so the handler allocates nothing
            Task run = connection.RunAsync(_ => response);

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();

            const int perPass = 16;
            client.Feed(Batch(1, perPass));              // warm-up: the requests the next batch reuses
            client.Drain();

            byte[] batch = Batch(1 + (2 * perPass), perPass);
            long before = GC.GetAllocatedBytesForCurrentThread();
            client.Feed(batch);                          // parsed, dispatched and answered inline
            long perRequest = (GC.GetAllocatedBytesForCurrentThread() - before) / perPass;

            client.Drain();
            Close(client, connection, run);

            // Before reuse, every request allocated about 650 B of parser objects. What is left is the test
            // transport's own flush, shared by the pass.
            Assert.True(perRequest < 200, $"a request on a warm connection allocated {perRequest} B");
        });
    }

    private static void Close(StrictClient client, Nghttp2Connection connection, Task run)
    {
        client.Close(run);
        connection.Dispose();
    }

    private static string Describe(Nghttp2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Ascii(field.Key)}={Ascii(field.Value)}");
        }

        return $"{request.StreamId} {Ascii(request.Method)} {Ascii(request.Path)} {Or(request.Authority)} "
             + $"[{string.Join(' ', fields)}] {Or(request.Body)}";

        static string Or(ReadOnlyMemory<byte> bytes) => bytes.IsEmpty ? "-" : Ascii(bytes);
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);

    // Each a GET for / with an authority and one header of its own, in one HEADERS frame with END_STREAM.
    private static byte[] Batch(int firstStream, int count)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < count; i++)
        {
            bytes.AddRange(Request(firstStream + (2 * i), post: false, "/", "localhost", [("x-n", $"{i}")], body: null));
        }
        return bytes.ToArray();
    }

    // HEADERS, with END_STREAM unless a DATA frame carrying the body follows. HPACK from the static table and
    // literals without indexing only, so the request needs no encoder of its own.
    private static byte[] Request(int streamId, bool post, string path, string authority,
        (string Name, string Value)[] fields, string? body)
    {
        var block = new List<byte> { post ? (byte)0x83 : (byte)0x82, 0x86 };   // :method, :scheme http
        if (path == "/")
        {
            block.Add(0x84);                                                    // :path /
        }
        else
        {
            block.Add(0x04);                                                    // :path, literal value
            AddString(block, path);
        }
        block.Add(0x01);                                                        // :authority, literal value
        AddString(block, authority);
        foreach ((string name, string value) in fields)
        {
            block.Add(0x00);                                                    // literal name and value
            AddString(block, name);
            AddString(block, value);
        }

        var frames = new List<byte>();
        frames.AddRange(FrameHeader(block.Count, 0x1, body is null ? (byte)0x5 : (byte)0x4, streamId));
        frames.AddRange(block);
        if (body is not null)
        {
            frames.AddRange(FrameHeader(body.Length, 0x0, 0x1, streamId));
            frames.AddRange(Encoding.ASCII.GetBytes(body));
        }
        return frames.ToArray();
    }

    private static void AddString(List<byte> block, string value)
    {
        block.Add((byte)value.Length);   // no Huffman; every value here is under 127 bytes
        block.AddRange(Encoding.ASCII.GetBytes(value));
    }

    private static byte[] FrameHeader(int length, byte type, byte flags, int streamId) =>
    [
        (byte)(length >> 16), (byte)(length >> 8), (byte)length,
        type, flags,
        (byte)(streamId >> 24), (byte)(streamId >> 16), (byte)(streamId >> 8), (byte)streamId,
    ];
}
