using System.Collections;
using System.Reflection;
using System.Text;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// ioxide.nghttp2 hands a retired request whose body arrived whole to the next stream on the connection.
/// </summary>
internal static class Nghttp2RequestReuseTests
{
    private static readonly Nghttp2Response Ok = Nghttp2Response.Text("ok");   // shared, so handlers allocate nothing

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
                return Ok;
            });

            Open(client);
            client.Feed(Request(1, post: true, "/first", "a.example", [("x-one", "1"), ("x-two", "2")], body: "hello"));
            client.Drain();
            // nghttp2 wants an authority or a host; a host alone leaves :authority unset, so a stale one would show.
            client.Feed(Request(3, post: false, "/", authority: null, [("host", "b.example")], body: null));
            client.Drain();
            Close(client, connection, run);

            Assert.Equal(2, seen.Count);
            Assert.Equal("1 POST /first a.example [x-one=1 x-two=2] hello", seen[0].Fields);
            Assert.Equal("3 GET / - [host=b.example] -", seen[1].Fields);
            Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request), "the second stream reuses the first one's request");
        });

        runner.Test("nghttp2 request: a parked handler's request goes back once it answers, holding nothing", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var parked = new TaskCompletionSource<Nghttp2Response>();
            var seen = new Dictionary<int, (Nghttp2Request Request, string Fields)>();
            Task run = connection.RunAsync(request =>
            {
                seen[request.StreamId] = (request, Describe(request));
                return request.Path.Span.SequenceEqual("/park"u8)
                    ? new ValueTask<Nghttp2Response>(parked.Task)   // answered later, through CompleteAsync
                    : new ValueTask<Nghttp2Response>(Ok);
            });

            Open(client);
            client.Feed(Request(1, post: true, "/park", "a.example", [("x-one", "1")], body: "hello"));
            client.Drain();
            client.Feed(Request(3, post: false, "/quick", "a.example", [], body: null));
            client.Drain();
            parked.SetResult(Ok);                        // stream 1 answers now, and its request is the last to go back
            client.Drain();
            client.Feed(Request(5, post: false, "/", authority: null, [("host", "c.example")], body: null));
            client.Drain();
            Close(client, connection, run);

            Assert.Equal("5 GET / - [host=c.example] -", seen[5].Fields);
            Assert.True(ReferenceEquals(seen[1].Request, seen[5].Request), "the parked handler's request was reused");
        });

        runner.Test("nghttp2 request: a streamed response's request goes back once its handler is done", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var seen = new List<(Nghttp2Request Request, string Fields)>();
            Task run = connection.RunAsync((request, writer) =>
            {
                seen.Add((request, Describe(request)));
                return ValueTask.CompletedTask;            // the connection sends a 200 with no body
            });

            Open(client);
            client.Feed(Request(1, post: false, "/first", "a.example", [("x-one", "1")], body: null));
            client.Drain();
            client.Feed(Request(3, post: false, "/", authority: null, [("host", "b.example")], body: null));
            client.Drain();
            Close(client, connection, run);

            Assert.Equal("3 GET / - [host=b.example] -", seen[1].Fields);
            Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request), "the second stream reuses the first one's request");
        });

        runner.Test("nghttp2 request: a request a peer sent 65 header lines is not kept for the next stream", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var seen = new List<Nghttp2Request>();
            Task run = connection.RunAsync(request =>
            {
                seen.Add(request);
                return Ok;
            });

            Open(client);
            (string, string)[] many = [.. Enumerable.Range(0, 65).Select(i => ($"x-{i}", "v"))];
            client.Feed(Request(1, post: false, "/", "a.example", many, body: null));
            client.Drain();
            client.Feed(Request(3, post: false, "/", "a.example", [], body: null));
            client.Drain();
            client.Feed(Request(5, post: false, "/", "a.example", [], body: null));
            client.Drain();
            Close(client, connection, run);

            Assert.Equal(3, seen.Count);
            Assert.True(!ReferenceEquals(seen[0], seen[1]), "a request whose field list grew past 64 entries was kept");
            Assert.True(ReferenceEquals(seen[1], seen[2]), "control: a small request is kept");
        });

        runner.Test("nghttp2 request: a connection keeps at most 32 requests for later streams", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var parked = new List<TaskCompletionSource<Nghttp2Response>>();   // one each: a shared one resumes off-thread
            Task run = connection.RunAsync(_ =>
            {
                var answer = new TaskCompletionSource<Nghttp2Response>();
                parked.Add(answer);
                return new ValueTask<Nghttp2Response>(answer.Task);
            });

            Open(client);
            client.Feed(Batch(1, 40));
            client.Drain();
            foreach (TaskCompletionSource<Nghttp2Response> answer in parked)
            {
                answer.SetResult(Ok);                    // each retires inline, on this thread
            }
            client.Drain();
            int pooled = ((ICollection)typeof(Nghttp2Connection)
                .GetField("_pendingPool", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(connection)!).Count;
            Close(client, connection, run);

            Assert.Equal(40, parked.Count);
            Assert.Equal(32, pooled);
        });

        // A body reader's request stays in _pending until its stream ends; handed on, the next stream's headers land on it.
        runner.Test("nghttp2 request: a request whose body is still arriving is not handed to the next stream", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var seen = new List<(Nghttp2Request Request, string Fields)>();
            Task run = connection.RunAsync((request, body) =>
            {
                seen.Add((request, Describe(request)));
                return new ValueTask<Nghttp2Response>(Ok);   // done before its body ends
            });

            Open(client);
            client.Feed(Request(1, post: true, "/upload", "a.example", [("x-one", "1")], body: null, endStream: false));
            client.Drain();
            client.Feed(Request(3, post: false, "/", "b.example", [], body: null));
            client.Drain();
            client.Feed([.. FrameHeader(5, 0x0, 0x1, 1), .. "hello"u8.ToArray()]);   // stream 1's body, and its end
            client.Drain();
            Close(client, connection, run);

            Assert.Equal(2, seen.Count);
            Assert.Equal("3 GET / b.example [] -", seen[1].Fields);
            Assert.True(!ReferenceEquals(seen[0].Request, seen[1].Request), "a request still in _pending was handed on");
        });

        runner.Test("nghttp2 request: a warm connection's request allocates none of the parser's objects", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            int served = 0;
            Task run = connection.RunAsync(_ =>
            {
                served++;
                return Ok;
            });

            Open(client);

            // Two warm-up passes: the ready lists swap each pass, so each grows in a pass of its own.
            const int perPass = 16;
            client.Feed(Batch(1, perPass));
            client.Drain();
            client.Feed(Batch(1 + (2 * perPass), perPass));
            client.Drain();

            byte[] batch = Batch(1 + (4 * perPass), perPass);
            int servedBefore = served;
            long before = GC.GetAllocatedBytesForCurrentThread();
            client.Feed(batch);                          // parsed, dispatched and answered inline
            long perRequest = (GC.GetAllocatedBytesForCurrentThread() - before) / perPass;
            Assert.Equal(perPass, served - servedBefore);   // all of them inside the window

            client.Drain();
            Close(client, connection, run);

            // What is left is the test transport's own flush, shared by the pass.
            Assert.True(perRequest < 200, $"a request on a warm connection allocated {perRequest} B");
        });
    }

    private static void Open(StrictClient client)
    {
        client.SendRequests();                           // preface and SETTINGS
        client.Drain();
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

    // HEADERS, then a DATA frame with the body if there is one; the last frame carries END_STREAM unless told not
    // to. HPACK from the static table and literals without indexing only, so the request needs no encoder of its own.
    private static byte[] Request(int streamId, bool post, string path, string? authority,
        (string Name, string Value)[] fields, string? body, bool endStream = true)
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
        if (authority is not null)
        {
            block.Add(0x01);                                                    // :authority, literal value
            AddString(block, authority);
        }
        foreach ((string name, string value) in fields)
        {
            block.Add(0x00);                                                    // literal name and value
            AddString(block, name);
            AddString(block, value);
        }

        bool headersEnd = endStream && body is null;
        var frames = new List<byte>();
        frames.AddRange(FrameHeader(block.Count, 0x1, headersEnd ? (byte)0x5 : (byte)0x4, streamId));
        frames.AddRange(block);
        if (body is not null)
        {
            frames.AddRange(FrameHeader(body.Length, 0x0, endStream ? (byte)0x1 : (byte)0x0, streamId));
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
