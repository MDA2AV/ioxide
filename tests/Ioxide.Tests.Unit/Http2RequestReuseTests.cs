using System.Collections;
using System.Reflection;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// A connection hands a retired request, with its header list and field ranges, to the next stream.
/// </summary>
internal static class Http2RequestReuseTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 request: the next stream's request holds nothing of the one before", () =>
        {
            using var client = new StrictClient();

            var seen = new List<(Http2Request Request, string Fields)>();
            Task run = client.Connection.RunAsync(request =>
            {
                seen.Add((request, Describe(request)));
                return Http2Response.Text("ok");
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests();                       // preface and SETTINGS
            client.ReleaseFlush();                       // their ack
            client.Feed(Request(1, post: true, "/first", "a.example", [("x-one", "1"), ("x-two", "2")], body: "hello"));
            client.ReleaseFlush();
            // Split over HEADERS and CONTINUATION, so a header-block flag left set by the request before would show.
            client.Feed(Request(3, post: false, "/", authority: null, [], body: null, https: true, split: true));
            client.ReleaseFlush();
            client.Feed(Request(5, post: true, "/again", "c.example", [], body: "world", split: true));
            client.ReleaseFlush();
            client.Close(run);

            Assert.Equal(3, seen.Count);
            Assert.Equal("1 POST http /first a.example [x-one=1 x-two=2] hello", seen[0].Fields);
            Assert.Equal("3 GET https / - [] -", seen[1].Fields);
            Assert.Equal("5 POST http /again c.example [] world", seen[2].Fields);
            Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request) && ReferenceEquals(seen[1].Request, seen[2].Request),
                "each stream reuses the request of the one before");
        });

        runner.Test("h2 request: a parked handler's request goes back once it answers", () =>
        {
            using var client = new StrictClient();

            var parked = new TaskCompletionSource<Http2Response>();
            var seen = new List<(Http2Request Request, string Fields)>();
            Task run = client.Connection.RunAsync(request =>
            {
                seen.Add((request, Describe(request)));
                return request.StreamId == 1
                    ? new ValueTask<Http2Response>(parked.Task)   // answered later, through CompleteBufferedAsync
                    : new ValueTask<Http2Response>(Http2Response.Text("ok"));
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed(Request(1, post: false, "/park", "a.example", [("x-one", "1")], body: null));
            client.Drain();
            parked.SetResult(Http2Response.Text("late"));
            client.Drain();
            Http2Request retired = seen[0].Request;      // in the pool now, which must not pin the arena it read from
            Assert.True(retired.Method.IsEmpty && retired.Path.IsEmpty && retired.Headers.AsSpan().IsEmpty,
                "a retired request still points into the arena that went back");
            client.Feed(Request(3, post: false, "/", authority: null, [], body: null));
            client.Drain();
            client.Close(run);

            Assert.Equal("3 GET http / - [] -", seen[1].Fields);
            Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request), "the parked handler's request was reused");
        });

        runner.Test("h2 request: a request reset before it ends comes back for the next stream holding nothing", () =>
        {
            using var client = new StrictClient();

            var seen = new List<string>();
            Task run = client.Connection.RunAsync(request =>
            {
                seen.Add(Describe(request));
                return Http2Response.Text("ok");
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            // Its headers and part of its body, then the reset: never dispatched, so the parser takes it back.
            client.Feed([.. Request(1, post: true, "/first", "a.example", [("x-one", "1")], body: "hel", endStream: false),
                .. Http2FlowControlTests.RstStream(1, 8)]);
            client.Drain();
            int pooled = Pooled(client.Connection);
            client.Feed(Request(3, post: false, "/", authority: null, [], body: null));
            client.Drain();
            client.Close(run);

            Assert.Equal(1, pooled);
            Assert.True(seen.SequenceEqual(["3 GET http / - [] -"]), $"the handler was handed: {string.Join(", ", seen)}");
        });

        runner.Test("h2 request: a handler that disposes the connection leaves a parked handler's request alone", () =>
        {
            using var client = new StrictClient();

            var parked = new TaskCompletionSource<Http2Response>();
            Http2Request? held = null;
            Task run = client.Connection.RunAsync(request =>
            {
                if (request.StreamId == 1)
                {
                    held = request;
                    return new ValueTask<Http2Response>(parked.Task);
                }
                client.Connection.Dispose();             // in the same dispatch as stream 1
                return new ValueTask<Http2Response>(Http2Response.Text("ok"));
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1, 3);
            string path = Ascii(held!.Path);
            parked.SetResult(Http2Response.Text("late"));
            client.Close(run);

            Assert.Equal("/", path);
        });

        runner.Test("h2 request: a burst leaves at most 32 requests on the connection", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => Http2Response.Text("ok"));

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed(Batch(1, 40));                   // one read, so all 40 are open before the first retires
            client.Drain();
            int pooled = Pooled(client.Connection);
            client.Close(run);

            Assert.Equal(32, pooled);
        });

        foreach ((int lines, int kept) in new[] { (64, 1), (65, 0) })
        {
            int count = lines, expected = kept;
            runner.Test($"h2 request: a request with {count} header lines {(expected == 1 ? "is" : "is not")} kept for the next stream", () =>
            {
                using var client = new StrictClient();
                Task run = client.Connection.RunAsync(_ => Http2Response.Text("ok"));

                client.ReleaseFlush();                   // server SETTINGS
                client.SendRequests();                   // preface and SETTINGS
                client.Drain();
                client.Feed(Request(1, post: false, "/", authority: null,
                    Enumerable.Range(0, count).Select(i => ($"x-{i}", "1")).ToArray(), body: null));
                client.Drain();
                int pooled = Pooled(client.Connection);
                client.Close(run);

                Assert.Equal(expected, pooled);
            });
        }

        runner.Test("h2 request: a warm connection's request allocates none of the parser's objects", () =>
        {
            using var client = new StrictClient();

            Http2Response response = Http2Response.Text("ok");   // shared, so the handler allocates nothing
            int served = 0;
            Task run = client.Connection.RunAsync(_ =>
            {
                served++;
                return response;
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests();                       // preface and SETTINGS
            client.ReleaseFlush();                       // their ack

            // Two warm-up passes grow the ready queue and the pool.
            const int perPass = 16;
            client.Feed(Batch(1, perPass));
            client.ReleaseFlush();
            client.Feed(Batch(1 + (2 * perPass), perPass));
            client.ReleaseFlush();

            byte[] batch = Batch(1 + (4 * perPass), perPass);
            int servedBefore = served;
            long before = GC.GetAllocatedBytesForCurrentThread();
            client.Feed(batch);                          // parsed, dispatched and answered inline
            long perRequest = (GC.GetAllocatedBytesForCurrentThread() - before) / perPass;
            Assert.Equal(perPass, served - servedBefore);   // all of them inside the window

            client.ReleaseFlush();
            client.Close(run);

            // What is left is the test transport's own flush, shared by the pass: about 65 B.
            Assert.True(perRequest < 100, $"a request on a warm connection allocated {perRequest} B");
        });
    }

    private static int Pooled(Http2Connection connection)
        => ((ICollection)typeof(Http2Connection)
            .GetField("_pendingPool", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(connection)!).Count;

    private static string Describe(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Ascii(field.Key)}={Ascii(field.Value)}");
        }

        return $"{request.StreamId} {Ascii(request.Method)} {Ascii(request.Scheme)} {Ascii(request.Path)} {Or(request.Authority)} "
             + $"[{string.Join(' ', fields)}] {Or(request.Body)}";

        static string Or(ReadOnlyMemory<byte> bytes) => bytes.IsEmpty ? "-" : Ascii(bytes);
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);

    // Each a GET for / with one header of its own, in one HEADERS frame with END_STREAM.
    private static byte[] Batch(int firstStream, int count)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < count; i++)
        {
            bytes.AddRange(Request(firstStream + (2 * i), post: false, "/", authority: null, [("x-n", $"{i}")], body: null));
        }
        return bytes.ToArray();
    }

    // HEADERS, with END_STREAM unless a DATA frame carrying the body follows; split, a CONTINUATION ends the block.
    // HPACK from the static table and literals without indexing only, so the request needs no encoder of its own.
    private static byte[] Request(int streamId, bool post, string path, string? authority,
        (string Name, string Value)[] fields, string? body, bool https = false, bool split = false, bool endStream = true)
    {
        var block = new List<byte> { post ? (byte)0x83 : (byte)0x82, https ? (byte)0x87 : (byte)0x86 };   // :method, :scheme
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

        byte end = body is null && endStream ? (byte)0x1 : (byte)0x0;
        var frames = new List<byte>();
        if (split)
        {
            int half = block.Count / 2;
            frames.AddRange(FrameHeader(half, 0x1, end, streamId));                  // no END_HEADERS
            frames.AddRange(block.Take(half));
            frames.AddRange(FrameHeader(block.Count - half, 0x9, 0x4, streamId));    // CONTINUATION, END_HEADERS
            frames.AddRange(block.Skip(half));
        }
        else
        {
            frames.AddRange(FrameHeader(block.Count, 0x1, (byte)(end | 0x4), streamId));
            frames.AddRange(block);
        }
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
