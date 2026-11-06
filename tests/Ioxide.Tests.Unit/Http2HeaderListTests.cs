using System.Buffers.Binary;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// What a request's header blocks decode to is bounded, not only what they arrive as: once a large
/// field is in the dynamic table, each one-byte reference to it decodes to the whole field.
/// </summary>
internal static class Http2HeaderListTests
{
    private const byte Headers = 0x1, RstStream = 0x3, GoAway = 0x7, Continuation = 0x9;
    private const byte EndStream = 0x1, EndHeaders = 0x4;
    private const uint EnhanceYourCalm = 0xb;

    private static readonly byte[] Get = [0x82, 0x86, 0x84];                     // :method GET, :scheme http, :path /
    private static readonly byte[] Bomb = Enumerable.Repeat((byte)0xBE, 16_000).ToArray();   // index 62: the field below

    public static void Register(Runner runner)
    {
        // On main each of these streams holds 342 MB.
        runner.Test("h2 header list: a block that decodes past the limit resets its stream, keeps nothing and leaves HPACK in step", () =>
        {
            using var client = new StrictClient();
            var served = new List<string>();
            Task run = client.Connection.RunAsync(request =>
            {
                served.Add(Describe(request));
                return Http2Response.Text("ok");
            });
            PutFieldInTable(client);
            served.Clear();

            long before = GC.GetTotalMemory(forceFullCollection: true);
            long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();   // parsed inline on this thread
            var frames = new List<Frame>();
            foreach (int id in new[] { 3, 5, 7 })
            {
                client.Feed(Frame(Headers, 0, id, [.. Get, .. Bomb]));   // the block's first frame, and three more
                client.Feed(Frame(Continuation, 0, id, Bomb));
                client.Feed(Frame(Continuation, 0, id, Bomb));
                client.Feed(Frame(Continuation, EndHeaders, id, Bomb));
                frames.AddRange(client.Drain());
            }
            long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            long retained = GC.GetTotalMemory(forceFullCollection: true) - before;

            Assert.Equal("3 0xb, 5 0xb, 7 0xb", Resets(frames));
            Assert.Equal(0, frames.Count(f => f.Type == GoAway));
            Assert.True(retained < 2 * 1024 * 1024, $"3 open streams of 64 KiB blocks retained {retained / 1024} KiB");
            Assert.True(allocated < 4 * 1024 * 1024, $"decoding them allocated {allocated / 1024} KiB, though nothing past the limit is kept");
            Assert.Equal(0, served.Count);

            client.Feed(Frame(Headers, EndHeaders | EndStream, 9, [.. Get, 0xBE]));   // the same entry, so the table is in step
            client.Drain();
            Assert.True(served.SequenceEqual(["9 x=4063"]), $"the next request was served as: {string.Join(", ", served)}");
            client.Close(run);
        });

        runner.Test("h2 header list: a stream that repeats HEADERS is reset at the first past the limit", () =>
        {
            using var client = new StrictClient();
            int served = 0;
            Task run = client.Connection.RunAsync(_ =>
            {
                served++;
                return Http2Response.Text("ok");
            });
            PutFieldInTable(client);

            client.Feed(Frame(Headers, EndHeaders, 3, Get));
            long before = GC.GetTotalMemory(forceFullCollection: true);
            var frames = new List<Frame>();
            for (int i = 0; i < 8; i++)
            {
                client.Feed(Frame(Headers, EndHeaders, 3, Bomb));
                frames.AddRange(client.Drain());
            }
            long retained = GC.GetTotalMemory(forceFullCollection: true) - before;

            Assert.Equal(1, frames.Count(f => f.Type == RstStream && f.StreamId == 3));
            Assert.Equal(0, frames.Count(f => f.Type == GoAway));
            Assert.True(retained < 2 * 1024 * 1024, $"8 HEADERS frames on one stream retained {retained / 1024} KiB");
            Assert.Equal(1, served);                     // the request that filled the table
            client.Close(run);
        });

        // :method GET 42, :scheme http 43, :path / 38, and x-a with 100 bytes 135: RFC 9113 6.5.2's measure comes to 258.
        foreach ((int limit, bool fits) in new[] { (258, true), (257, false) })
        {
            int max = limit;
            bool expected = fits;
            runner.Test($"h2 header list: a request measuring 258 B against a limit of {max} is {(expected ? "served" : "reset")}", () =>
            {
                using var client = new StrictClient(new Http2Options { MaxHeaderListSize = max });
                int served = 0;
                Task run = client.Connection.RunAsync(_ =>
                {
                    served++;
                    return Http2Response.Text("ok");
                });
                client.SendRequests();
                client.Drain();

                byte[] block = [.. Get, .. Http2TrailerTests.Field("x-a", new string('v', 100))];
                client.Feed(Frame(Headers, EndHeaders | EndStream, 1, block));
                List<Frame> first = client.Drain();
                client.Feed(Frame(Headers, EndHeaders | EndStream, 3, block));   // a request's count is its own
                List<Frame> second = client.Drain();
                client.Close(run);

                Assert.Equal(expected ? 2 : 0, served);
                Assert.Equal(expected ? "" : "1 0xb", Resets(first));
                Assert.Equal(expected ? "" : "3 0xb", Resets(second));
            });
        }

        runner.Test("h2 header list: a handler taking a body reader never sees a request past the limit", () =>
        {
            using var client = new StrictClient();
            var served = new List<int>();
            Task run = client.Connection.RunAsync((request, _) =>
            {
                served.Add(request.StreamId);
                return ValueTask.FromResult(Http2Response.Text("ok"));
            });
            PutFieldInTable(client);
            served.Clear();

            client.Feed(Frame(Headers, EndHeaders, 3, [.. Get, .. Bomb]));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("3 0xb", Resets(frames));
            Assert.Equal(0, served.Count);
        });

        // Trailers land in the same request, so a block that fits does not get a fresh allowance for the one after it.
        runner.Test("h2 header list: trailers count with the block that opened the request", () =>
        {
            using var client = new StrictClient(new Http2Options { MaxHeaderListSize = 400 });
            int served = 0;
            Task run = client.Connection.RunAsync(_ =>
            {
                served++;
                return Http2Response.Text("ok");
            });
            client.SendRequests();
            client.Drain();

            byte[] field = Http2TrailerTests.Field("x-a", new string('v', 100));
            client.Feed(Frame(Headers, EndHeaders, 1, [.. Get, .. field]));   // 258 B
            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, [.. field, .. field]));   // and 270 B more
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("1 0xb", Resets(frames));
            Assert.Equal(0, served);
        });
    }

    // Stream 1 inserts x with 4,063 bytes at dynamic index 62.
    private static void PutFieldInTable(StrictClient client)
    {
        client.SendRequests();                           // preface and SETTINGS
        client.Drain();
        client.Feed(Frame(Headers, EndHeaders | EndStream, 1, [.. Get, .. Http2TrailerTests.Field("x", new string('v', 4063), index: true)]));
        client.Drain();
    }

    private static byte[] Frame(byte type, int flags, int streamId, ReadOnlySpan<byte> payload)
        => Http2FlowControlTests.FrameBytes(type, (byte)flags, streamId, payload);

    private static string Describe(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Encoding.ASCII.GetString(field.Key.Span)}={field.Value.Length}");
        }
        return $"{request.StreamId} {string.Join(' ', fields)}";
    }

    private static string Resets(List<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type == RstStream)
        .Select(f => $"{f.StreamId} 0x{BinaryPrimitives.ReadUInt32BigEndian(f.Payload):x}"));
}
