using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// What a request's header blocks decode to is bounded, not only what they arrive as: once a large
/// field is in the dynamic table, each one-byte reference to it decodes to the whole field.
/// </summary>
internal static class Nghttp2HeaderListTests
{
    private const byte Headers = 0x1, RstStream = 0x3, GoAway = 0x7;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    // :method GET, :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static readonly byte[] Get = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
    private static readonly byte[] Bomb = Enumerable.Repeat((byte)0xBE, 16_000).ToArray();   // index 62: the field below
    private static readonly Nghttp2Response Ok = Nghttp2Response.Text("ok");

    public static void Register(Runner runner)
    {
        // On main each of these streams holds 62 MB until the connection closes.
        runner.Test("nghttp2 header list: a block that decodes past the limit resets its stream, keeps nothing and leaves HPACK in step", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            var served = new List<string>();
            Task run = connection.RunAsync(request =>
            {
                served.Add(Describe(request));
                return Ok;
            });
            PutFieldInTable(client);
            served.Clear();

            long before = GC.GetTotalMemory(forceFullCollection: true);
            long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();   // parsed inline on this thread
            var frames = new List<Frame>();
            foreach (int id in new[] { 3, 5, 7 })
            {
                client.Feed(Frame(Headers, EndHeaders, id, [.. Get, .. Bomb]));   // no END_STREAM: it would stay until the close
                frames.AddRange(client.Drain());
            }
            long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            long retained = GC.GetTotalMemory(forceFullCollection: true) - before;

            Assert.Equal("3 0xb, 5 0xb, 7 0xb", Resets(frames));
            Assert.Equal(0, frames.Count(f => f.Type == GoAway));
            Assert.True(retained < 2 * 1024 * 1024, $"3 open streams of 16 KB frames retained {retained / 1024} KiB");
            Assert.True(allocated < 4 * 1024 * 1024, $"decoding them allocated {allocated / 1024} KiB, though nothing past the limit is kept");
            Assert.Equal(0, served.Count);

            // Once a request, not once for each of its 16,000 fields: every entry is a native call when the read unwinds.
            object ready = typeof(Nghttp2Connection).GetField("_readyThisPass", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(connection)!;
            int capacity = (int)ready.GetType().GetProperty("Capacity")!.GetValue(ready)!;
            Assert.True(capacity < 64, $"the ready list grew to {capacity} entries for 3 requests");

            client.Feed(Frame(Headers, EndHeaders | EndStream, 9, [.. Get, 0xBE]));   // the same entry, so the table is in step
            client.Drain();
            Assert.True(served.SequenceEqual(["9 x=4063"]), $"the next request was served as: {string.Join(", ", served)}");
            Assert.True(!connection.IsBroken, "one stream's headers failed the connection");
            client.Close(run);
            connection.Dispose();
        });

        // :method GET 42, :scheme http 43, :path / 38, :authority a.example 51, and x-a with 100 bytes 135: 309 by RFC 9113 6.5.2.
        foreach ((int limit, bool fits) in new[] { (309, true), (308, false) })
        {
            int max = limit;
            bool expected = fits;
            runner.Test($"nghttp2 header list: a request measuring 309 B against a limit of {max} is {(expected ? "served" : "reset")}", () =>
            {
                using var client = new StrictClient();
                var connection = new Nghttp2Connection(client, new Nghttp2Options { MaxHeaderListSize = max });
                int served = 0;
                Task run = connection.RunAsync(_ =>
                {
                    served++;
                    return Ok;
                });
                client.SendRequests();
                client.Drain();

                byte[] block = [.. Get, .. Http2TrailerTests.Field("x-a", new string('v', 100))];
                client.Feed(Frame(Headers, EndHeaders | EndStream, 1, block));
                List<Frame> first = client.Drain();
                client.Feed(Frame(Headers, EndHeaders | EndStream, 3, block));   // a request's count is its own
                List<Frame> second = client.Drain();
                client.Close(run);
                connection.Dispose();

                Assert.Equal(expected ? 2 : 0, served);
                Assert.Equal(expected ? "" : "1 0xb", Resets(first));
                Assert.Equal(expected ? "" : "3 0xb", Resets(second));
            });
        }

        runner.Test("nghttp2 header list: a handler taking a body reader never sees a request past the limit", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client, new Nghttp2Options { MaxHeaderListSize = 300 });
            int served = 0;
            Task run = connection.RunAsync((request, _) =>
            {
                served++;
                return new ValueTask<Nghttp2Response>(Ok);
            });
            client.SendRequests();
            client.Drain();

            client.Feed(Frame(Headers, EndHeaders, 1, [.. Get, .. Http2TrailerTests.Field("x-a", new string('v', 100))]));
            List<Frame> frames = client.Drain();
            client.Close(run);
            connection.Dispose();

            Assert.Equal("1 0xb", Resets(frames));
            Assert.Equal(0, served);
        });

        runner.Test("nghttp2 header list: a streamed response's handler never sees a request past the limit", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client, new Nghttp2Options { MaxHeaderListSize = 300 });
            int served = 0;
            Task run = connection.RunAsync((_, writer) =>
            {
                served++;
                return ValueTask.CompletedTask;
            });
            client.SendRequests();
            client.Drain();

            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, [.. Get, .. Http2TrailerTests.Field("x-a", new string('v', 100))]));
            List<Frame> frames = client.Drain();
            client.Close(run);
            connection.Dispose();

            Assert.Equal("1 0xb", Resets(frames));
            Assert.Equal(0, served);
        });

        // Trailers land in the same request, so a block that fits does not get a fresh allowance for the one after it.
        runner.Test("nghttp2 header list: trailers count with the block that opened the request", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client, new Nghttp2Options { MaxHeaderListSize = 500 });
            int served = 0;
            Task run = connection.RunAsync(_ =>
            {
                served++;
                return Ok;
            });
            client.SendRequests();
            client.Drain();

            byte[] field = Http2TrailerTests.Field("x-a", new string('v', 100));
            client.Feed(Frame(Headers, EndHeaders, 1, [.. Get, .. field]));   // 309 B
            client.Feed(Frame(Headers, EndHeaders | EndStream, 1, [.. field, .. field]));   // and 270 B more
            List<Frame> frames = client.Drain();
            client.Close(run);
            connection.Dispose();

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

    private static string Describe(Nghttp2Request request)
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
