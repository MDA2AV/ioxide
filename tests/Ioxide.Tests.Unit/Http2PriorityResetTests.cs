using System.Buffers.Binary;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// The stream errors a PRIORITY, or the priority fields of a HEADERS, can raise (RFC 9113 6.3, RFC 7540
/// 5.3.1), on a stream in each state it can be in: never opened, being decoded, or being served by a
/// handler that is reading its body and parked on credit for its response.
/// </summary>
internal static class Http2PriorityResetTests
{
    private const byte Headers = 0x1, Priority = 0x2, Continuation = 0x9;
    private const byte EndStream = 0x1, EndHeaders = 0x4, PriorityFlag = 0x20;

    public static void Register(Runner runner)
    {
        // RFC 9113 6.4: no RST_STREAM may name a stream that was never opened.
        foreach ((string name, int streamId) in new[] { ("an even stream", 2), ("an odd stream skipped below the highest", 3) })
        {
            string shape = name;
            int stream = streamId;
            runner.Test($"h2 priority: a PRIORITY of four octets on {shape} ends the connection rather than reset a stream never opened", () =>
            {
                using var client = new StrictClient();
                Task run = client.Connection.RunAsync(_ => Http2Response.Text("ok"));
                client.SendRequests(1, 5);
                List<Frame> frames = client.Drain();
                client.Feed(Frame(Priority, 0, stream, [0, 0, 0, 1]));
                frames.AddRange(client.Drain());
                client.Close(run);

                Assert.Equal("GOAWAY 5 0x6", Http2ControlFrameTests.Errors(frames));
            });
        }

        // Each frame lands while the handler has a read parked on the body and a flush parked on credit.
        byte[] insert = Http2TrailerTests.Field("x-b", "w", index: true);
        foreach ((string name, byte[] frame, string expected) in new[]
        {
            ("a PRIORITY of four octets", Frame(Priority, 0, 1, [0, 0, 0, 3]), "RST_STREAM 1 0x6"),
            ("trailers whose priority depends on their own stream", Frame(Headers, EndHeaders | EndStream | PriorityFlag, 1, [.. Dependency(1), .. insert]), "RST_STREAM 1 0x1"),
        })
        {
            string shape = name;
            byte[] bad = frame;
            string answer = expected;
            runner.Test($"h2 priority: {shape} on a stream being served ends its read, wakes its flush parked on credit to the peer gone, and nothing more goes out on it", () =>
            {
                using var client = new StrictClient();
                var read = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                var flushed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                var served = new List<string>();
                Task run = client.Connection.RunAsync(async (request, body, writer) =>
                {
                    served.Add($"{request.StreamId} {Http2ControlFrameTests.Fields(request)}");
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    if (request.StreamId != 1)
                    {
                        return;
                    }
                    _ = ReadAsync(body, read);
                    writer.GetSpan(70_000)[..70_000].Fill((byte)'x');   // past the peer's 65535-byte window
                    writer.Advance(70_000);
                    flushed.TrySetResult((await writer.FlushAsync()).IsCompleted ? "peer gone" : "flushed");
                });

                client.ReleaseFlush();   // server SETTINGS
                client.Feed([.. Http2FlowControlTests.Open(), .. Frame(Headers, EndHeaders, 1, [0x83, 0x86, 0x84])]);
                client.Drain();
                Assert.True(!read.Task.IsCompleted && !flushed.Task.IsCompleted, "precondition: the handler was meant to be parked on its read and its flush");

                client.Feed(bad);
                client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, .. (bad[3] == Headers ? (byte[])[0xBE] : [])]));
                List<Frame> frames = client.Drain();

                Assert.True(read.Task.Wait(2_000), "the read parked on the body never woke");
                Assert.True(read.Task.Result.StartsWith("IOException"), $"the read ended with: {read.Task.Result}");
                Assert.True(flushed.Task.Wait(2_000), "the flush parked on credit never woke");
                Assert.Equal("peer gone", flushed.Task.Result);
                Assert.Equal(answer, Http2ControlFrameTests.Errors(frames));
                Assert.Equal(0, frames.Count(f => f.StreamId == 1 && f.Type != 0x3));
                Assert.Equal(bad[3] == Headers ? "3 x-b=w" : "3 ", served[^1]);
                client.Close(run);
            });
        }

        runner.Test("h2 priority: HEADERS depending on their own stream, the block continued in CONTINUATION, are reset once it is in, and HPACK stays in step", () =>
        {
            using var client = new StrictClient();
            var served = new List<string>();
            Task run = client.Connection.RunAsync(request =>
            {
                served.Add($"{request.StreamId} {Http2ControlFrameTests.Fields(request)}");
                return Http2Response.Text("ok");
            });
            client.SendRequests();
            client.Drain();

            client.Feed(Frame(Headers, EndStream | PriorityFlag, 1, [.. Dependency(1), 0x82, 0x86]));
            client.Feed(Frame(Continuation, EndHeaders, 1, [0x84, .. Http2TrailerTests.Field("x-b", "w", index: true)]));
            client.Feed(Frame(Headers, EndHeaders | EndStream, 3, [0x82, 0x86, 0x84, 0xBE]));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x1", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual(["3 x-b=w"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        runner.Test("h2 priority: trailers depending on their own stream reset a buffered request still arriving, and it is never served", () =>
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

            client.Feed(Frame(Headers, EndHeaders, 1, [0x83, 0x86, 0x84]));
            client.Feed(Http2FlowControlTests.FrameBytes(0x0, 0, 1, new byte[4]));
            client.Feed(Frame(Headers, EndHeaders | EndStream | PriorityFlag, 1, [.. Dependency(1), .. Http2TrailerTests.Field("x-checksum", "abc")]));
            client.Feed(Http2FlowControlTests.Get(3));
            List<Frame> frames = client.Drain();
            client.Close(run);

            Assert.Equal("RST_STREAM 1 0x1", Http2ControlFrameTests.Errors(frames));
            Assert.True(served.SequenceEqual([3]), $"the handler was handed: {string.Join(", ", served)}");
        });
    }

    private static async Task ReadAsync(Http2BodyReader body, TaskCompletionSource<string> outcome)
    {
        try
        {
            var bytes = new List<byte>();
            for (ReadOnlyMemory<byte> chunk = await body.ReadAsync(); !chunk.IsEmpty; chunk = await body.ReadAsync())
            {
                bytes.AddRange(chunk.ToArray());
            }
            outcome.TrySetResult($"ended after {Encoding.ASCII.GetString([.. bytes])}");
        }
        catch (Exception e)
        {
            outcome.TrySetResult(e.GetType().Name);
        }
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
}
