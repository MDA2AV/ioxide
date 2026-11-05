using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Text;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// nghttp2 will not send a header block past 64 KiB, and drops it with nothing on the wire: only a reset tells the peer.
/// </summary>
internal static class Nghttp2OversizedResponseTests
{
    private const byte Headers = 0x1, RstStream = 0x3;

    public static void Register(Runner runner)
    {
        runner.Test("nghttp2: a buffered response with a header block past nghttp2's limit resets its own stream, and the connection serves on", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Nghttp2Response oversized = Oversized();
            Task run = connection.RunAsync(request => request.StreamId == 1 ? oversized : Nghttp2Response.Text("ok"));

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed([.. Get(1), .. Get(3)]);
            List<Frame> frames = client.Drain();

            Assert.Equal("1 0x2", Resets(frames));
            Assert.True(!frames.Any(f => f.Type == Headers && f.StreamId == 1), "the oversized response's HEADERS went out");
            Assert.True(frames.Any(f => f.Type == Headers && f.StreamId == 3), "stream 3 was not answered");
            Assert.True(!connection.IsBroken, "one response failed the connection");
            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2: a streamed response with a header block past nghttp2's limit hears the peer gone at its flush", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Nghttp2Response oversized = Oversized();
            var outcome = new TaskCompletionSource<string>();
            Task run = connection.RunAsync(async (request, writer) =>
            {
                if (request.StreamId == 1)
                {
                    writer.WriteHeaders(oversized);
                    FlushResult flushed = await writer.FlushAsync();
                    outcome.SetResult(flushed.IsCompleted ? "peer gone" : "flushed");
                }
            });

            client.SendRequests();
            client.Drain();
            client.Feed(Get(1));
            List<Frame> frames = client.Drain();

            Assert.Equal("1 0x2", Resets(frames));
            Assert.True(outcome.Task.IsCompleted, "the flush never returned");
            Assert.Equal("peer gone", outcome.Task.Result);

            client.Feed(Get(3));
            frames = client.Drain();
            Assert.True(frames.Any(f => f.Type == Headers && f.StreamId == 3), "stream 3 was not answered");
            Assert.True(!connection.IsBroken, "one response failed the connection");
            client.Close(run);
            connection.Dispose();
        });
    }

    private static Nghttp2Response Oversized()
    {
        var response = new Nghttp2Response { Status = 200, Body = new byte[1024] };
        byte[] value = Encoding.ASCII.GetBytes(new string('v', 40 * 1024));
        response.Headers.Add("x-a"u8.ToArray(), value);
        response.Headers.Add("x-b"u8.ToArray(), value);
        return response;
    }

    // A GET with END_STREAM: :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Get(int streamId)
    {
        byte[] block = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
        return Http2FlowControlTests.FrameBytes(Headers, 0x5, streamId, block);
    }

    private static string Resets(List<Frame> frames) => string.Join(", ", frames
        .Where(f => f.Type == RstStream)
        .Select(f => $"{f.StreamId} 0x{BinaryPrimitives.ReadUInt32BigEndian(f.Payload):x}"));
}
