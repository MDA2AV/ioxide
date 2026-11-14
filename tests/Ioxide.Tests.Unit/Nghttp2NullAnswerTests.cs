using System.Text;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>A buffered handler that answers null is answered as one that throws: a bare 500 on its own stream, and the connection serves on.</summary>
internal static class Nghttp2NullAnswerTests
{
    public static void Register(Runner runner)
    {
        runner.Test("nghttp2: a synchronous handler that answers null is answered 500 on its own stream, the fault reaches stderr, and the next stream in the same read is served", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            var stderr = new StringWriter();
            TextWriter original = Console.Error;
            Console.SetError(stderr);
            try
            {
                Task run = connection.RunAsync(request => request.StreamId == 1 ? null! : Nghttp2Response.Text("ok"));

                client.SendRequests();                   // preface and SETTINGS
                client.Drain();
                client.Feed([.. Get(1), .. Get(3)]);
                List<Frame> frames = client.Drain();

                Assert.True(!run.IsCompleted, "the connection ended on a null answer");
                List<Frame> stream = frames.Where(f => f.StreamId == 1).ToList();
                Assert.True(stream is [{ Type: Frame.Headers, EndStream: true }],
                    $"stream 1 was sent [{string.Join(", ", stream.Select(f => $"type {f.Type} flags 0x{f.Flags:x}"))}], not one HEADERS that ends it");
                Assert.True(stream[0].Payload is [0x8E], $"stream 1's header block was [{Convert.ToHexString(stream[0].Payload)}], not :status 500 alone");
                Assert.Equal("ok", Encoding.UTF8.GetString(Frame.Body(frames, 3)));
                Assert.True(stderr.ToString().Contains("[ioxide.nghttp2] request handler faulted"), $"stderr had: [{stderr}]");

                client.Close(run);
            }
            finally
            {
                Console.SetError(original);
                connection.Dispose();
            }
        });
    }

    // A GET with END_STREAM: :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Get(int streamId)
    {
        byte[] block = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
        return Http2FlowControlTests.FrameBytes(0x1, 0x5, streamId, block);
    }
}
