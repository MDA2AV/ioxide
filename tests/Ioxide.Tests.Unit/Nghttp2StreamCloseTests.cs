using System.Collections;
using System.IO.Pipelines;
using System.Reflection;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>A request its peer resets before it ends leaves the connection, whatever code the reset carries.</summary>
internal static class Nghttp2StreamCloseTests
{
    public static void Register(Runner runner)
    {
        foreach ((uint code, string name) in new[] { (0u, "NO_ERROR"), (8u, "CANCEL") })
        {
            uint error = code;
            runner.Test($"nghttp2: a request its peer resets with {name} before it ends is released", () =>
            {
                using var client = new StrictClient();
                var connection = new Nghttp2Connection(client);

                int served = 0;
                Task run = connection.RunAsync(_ =>
                {
                    served++;
                    return Nghttp2Response.Text("ok");
                });

                client.SendRequests();                   // preface and SETTINGS
                client.Drain();

                // A POST's headers without END_STREAM, so its body is still owed, and then the reset.
                client.Feed([.. Headers(1, post: true, endStream: false), .. Http2FlowControlTests.RstStream(1, error)]);
                client.Drain();
                Assert.Equal(0, Pending(connection));
                Assert.Equal(0, served);

                client.Feed(Headers(3, post: false, endStream: true));   // and the connection serves on
                client.Drain();
                Assert.Equal(1, served);

                client.Close(run);
                connection.Dispose();
            });
        }

        // Its handler is dispatched and parked, with no headers out, so nothing it could send would ever call back.
        foreach (int staged in new[] { 128 * 1024, 0 })
        {
            int bytes = staged;
            runner.Test($"nghttp2: a streamed response its peer resets with NO_ERROR hears the peer gone at a flush of {bytes} B", () =>
            {
                using var client = new StrictClient();
                var connection = new Nghttp2Connection(client);

                var go = new TaskCompletionSource();
                var outcome = new TaskCompletionSource<string>();
                Task run = connection.RunAsync(async (_, writer) =>
                {
                    await go.Task;
                    if (bytes > 0)                       // past the 64 KiB a flush may run ahead of nghttp2
                    {
                        writer.GetSpan(bytes)[..bytes].Fill((byte)'x');
                        writer.Advance(bytes);
                    }
                    FlushResult flushed = await writer.FlushAsync();
                    outcome.SetResult(flushed.IsCompleted ? "peer gone" : "flushed");
                });

                client.SendRequests();                   // preface and SETTINGS
                client.Drain();
                client.Feed(Headers(1, post: false, endStream: true));
                client.Drain();
                client.Feed(Http2FlowControlTests.RstStream(1, 0));
                client.Drain();
                go.SetResult();
                client.Drain();

                Assert.True(outcome.Task.IsCompleted, "the flush of a stream its peer reset never returned");
                Assert.Equal("peer gone", outcome.Task.Result);
                client.Close(run);
                connection.Dispose();
            });
        }
    }

    // :method, :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Headers(int streamId, bool post, bool endStream)
    {
        byte[] block = [post ? (byte)0x83 : (byte)0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
        return Http2FlowControlTests.FrameBytes(0x1, endStream ? (byte)0x5 : (byte)0x4, streamId, block);
    }

    // The requests still being assembled. Nothing outside the connection can see them, so a leak shows nowhere else.
    private static int Pending(Nghttp2Connection connection)
        => ((IDictionary)typeof(Nghttp2Connection)
            .GetField("_pending", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(connection)!).Count;
}
