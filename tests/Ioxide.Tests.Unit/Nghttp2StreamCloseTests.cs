using System.Collections;
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
