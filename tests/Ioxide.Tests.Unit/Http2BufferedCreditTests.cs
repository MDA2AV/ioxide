using System.Runtime.CompilerServices;
using ioxide.http2;
using static Ioxide.Tests.Http2FlowControlTests;

namespace Ioxide.Tests;

/// <summary>
/// A buffered response the peer's windows cannot take whole: what it waits on, what it holds while
/// it waits, and when it lets go. Http2FlowControlTests has the stream-window case itself.
/// </summary>
internal static class Http2BufferedCreditTests
{
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_writerPool")]
    private static extern ref Stack<Http2ResponseWriter> WriterPool(Http2Connection connection);

    public static void Register(Runner runner)
    {
        runner.Test("h2 flow: a buffered response past the connection window waits for a WINDOW_UPDATE instead of being reset", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200, Body = new byte[100 * 1024] });

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 1 << 20)), .. Get(1)]);    // the connection window stays at 65535
            List<Frame> frames = client.Drain();

            Assert.Equal(65535, Frame.Body(frames, 1).Length);
            Assert.True(!frames.Any(f => f.Type == RstStreamFrame),
                "the response was reset when the connection window ran out, instead of waiting for credit");

            client.Feed(WindowUpdate(0, 1 << 20));
            frames.AddRange(client.Drain());
            Assert.Equal(100 * 1024, Frame.Body(frames, 1).Length);
            Assert.True(frames.Last(f => f.StreamId == 1).EndStream, "the response never ended");

            client.Close(run);
        });

        runner.Test("h2 flow: stream credit sent after a request, before its answer, still counts", () =>
        {
            // The request leaves _streams once it is whole, so a WINDOW_UPDATE right behind it found no window.
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200, Body = new byte[100 * 1024] });

            client.ReleaseFlush();
            client.Feed([.. Open(), .. Get(1), .. WindowUpdate(1, 1 << 20), .. WindowUpdate(0, 1 << 20)]);

            int sent = Frame.Body(client.Drain(), 1).Length;
            Assert.True(sent == 100 * 1024,
                $"{sent} of {100 * 1024} bytes: the stream's WINDOW_UPDATE was dropped, and the rest waits on credit the peer already gave");

            client.Close(run);
        });

        runner.Test("h2 flow: a parked buffered response sends the body it was given, not what its buffer holds later", () =>
        {
            // Http2Response lets a handler pool its body once it returns, so what waits on credit must be a copy.
            byte[] body = new byte[64 * 1024];
            for (int i = 0; i < body.Length; i++)
            {
                body[i] = (byte)(i % 251);
            }
            byte[] given = body.ToArray();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200, Body = body });

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
            List<Frame> frames = client.Drain();
            Assert.Equal(16384, Frame.Body(frames, 1).Length);       // one stream window, then parked

            body.AsSpan().Clear();
            client.Feed(WindowUpdate(1, 1 << 20));
            frames.AddRange(client.Drain());
            Assert.True(Frame.Body(frames, 1).AsSpan().SequenceEqual(given),
                "the parked rest was read from the handler's buffer after the handler had handed it back");

            client.Close(run);
        });

        runner.Test("h2 flow: a parked buffered response stops at the peer's RST_STREAM, and the connection serves on", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(
                request => new Http2Response { Status = 200, Body = new byte[request.StreamId == 1 ? 64 * 1024 : 10] });

            client.ReleaseFlush();
            client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
            Assert.Equal(16384, Frame.Body(client.Drain(), 1).Length);

            client.Feed([.. RstStream(1, Cancel), .. Get(3)]);
            Assert.True(WriterPool(client.Connection).Count == 1, "the reset left the parked response waiting on credit");

            client.Feed([.. WindowUpdate(1, 1 << 20), .. WindowUpdate(0, 1 << 20)]);
            List<Frame> frames = client.Drain();
            Assert.True(!frames.Any(f => f.StreamId == 1), "frames went out on stream 1 after the peer had reset it");
            Assert.Equal(10, Frame.Body(frames, 3).Length);

            client.Close(run);
        });

        runner.Test("h2 flow: a parked buffered response lets go when the peer sends GOAWAY or closes the connection", () =>
        {
            foreach (bool goAway in new[] { true, false })
            {
                using var client = new StrictClient();
                Task run = client.Connection.RunAsync(_ => new Http2Response { Status = 200, Body = new byte[64 * 1024] });

                client.ReleaseFlush();
                client.Feed([.. Open((InitialWindowSize, 16384)), .. WindowUpdate(0, 1 << 20), .. Get(1)]);
                Assert.Equal(16384, Frame.Body(client.Drain(), 1).Length);

                if (goAway)
                {
                    client.Feed(GoAway());
                }
                client.Close(run);
                Assert.True(WriterPool(client.Connection).Count == 1,
                    $"the connection ended on {(goAway ? "a GOAWAY" : "a clean close")} with its parked response still waiting on credit");
            }
        });
    }

    private static byte[] GoAway() => FrameBytes(0x7, 0, 0, new byte[8]);   // last stream id 0, NO_ERROR
}
