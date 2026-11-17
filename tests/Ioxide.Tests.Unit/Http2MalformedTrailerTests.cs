using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// The trailers of a request whose handler takes a body reader, which is already running when they
/// arrive. They are decoded aside and dropped, but checked as a buffered request's are: a pseudo-header
/// or a field no request may carry makes them malformed, and so does a block that does not end the
/// stream (RFC 9113 8.1). The stream is reset with PROTOCOL_ERROR and the handler's read says why,
/// rather than the handler waiting for an end that never comes.
/// </summary>
internal static class Http2MalformedTrailerTests
{
    private const byte Data = 0x0, Headers = 0x1;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    public static void Register(Runner runner)
    {
        foreach ((string name, int flags, byte[] trailers, string reason) in new[]
        {
            ("a pseudo-header", EndHeaders | EndStream, (byte[])[0x04, 2, .. "/x"u8], "malformed"),
            ("transfer-encoding", EndHeaders | EndStream, Http2TrailerTests.Field("transfer-encoding", "chunked"), "malformed"),
            ("no END_STREAM", EndHeaders, Http2TrailerTests.Field("x-checksum", "abc"), "did not end its stream"),
        })
        {
            string shape = name;
            int trailerFlags = flags;
            byte[] block = trailers;
            string why = reason;
            runner.Test($"h2 streamed request: trailers with {shape} reset the stream, and the handler's read says why", () =>
            {
                (string outcome, List<Frame> frames) = Upload(trailerFlags, block);

                Assert.True(outcome.StartsWith("abc|") && outcome.Contains(why), $"the handler read: {outcome}");
                Assert.Equal("RST_STREAM 1 0x1", Http2ControlFrameTests.Errors(frames));
                Assert.Equal(0, frames.Count(f => f.Type == Headers && f.StreamId == 1));   // nothing more goes out on it
                Assert.Equal(1, frames.Count(f => f.Type == Headers && f.StreamId == 3));
            });
        }

        runner.Test("h2 streamed request: control: well-formed trailers end the body, and HPACK stays in step", () =>
        {
            (string outcome, List<Frame> frames) = Upload(EndHeaders | EndStream, Http2TrailerTests.Field("x-checksum", "abc", index: true), namesTheirEntry: true);

            Assert.Equal("abc", outcome);
            Assert.Equal("", Http2ControlFrameTests.Errors(frames));
            Assert.Equal(1, frames.Count(f => f.Type == Headers && f.StreamId == 1));
            Assert.Equal(1, frames.Count(f => f.Type == Headers && f.StreamId == 3));
        });
    }

    // A POST on stream 1 whose handler reads its body, three bytes, then the trailers, then a GET on
    // stream 3, which can name the entry the trailers insert: it resolves only if they were decoded.
    private static (string Outcome, List<Frame> Frames) Upload(int trailerFlags, byte[] trailers, bool namesTheirEntry = false)
    {
        using var client = new StrictClient();
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task run = client.Connection.RunAsync(async (request, body) =>
        {
            if (request.StreamId != 1)
            {
                return Http2Response.Text("ok");
            }

            var read = new StringBuilder();
            try
            {
                for (ReadOnlyMemory<byte> chunk = await body.ReadAsync(); !chunk.IsEmpty; chunk = await body.ReadAsync())
                {
                    read.Append(Encoding.ASCII.GetString(chunk.Span));
                }
            }
            catch (IOException e)
            {
                read.Append('|').Append(e.Message);
            }
            outcome.TrySetResult(read.ToString());
            return Http2Response.Text("ok");
        });
        client.SendRequests();
        client.Drain();

        client.Feed(Http2FlowControlTests.FrameBytes(Headers, EndHeaders, 1, [0x83, 0x86, 0x84]));
        client.Feed(Http2FlowControlTests.FrameBytes(Data, 0, 1, "abc"u8));
        client.Feed(Http2FlowControlTests.FrameBytes(Headers, (byte)trailerFlags, 1, trailers));
        byte[] get = namesTheirEntry ? [0x82, 0x86, 0x84, 0xBE] : [0x82, 0x86, 0x84];
        client.Feed(Http2FlowControlTests.FrameBytes(Headers, EndHeaders | EndStream, 3, get));
        List<Frame> frames = client.Drain();

        string result = outcome.Task.Wait(2_000) ? outcome.Task.Result : "(still waiting for the end of the body)";
        client.Close(run);
        return (result, frames);
    }
}
