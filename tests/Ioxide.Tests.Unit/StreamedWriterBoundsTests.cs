using System.Buffers;
using System.Text;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// The IBufferWriter edges of the streamed writers on both HTTP/2 stacks: a hint no staging array holds beside what
/// is staged is refused rather than handed less, and an Advance past the span is refused however large its count.
/// Each handler runs a probe, and the response it then completes has to carry what the probe staged.
/// </summary>
internal static class StreamedWriterBoundsTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 writer: GetSpan and GetMemory refuse a hint the staging array cannot hold beside what it has staged, rather than hand out less", () =>
            AssertHttp2("GetSpan refused, GetMemory refused", BufferWriterProbes.Overreach));

        runner.Test("h2 writer: an Advance past the span it was handed is refused, however large its count", () =>
            AssertHttp2("refused", BufferWriterProbes.Overrun));

        runner.Test("nghttp2 writer: GetSpan and GetMemory refuse a hint the staging array cannot hold beside what it has staged, rather than hand out less", () =>
            AssertNghttp2("GetSpan refused, GetMemory refused", BufferWriterProbes.Overreach));
    }

    private static void AssertHttp2(string expected, Func<IBufferWriter<byte>, string> probe)
    {
        string? told = null;
        using var client = new StrictClient();
        Task run = client.Connection.RunAsync(async (_, writer) =>
        {
            writer.WriteHeaders(new Http2Response { Status = 200 });
            told = probe(writer);
            await writer.CompleteAsync();
        });

        client.ReleaseFlush();                       // server SETTINGS
        client.SendRequests(1);
        List<Frame> frames = client.Drain();

        Assert.Equal(expected, told);
        AssertStaged(Frame.Body(frames, streamId: 1));
        client.Close(run);
    }

    private static void AssertNghttp2(string expected, Func<IBufferWriter<byte>, string> probe)
    {
        string? told = null;
        using var client = new StrictClient();
        var connection = new Nghttp2Connection(client);
        Task run = connection.RunAsync((_, writer) =>
        {
            writer.WriteHeaders(new Nghttp2Response { Status = 200 });
            told = probe(writer);
            return ValueTask.CompletedTask;
        });

        client.SendRequests();                       // preface and SETTINGS
        client.Drain();
        client.Feed(Get(1));
        List<Frame> frames = client.Drain();

        Assert.Equal(expected, told);
        AssertStaged(Frame.Body(frames, streamId: 1));
        client.Close(run);
        connection.Dispose();
    }

    private static void AssertStaged(byte[] body)
        => Assert.True(body.AsSpan().SequenceEqual(BufferWriterProbes.Staged),
            $"the stream carried '{Encoding.ASCII.GetString(body)}', not the bytes staged before the probe");

    // A GET with END_STREAM: :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Get(int streamId)
    {
        byte[] block = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
        return Http2FlowControlTests.FrameBytes(0x1, 0x5, streamId, block);
    }
}
