using System.Buffers;
using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// The IBufferWriter edges of the streamed writers on both HTTP/3 stacks: a hint no staging block holds beside what
/// is staged is refused rather than handed less, and an Advance past the span is refused however large its count.
/// Each handler runs a probe, and the response it then completes has to carry what the probe staged.
/// </summary>
internal static class H3StreamedWriterBoundsTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h3 writer: GetSpan and GetMemory refuse a hint the staging block cannot hold beside what it has staged, rather than hand out less", () =>
            AssertNghttp3("GetSpan refused, GetMemory refused", BufferWriterProbes.Overreach));

        runner.Test("h3 writer: an Advance past the span it was handed is refused, however large its count", () =>
            AssertNghttp3("refused", BufferWriterProbes.Overrun));

        runner.Test("http3 writer: GetSpan and GetMemory refuse a hint the staging array cannot hold beside what it has staged, rather than hand out less", () =>
            AssertHttp3("GetSpan refused, GetMemory refused", BufferWriterProbes.Overreach));

        runner.Test("http3 writer: an Advance past the span it was handed is refused, however large its count", () =>
            AssertHttp3("refused", BufferWriterProbes.Overrun));
    }

    private static void AssertNghttp3(string expected, Func<IBufferWriter<byte>, string> probe)
    {
        var told = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        string body = Get(conn => new Nghttp3Connection(conn).RunAsync(async (_, _, writer) =>
        {
            writer.WriteHeaders(new Nghttp3Response { Status = 200 });
            told.SetResult(probe(writer));
            await writer.CompleteAsync();
        }));

        AssertProbed(expected, told.Task, body);
    }

    private static void AssertHttp3(string expected, Func<IBufferWriter<byte>, string> probe)
    {
        var told = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        string body = Get(conn => new Http3Connection(conn).RunAsync(async (_, _, writer) =>
        {
            writer.WriteHeaders(new Http3Response { Status = 200 });
            told.SetResult(probe(writer));
            await writer.CompleteAsync();
        }));

        AssertProbed(expected, told.Task, body);
    }

    // What the probe reported first: a writer it got past may never end its response at all.
    private static void AssertProbed(string expected, Task<string> told, string body)
    {
        Assert.True(told.Wait(5_000), "the handler never ran its probe");
        Assert.Equal(expected, told.Result);
        Assert.True(body == Encoding.ASCII.GetString(BufferWriterProbes.Staged),
            $"the response carried '{body}', not the bytes staged before the probe");
    }

    private static string Get(Func<QuicConnection, Task> serve)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => serve(conn));

        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

        (_, string body) = client.Get("/", timeoutMs: 15_000);
        return body;
    }
}
