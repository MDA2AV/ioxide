using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// MaxRequestBytes on both HTTP/3 stacks: an assembled body past it is reset with H3_EXCESSIVE_LOAD
/// and never reaches its handler, one exactly at it is served, and a streamed body - bound by its
/// flow-control window instead - is not capped at all. Every case runs at a cap of 1000 bytes.
/// </summary>
internal static class H3BodyLimitTests
{
    private const int Cap = 1000;

    public static void Register(Runner runner)
    {
        runner.Test("h3: an assembled body past MaxRequestBytes is reset with H3_EXCESSIVE_LOAD", () =>
            Assert.Equal("reset 0x107", Outcome(Nghttp3Assembled, Cap + 1)));

        runner.Test("control: h3 serves an assembled body of exactly MaxRequestBytes", () =>
            Assert.Equal($"served {Cap}", Outcome(Nghttp3Assembled, Cap)));

        runner.Test("h3: MaxRequestBytes does not cap a streamed body", () =>
            Assert.Equal($"served {4 * Cap}", Outcome(Nghttp3Streamed, 4 * Cap)));

        runner.Test("http3: an assembled body past MaxRequestBytes is reset with H3_EXCESSIVE_LOAD", () =>
            Assert.Equal("reset 0x107", Outcome(ManagedAssembled, Cap + 1)));

        runner.Test("control: http3 serves an assembled body of exactly MaxRequestBytes", () =>
            Assert.Equal($"served {Cap}", Outcome(ManagedAssembled, Cap)));

        runner.Test("http3: MaxRequestBytes does not cap a streamed body", () =>
            Assert.Equal($"served {4 * Cap}", Outcome(ManagedStreamed, 4 * Cap)));
    }

    private static Task Nghttp3Assembled(QuicConnection conn, Action<long> served)
        => new Nghttp3Connection(conn, new Nghttp3Options { MaxRequestBytes = Cap }).RunAsync(req =>
        {
            served(req.Body.Length);
            return Nghttp3Response.Text("ok");
        });

    private static Task Nghttp3Streamed(QuicConnection conn, Action<long> served)
        => new Nghttp3Connection(conn, new Nghttp3Options { MaxRequestBytes = Cap }).RunAsync(async (_, body) =>
        {
            served(await ReadToEnd(body.ReadAsync));
            return Nghttp3Response.Text("ok");
        });

    private static Task ManagedAssembled(QuicConnection conn, Action<long> served)
        => new Http3Connection(conn, new Http3Options { MaxRequestBytes = Cap }).RunAsync(req =>
        {
            served(req.Body.Length);
            return Http3Response.Text("ok");
        });

    private static Task ManagedStreamed(QuicConnection conn, Action<long> served)
        => new Http3Connection(conn, new Http3Options { MaxRequestBytes = Cap }).RunAsync(async (_, body) =>
        {
            served(await ReadToEnd(body.ReadAsync));
            return Http3Response.Text("ok");
        });

    private static async ValueTask<long> ReadToEnd(Func<ValueTask<ReadOnlyMemory<byte>>> read)
    {
        long total = 0;
        ReadOnlyMemory<byte> chunk;
        while (!(chunk = await read()).IsEmpty)
        {
            total += chunk.Length;
        }
        return total;
    }

    /// <summary>
    /// POST <paramref name="length"/> bytes as one DATA frame, with no content-length, and report
    /// what became of the request: "served N" with the body its handler was given, "reset 0x..."
    /// with the code its stream was reset with, or "nothing".
    /// </summary>
    private static string Outcome(Func<QuicConnection, Action<long>, Task> serve, int length)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        long served = -1;
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => serve(conn, body => Volatile.Write(ref served, body)));

        using var client = new RawH3Client("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        client.OpenRequestStream();

        client.Write([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(length), .. new byte[length]], fin: true);

        // A served request is never reset, so this waits its timeout out - long enough for the
        // handler, which runs as soon as the fin is in, to have recorded what it was given.
        ulong? code = client.WaitForReset(timeoutMs: 2000);
        long body = Volatile.Read(ref served);
        return body >= 0 ? $"served {body}" : code is ulong c ? $"reset 0x{c:x}" : "nothing";
    }
}
