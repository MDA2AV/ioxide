using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A whole-response nghttp3 handler that throws, with its request body assembled and with it streamed
/// through a body reader: the two modes share one asynchronous dispatch. Wherever the handler throws,
/// its request is answered a bare 500 and the connection serves the next request.
/// </summary>
internal static class H3BufferedFaultTests
{
    // Past the 256 KiB stream window, so a streamed upload the failed handler never read only
    // finishes if the failure gave the window back.
    private static readonly byte[] Upload = new byte[300_000];

    public static void Register(Runner runner)
    {
        foreach (bool streamed in new[] { false, true })
        {
            string mode = streamed ? "streamed body" : "assembled body";

            runner.Test($"h3 fault (nghttp3, {mode}): a buffered handler that throws before it has a task answers 500, and the connection serves on", () =>
                FailThenServe(streamed, BeforeTask));

            runner.Test($"h3 fault (nghttp3, {mode}): a buffered handler that throws before its first await answers 500, and the connection serves on", () =>
                FailThenServe(streamed, BeforeAwait));

            runner.Test($"h3 fault (nghttp3, {mode}): a buffered handler that throws after an await answers 500, and the connection serves on", () =>
                FailThenServe(streamed, AfterAwait));
        }
    }

    // POST the upload to "/boom", whose handler throws, then GET "/ok" on the same connection.
    private static void FailThenServe(bool streamed, Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => streamed
                ? new Nghttp3Connection(conn).RunAsync((Nghttp3Request request, Nghttp3BodyReader _) => handler(request))
                : new Nghttp3Connection(conn).RunAsync(handler));

        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

        (int status, string body) = client.Request("POST", "/boom", Upload, timeoutMs: 15_000);
        Assert.True(status == 500 && body == "", $"the request whose handler threw got {Answer(status, body)}, not a bare 500");

        (status, body) = client.Get("/ok", timeoutMs: 5000);
        Assert.True(status == 200 && body == "ok",
            $"the next request on the connection got {Answer(status, body)}" + (client.PeerClosed ? ": the server closed the connection" : ""));
    }

    // Not async, so the call itself throws.
    private static ValueTask<Nghttp3Response> BeforeTask(Nghttp3Request request)
        => Fails(request) ? throw Failure() : ValueTask.FromResult(Nghttp3Response.Text("ok"));

    // Async, so the task the call returns is already faulted.
    private static async ValueTask<Nghttp3Response> BeforeAwait(Nghttp3Request request)
    {
        if (Fails(request))
        {
            throw Failure();
        }
        await TestServer.LaterPass();
        return Nghttp3Response.Text("ok");
    }

    // The task faults in a later reactor pass, outside the dispatch that started it.
    private static async ValueTask<Nghttp3Response> AfterAwait(Nghttp3Request request)
    {
        bool fails = Fails(request);
        await TestServer.LaterPass();
        return fails ? throw Failure() : Nghttp3Response.Text("ok");
    }

    private static bool Fails(Nghttp3Request request) => request.Path.Span.SequenceEqual("/boom"u8);

    private static InvalidOperationException Failure() => new("the handler failed");

    private static string Answer(int status, string body) => status < 0 ? "no answer" : $"{status} [{body}]";
}
