using System.Net.Sockets;
using ioxide;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// A protocol layer that gives up on a connection lets go of it, and its client can go on sending regardless. Each
/// survives by the suite's own test: a fresh, well-formed request is still answered.
/// </summary>
internal static class LetGoChaosTests
{
    public static void Register(Runner runner)
    {
        bool noIncremental = !TestServer.KernelAtLeast(6, 12);

        foreach ((LetGoDriver.Mode mode, LetGoDriver.Ending ending, string name) in LetGoDriver.Cases())
        {
            bool skip = noIncremental && mode == LetGoDriver.Incremental;

            runner.Test($"h2c let-go, a bad connection preface: {name}", () =>
            {
                int port = TestServer.StartConfigured(Http2, LetGoDriver.Configure(mode, ending)).Port;
                LetGoDriver.Check(() => LetGoDriver.Refused(port, "NOT THE PREFACE, NOT AT ALL, IT IS NOT\r\n\r\n"u8), () => H2Answers(port), mode, ending);
            }, skip: skip);

            runner.Test($"h2c let-go, nghttp2, a bad connection preface: {name}", () =>
            {
                int port = TestServer.StartConfigured(Nghttp2, LetGoDriver.Configure(mode, ending)).Port;
                LetGoDriver.Check(() => LetGoDriver.Refused(port, "NOT THE PREFACE, NOT AT ALL, IT IS NOT\r\n\r\n"u8), () => H2Answers(port), mode, ending);
            }, skip: skip);

            runner.Test($"http/1.1 let-go, headers past the limit: {name}", () =>
            {
                int port = TestServer.StartConfigured(ChaosServer.Http, LetGoDriver.Configure(mode, ending)).Port;

                byte[] tooLong = new byte[ChaosServer.MaxRequestBytes + 1];
                tooLong.AsSpan().Fill((byte)'x');
                LetGoDriver.Check(() => LetGoDriver.Refused(port, tooLong), () => LetGoDriver.Answers(() =>
                    Client.Get(port, "/", LetGoDriver.GraceMs).Status == 200), mode, ending);
            }, skip: skip);
        }
    }

    private static async Task Http2(Reactor _, TcpConnection conn)
    {
        try
        {
            await new Http2Connection(conn).RunAsync(_ => Http2Response.Text("ok"));
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task Nghttp2(Reactor _, TcpConnection conn)
    {
        try
        {
            await new Nghttp2Connection(conn).RunAsync(_ => Nghttp2Response.Text("ok"));
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static bool H2Answers(int port) => LetGoDriver.Answers(() =>
    {
        using var client = new H2cClient(port);
        client.Open();
        client.Request(streamId: 1);
        return client.AwaitResponse(streamId: 1);
    });
}
