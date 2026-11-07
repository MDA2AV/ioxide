using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// An ASP.NET app on the transport, whose connections its adapter lets go whenever Kestrel is done with them: after a
/// Connection: close answer, a request it refused, or a handshake that failed. Its clients can carry on regardless.
/// </summary>
internal static class KestrelLetGoTests
{
    private static ReadOnlySpan<byte> CloseRequest => "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"u8;

    public static void Register(Runner runner)
    {
        bool noIncremental = !TestServer.KernelAtLeast(6, 12);

        foreach ((LetGoDriver.Mode mode, LetGoDriver.Ending ending, string name) in LetGoDriver.Cases())
        {
            bool skip = noIncremental && mode == LetGoDriver.Incremental;

            runner.Test($"kestrel let-go, a Connection: close answer: {name}", () =>
            {
                Run(tls: false, mode, ending, port => LetGoDriver.Refused(port, CloseRequest));
            }, skip: skip);

            runner.Test($"kestrel let-go, a request it refused: {name}", () =>
            {
                Run(tls: false, mode, ending, port => LetGoDriver.Refused(port, "NOT A REQUEST\r\n\r\n"u8));
            }, skip: skip);

            runner.Test($"kestrel let-go, a Connection: close answer over TLS: {name}", () =>
            {
                Run(tls: true, mode, ending, AnsweredOverTls);
            }, skip: skip);

            runner.Test($"kestrel let-go, a failed TLS handshake: {name}", () =>
            {
                Run(tls: true, mode, ending, port => LetGoDriver.Refused(port, CloseRequest));
            }, skip: skip);
        }
    }

    private static void Run(bool tls, LetGoDriver.Mode mode, LetGoDriver.Ending ending, Func<int, Socket> letGoClient)
    {
        int port = TestServer.NextPort();
        var listening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port));
        builder.WebHost.UseIoxide(o =>
        {
            o.ReactorCount = 1;
            o.ConfigureServer = config => LetGoDriver.Configure(mode, ending, config);
            o.OnReactorStart = _ => listening.TrySetResult();
            if (tls)
            {
                (string certPath, string keyPath) = TestCert.Ensure();
                o.UseTls(certPath, keyPath, [port]);
            }
        });

        WebApplication app = builder.Build();
        app.Run(context =>
        {
            context.Response.ContentLength = 2;
            return context.Response.WriteAsync("ok");
        });

        app.StartAsync().GetAwaiter().GetResult();
        try
        {
            Assert.True(listening.Task.Wait(5_000), "the reactor never came up");

            LetGoDriver.Check(() => letGoClient(port), () => LetGoDriver.Answers(() =>
                (tls ? Client.GetTls(port, "/", LetGoDriver.GraceMs) : Client.Get(port, "/", LetGoDriver.GraceMs)).Status == 200), mode, ending);
        }
        finally
        {
            using var stopping = new CancellationTokenSource(3_000);
            app.StopAsync(stopping.Token).GetAwaiter().GetResult();
        }
    }

    private static Socket AnsweredOverTls(int port)
    {
        Socket client = LetGoDriver.Connect(port);
        using (var ssl = new SslStream(new NetworkStream(client), leaveInnerStreamOpen: true, (_, _, _, _) => true))
        {
            ssl.AuthenticateAsClient("localhost");
            ssl.Write(CloseRequest);

            var buffer = new byte[4096];
            try
            {
                while (ssl.Read(buffer) > 0)
                {
                }
            }
            catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset })
            {
                // A reset is an end too.
            }
        }

        return client;
    }
}
