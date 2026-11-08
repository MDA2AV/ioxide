using System.Net;
using System.Net.Sockets;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// OnFault keeps one lost reactor from ending the process, which also keeps ALL of them being lost from
/// reaching the host: StartAsync has returned by the time a reactor finds its port taken.
/// </summary>
internal static class KestrelBindFailureTests
{
    public static void Register(Runner runner)
    {
        runner.Test("kestrel: a port no reactor could bind fails the host's start", () =>
        {
            // A plain listener asks for no SO_REUSEPORT, so every reactor's bind is refused, without privilege.
            using var blocker = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            blocker.Bind(new IPEndPoint(IPAddress.Any, 0));
            blocker.Listen(8);
            int port = ((IPEndPoint)blocker.LocalEndPoint!).Port;

            WebApplication app = NewApp(port, null);
            try
            {
                Assert.Throws<Exception>(() => app.StartAsync().GetAwaiter().GetResult(), "bind");
            }
            finally
            {
                app.StopAsync().GetAwaiter().GetResult();
            }
        });

        runner.Test("kestrel: control: the same host on a free port starts and answers", () =>
        {
            var listening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.NextPort();

            WebApplication app = NewApp(port, listening);
            app.StartAsync().GetAwaiter().GetResult();
            try
            {
                Assert.True(listening.Task.Wait(5_000), "no reactor came up");
                (int status, _) = Client.Get(port, "/");
                Assert.Equal(200, status);
            }
            finally
            {
                app.StopAsync().GetAwaiter().GetResult();
            }
        });
    }

    private static WebApplication NewApp(int port, TaskCompletionSource? listening)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Any, port));
        builder.WebHost.UseIoxide(o =>
        {
            o.ReactorCount = 2;
            o.OnReactorStart = _ => listening?.TrySetResult();
        });

        WebApplication app = builder.Build();
        app.Run(context => context.Response.WriteAsync("ok"));
        return app;
    }
}
