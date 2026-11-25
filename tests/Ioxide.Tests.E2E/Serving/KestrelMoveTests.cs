using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// An ASP.NET app's connections stay on their reactors (<see cref="TcpOptions.Rebalance"/>): the pipes between Kestrel and
/// the transport are scheduled on the reactor the connection was accepted on.
/// </summary>
internal static class KestrelMoveTests
{
    public static void Register(Runner runner)
    {
        foreach (bool tls in new[] { false, true })
        {
            runner.Test($"kestrel: a connection stays on its reactor, whoever asks for it to move ({(tls ? "TLS" : "plaintext")})", () =>
            {
                var reactors = new ConcurrentBag<Reactor>();
                int port = TestServer.NextPort();
                WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
                builder.Logging.ClearProviders();
                builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port));
                builder.WebHost.UseIoxide(o =>
                {
                    o.ReactorCount = 2;
                    o.ConfigureServer = config => config with { RecvSlots = 256, RecvBufferSize = 4096, Tcp = config.Tcp! with { Rebalance = true } };
                    o.OnReactorStart = reactors.Add;
                    if (tls)
                    {
                        (string certPath, string keyPath) = TestCert.Ensure();
                        o.UseTls(certPath, keyPath, [port]);
                    }
                });
                WebApplication app = builder.Build();
                app.Run(context => context.Response.WriteAsync("ok"));
                app.StartAsync().GetAwaiter().GetResult();
                try
                {
                    Assert.Equal(2, reactors.Count);
                    using Socket client = Moves.Connect(port);
                    Reactor? holder = null;
                    Assert.True(SpinWait.SpinUntil(() => (holder = reactors.FirstOrDefault(r => Moves.LiveOn(r) == 1)) is not null, 5_000), "the connection was never accepted");

                    TcpConnection? conn = null;
                    Moves.On(holder!, () => conn = Moves.ConnectionsOf(holder!).Single());
                    Assert.True(conn!.Pinned, "the connection is not pinned");
                    Assert.True(!Moves.Begin(conn, reactors.Single(r => r != holder)), "a connection of Kestrel's began to move");

                    using var shuffle = new Moves.Shuffle([.. reactors]);
                    for (int i = 0; i < 50; i++)
                    {
                        Assert.Equal(200, (tls ? Client.GetTls(port, "/") : Client.Get(port, "/")).Status);
                    }
                    Assert.Equal(0L, shuffle.Made);
                    Assert.True(ReferenceEquals(conn.Reactor, holder), "it moved");
                }
                finally
                {
                    using var stopping = new CancellationTokenSource(3_000);
                    app.StopAsync(stopping.Token).GetAwaiter().GetResult();
                }
            });
        }
    }
}
