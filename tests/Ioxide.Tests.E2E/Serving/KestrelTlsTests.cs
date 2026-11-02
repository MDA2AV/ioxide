using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>The TLS features the Kestrel transport sets on a connection, read the way an app reads them.</summary>
internal static class KestrelTlsTests
{
    public static void Register(Runner runner)
    {
        runner.Test("kestrel: an app reading ITlsHandshakeFeature gets the cipher suite its TLS connection negotiated", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            int port = TestServer.NextPort();
            var listening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port));
            builder.WebHost.UseIoxide(o =>
            {
                o.ReactorCount = 1;
                o.UseTls(certPath, keyPath, [port]);
                // Runs once the reactor has opened its listener, so the connect below is never refused.
                o.OnReactorStart = _ => listening.TrySetResult();
            });

            WebApplication app = builder.Build();
            app.Run(context =>
            {
                string suite = context.Features.Get<ITlsHandshakeFeature>()?.NegotiatedCipherSuite?.ToString() ?? "null";
                context.Response.ContentLength = suite.Length;
                return context.Response.WriteAsync(suite);
            });

            app.StartAsync().GetAwaiter().GetResult();
            try
            {
                Assert.True(listening.Task.Wait(10_000), "the transport's reactor never started");

                using var client = new TcpClient();
                client.Connect(IPAddress.Loopback, port);
                client.ReceiveTimeout = 6_000;

                using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
                ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

                Client.Send(ssl, "/");
                (int status, string body) = Client.ReadResponse(ssl);

                Assert.Equal(200, status);
                Assert.Equal(ssl.NegotiatedCipherSuite.ToString(), body);
            }
            finally
            {
                app.StopAsync().GetAwaiter().GetResult();
                app.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        });
    }
}
