using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>The TLS features the Kestrel transport sets on a connection, read the way an app reads them.</summary>
internal static class KestrelTlsTests
{
    public static void Register(Runner runner)
    {
        runner.Test("kestrel: an app reading the TLS features gets the cipher suite, protocol and ALPN its connection negotiated", () =>
        {
            (int status, string body, string negotiated) = Request(context =>
            {
                string tls = Describe(context.Features.Get<ITlsHandshakeFeature>(), context.Features.Get<ITlsApplicationProtocolFeature>());
                context.Response.ContentLength = tls.Length;
                return context.Response.WriteAsync(tls);
            });

            Assert.Equal(200, status);
            Assert.Equal(negotiated, body);
        });

        runner.Test("kestrel: the TLS features still report what the connection negotiated once Kestrel has disposed it and its TLS session", () =>
        {
            ITlsHandshakeFeature? handshake = null;
            ITlsApplicationProtocolFeature? alpn = null;

            (_, _, string negotiated) = Request(context =>
            {
                // Held past the connection, as an HTTP/2 stream's handler is when a connection error ends it first.
                handshake = context.Features.Get<ITlsHandshakeFeature>();
                alpn = context.Features.Get<ITlsApplicationProtocolFeature>();
                return Task.CompletedTask;
            });

            Assert.Equal(negotiated, Describe(handshake, alpn));
        });
    }

    private static string Describe(ITlsHandshakeFeature? handshake, ITlsApplicationProtocolFeature? alpn) =>
        $"{handshake?.NegotiatedCipherSuite?.ToString() ?? "null"} {handshake?.Protocol} "
        + (alpn is null ? "null" : Encoding.ASCII.GetString(alpn.ApplicationProtocol.Span));

    // One request over TLS, offering http/1.1, to a Kestrel app on the ioxide transport. Negotiated is what the
    // client's SslStream settled on, in Describe's format.
    private static (int Status, string Body, string Negotiated) Request(RequestDelegate handler)
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
        app.Run(handler);

        app.StartAsync().GetAwaiter().GetResult();
        try
        {
            Assert.True(listening.Task.Wait(10_000), "the transport's reactor never started");

            using var client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            client.ReceiveTimeout = 6_000;

            using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            });

            Client.Send(ssl, "/");
            (int status, string body) = Client.ReadResponse(ssl);
            return (status, body, $"{ssl.NegotiatedCipherSuite} {ssl.SslProtocol} {ssl.NegotiatedApplicationProtocol}");
        }
        finally
        {
            // Returns once Kestrel has disposed every connection, which frees each one's TLS session.
            app.StopAsync().GetAwaiter().GetResult();
            app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
