using System.Net;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// What a host asked to listen on is what it listens on. The transport takes only the port from the endpoint
/// Kestrel hands it, so an app that asked for loopback, to stay private, is on every interface.
/// </summary>
internal static class KestrelListenAddressTests
{
    private const string Loopback = "0100007F";      // 127.0.0.1, as /proc/net/tcp prints it
    private const string AnyAddress = "00000000";    // 0.0.0.0

    public static void Register(Runner runner)
    {
        runner.Test("kestrel: a host told to listen on loopback does not listen on every interface", () =>
        {
            int port = TestServer.NextPort();
            HashSet<string> addresses = AddressesListenedOn(port, ioxide: true);

            Assert.True(!addresses.Contains(AnyAddress) && addresses.Contains(Loopback),
                $"told to listen on {Loopback}, it listens on [{string.Join(", ", addresses)}]");
        });

        runner.Test("kestrel: control: the stock transport, told the same, listens on loopback only", () =>
        {
            int port = TestServer.NextPort();
            HashSet<string> addresses = AddressesListenedOn(port, ioxide: false);

            Assert.Equal(Loopback, string.Join(", ", addresses));
        });
    }

    private static HashSet<string> AddressesListenedOn(int port, bool ioxide)
    {
        var listening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port));
        if (ioxide)
        {
            builder.WebHost.UseIoxide(o =>
            {
                o.ReactorCount = 1;
                o.OnReactorStart = _ => listening.TrySetResult();
            });
        }

        WebApplication app = builder.Build();
        app.Run(context => context.Response.WriteAsync("ok"));

        app.StartAsync().GetAwaiter().GetResult();
        try
        {
            Assert.True(!ioxide || listening.Task.Wait(5_000), "the reactor never came up");

            // The "st" column: 0A is LISTEN.
            return File.ReadAllLines("/proc/net/tcp")
                .Skip(1)
                .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .Where(row => row[3] == "0A" && Convert.ToInt32(row[1][(row[1].IndexOf(':') + 1)..], 16) == port)
                .Select(row => row[1][..row[1].IndexOf(':')])
                .ToHashSet();
        }
        finally
        {
            app.StopAsync().GetAwaiter().GetResult();
        }
    }
}
