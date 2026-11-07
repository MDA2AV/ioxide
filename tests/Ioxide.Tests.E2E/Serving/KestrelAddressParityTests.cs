using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// Whatever a host asks to listen on, the transport does what the stock one does, so the stock one is the test's
/// oracle: the same sockets listening, the same addresses reported, the same connections accepted and refused.
/// </summary>
internal static class KestrelAddressParityTests
{
    private static readonly IPAddress? OwnAddress = NetworkInterface.GetAllNetworkInterfaces()
        .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
        .Select(unicast => unicast.Address)
        .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);

    public static void Register(Runner runner)
    {
        (string Name, Action<WebApplicationBuilder, int> Ask)[] asks =
        [
            ("Listen(Loopback)", (b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, p))),
            ("Listen(IPv6Loopback)", (b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.IPv6Loopback, p))),
            ("Listen(Any)", (b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Any, p))),
            ("Listen(IPv6Any)", (b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.IPv6Any, p))),
            ("ListenLocalhost", (b, p) => b.WebHost.ConfigureKestrel(k => k.ListenLocalhost(p))),
            ("ListenAnyIP", (b, p) => b.WebHost.ConfigureKestrel(k => k.ListenAnyIP(p))),
            ("the URL http://127.0.0.1", (b, p) => b.WebHost.UseUrls($"http://127.0.0.1:{p}")),
            ("the URL http://[::1]", (b, p) => b.WebHost.UseUrls($"http://[::1]:{p}")),
            ("the URL http://localhost", (b, p) => b.WebHost.UseUrls($"http://localhost:{p}")),
            ("the URL http://*", (b, p) => b.WebHost.UseUrls($"http://*:{p}")),
            ("the URL http://+", (b, p) => b.WebHost.UseUrls($"http://+:{p}")),
        ];

        foreach ((string name, Action<WebApplicationBuilder, int> ask) in asks)
        {
            runner.Test($"kestrel: told {name}, it does what the stock transport does", () => SameAsStock(ask));
        }

        runner.Test("kestrel: told this machine's own address, it does what the stock transport does", () =>
        {
            SameAsStock((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(OwnAddress!, p)));
        }, skip: OwnAddress is null);

        runner.Test("kestrel: told an address this machine doesn't have, the host's start fails, as on the stock transport", () =>
        {
            var nowhere = IPAddress.Parse("192.0.2.1");   // TEST-NET-1: never assigned
            int port = TestServer.NextPort();

            Assert.Throws<Exception>(() => Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(nowhere, p)), port, ioxide: false).Dispose());
            Assert.Throws<Exception>(() => Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(nowhere, p)), port, ioxide: true).Dispose());
        });

        runner.Test("kestrel: told port 0, it reports the port it got, and every reactor listens on that one", () =>
        {
            using Host host = Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, p)), 0, ioxide: true);

            string address = host.Reported.Single();
            int port = new Uri(address).Port;
            Assert.True(port != 0, $"it reports {address}");

            Assert.True(LetGoDriver.Eventually(() => host.ReactorsUp), "the reactors never came up");
            Assert.Equal("tcp 0100007F", string.Join(", ", Listening(port)));
            Assert.Equal(200, Client.Get(port, "/").Status);
        });

        runner.Test("kestrel: control: the stock transport, told port 0, reports the port it got", () =>
        {
            using Host host = Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, p)), 0, ioxide: false);

            int port = new Uri(host.Reported.Single()).Port;
            Assert.True(port != 0, "it reports port 0");
            Assert.Equal(200, Client.Get(port, "/").Status);
        });

        runner.Test("kestrel: stopping the host leaves no socket of its own behind", () =>
        {
            int port = TestServer.NextPort();
            Thread.Sleep(150);   // what the last test left behind has gone
            GC.Collect();
            GC.WaitForPendingFinalizers();
            int before = LetGoDriver.OpenSockets();

            Host host = Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, p)), port, ioxide: true);
            Assert.True(LetGoDriver.Eventually(() => host.ReactorsUp), "the reactors never came up");
            Assert.Equal(200, Client.Get(port, "/").Status);

            // A socket left open also closes when its finalizer runs, so no collection may run while this looks.
            Assert.True(GC.TryStartNoGCRegion(64 * 1024 * 1024), "no room for a region without collections");
            try
            {
                host.Dispose();
                Assert.True(LetGoDriver.Eventually(() => LetGoDriver.OpenSockets() <= before),
                    $"{LetGoDriver.OpenSockets() - before} sockets still open after the host stopped");
            }
            finally
            {
                if (System.Runtime.GCSettings.LatencyMode == System.Runtime.GCLatencyMode.NoGCRegion)
                {
                    GC.EndNoGCRegion();
                }
            }
        });

        runner.Test("kestrel: a ConfigureServer that replaces the TCP options still listens where the host asked", () =>
        {
            int port = TestServer.NextPort();

            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port));

            var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            builder.WebHost.UseIoxide(o =>
            {
                o.ReactorCount = 1;
                o.ConfigureServer = config => config with { Tcp = new ioxide.TcpOptions { ReadTimeoutMs = 1_000 } };
                o.OnReactorStart = _ => started.TrySetResult();
            });

            WebApplication app = builder.Build();
            app.Run(context => context.Response.WriteAsync("ok"));
            app.StartAsync().GetAwaiter().GetResult();
            try
            {
                Assert.True(started.Task.Wait(5_000), "the reactor never came up");
                Assert.Equal("tcp 0100007F", string.Join(", ", Listening(port)));
            }
            finally
            {
                using var stopping = new CancellationTokenSource(3_000);
                app.StopAsync(stopping.Token).GetAwaiter().GetResult();
            }
        });

        runner.Test("kestrel: told :: with IPv4's wildcard taken, the host's start fails, as on the stock transport", () =>
        {
            using var taken = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            taken.Bind(new IPEndPoint(IPAddress.Any, 0));
            taken.Listen(8);
            int port = ((IPEndPoint)taken.LocalEndPoint!).Port;

            Assert.Throws<Exception>(() => Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.IPv6Any, p)), port, ioxide: false).Dispose());
            Assert.Throws<Exception>(() => Started((b, p) => b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.IPv6Any, p)), port, ioxide: true).Dispose());
        }, skip: !Socket.OSSupportsIPv6);
    }

    private static void SameAsStock(Action<WebApplicationBuilder, int> ask)
    {
        int port = TestServer.NextPort();

        Seen stock;
        try
        {
            using Host host = Started(ask, port, ioxide: false);
            stock = host.See(port);
        }
        catch (Exception e) when (e is IOException or SocketException)
        {
            // This machine can't do what was asked, such as IPv6 loopback with IPv6 off: neither transport should start.
            Assert.Throws<Exception>(() => Started(ask, port, ioxide: true).Dispose());
            return;
        }

        using (Host host = Started(ask, port, ioxide: true))
        {
            Assert.True(LetGoDriver.Eventually(() => Listening(port).SequenceEqual(stock.Listening)),
                $"the stock transport listens on [{string.Join(", ", stock.Listening)}], and this on [{string.Join(", ", Listening(port))}]");

            Seen ours = host.See(port);
            Assert.Equal(string.Join(", ", stock.Reported), string.Join(", ", ours.Reported));
            Assert.Equal(stock.Connections, ours.Connections);

            if (ours.Connections.Contains("127.0.0.1 accepted"))
            {
                Assert.Equal(200, Client.Get(port, "/").Status);
            }
        }
    }

    private sealed record Seen(string[] Listening, string[] Reported, string Connections);

    private sealed class Host(WebApplication app, string[] reported, Func<bool> reactorsUp) : IDisposable
    {
        public string[] Reported { get; } = reported;

        public bool ReactorsUp => reactorsUp();

        public Seen See(int port) => new(Listening(port), Reported, string.Join("; ",
            new[] { IPAddress.Loopback, IPAddress.IPv6Loopback, OwnAddress }
                .Where(address => address is not null)
                .Select(address => $"{address} {(Accepts(address!, port) ? "accepted" : "refused")}")));

        public void Dispose()
        {
            using var stopping = new CancellationTokenSource(3_000);
            app.StopAsync(stopping.Token).GetAwaiter().GetResult();
        }
    }

    private static Host Started(Action<WebApplicationBuilder, int> ask, int port, bool ioxide)
    {
        int started = 0;

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        ask(builder, port);
        if (ioxide)
        {
            builder.WebHost.UseIoxide(o =>
            {
                o.ReactorCount = 2;
                o.OnReactorStart = _ => Interlocked.Increment(ref started);
            });
        }

        WebApplication app = builder.Build();
        app.Run(context =>
        {
            context.Response.ContentLength = 2;
            return context.Response.WriteAsync("ok");
        });

        app.StartAsync().GetAwaiter().GetResult();

        string[] reported = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Order().ToArray();
        return new Host(app, reported, () => Volatile.Read(ref started) >= 2);
    }

    // The sockets listening on the port, as /proc prints their addresses. A set, since reactors share them.
    private static string[] Listening(int port)
    {
        var rows = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string family in new[] { "tcp", "tcp6" })
        {
            string path = $"/proc/net/{family}";
            if (!File.Exists(path))
            {
                continue;
            }

            foreach (string line in File.ReadLines(path).Skip(1))
            {
                string[] row = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                int colon = row[1].IndexOf(':');
                if (row[3] == "0A" && Convert.ToInt32(row[1][(colon + 1)..], 16) == port)
                {
                    rows.Add($"{family} {row[1][..colon]}");
                }
            }
        }

        return rows.ToArray();
    }

    private static bool Accepts(IPAddress address, int port)
    {
        try
        {
            using var client = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(address, port);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
