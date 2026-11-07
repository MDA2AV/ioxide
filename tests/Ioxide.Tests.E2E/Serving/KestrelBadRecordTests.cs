using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// The Kestrel transport decrypts in its receive pump, with buffers it took from the connection's queue, so nothing
/// but the pump can return them. A record that won't decrypt throws out of it. On the shared ring a buffer not returned
/// then is gone for the life of the process, so each client below would cost the reactor one.
/// </summary>
internal static class KestrelBadRecordTests
{
    private const int Slots = 16;
    private const int Clients = Slots * 3;   // several times the ring, so a loss can't hide behind slack

    private static readonly byte[] GoodRequest = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

    public static void Register(Runner runner)
    {
        foreach ((string name, byte[] record) in BadRecords())
        {
            runner.Test($"kestrel: clients over TLS that each send {name} leave every buffer in the ring", () =>
            {
                (int served, bool last) = Drive(record, SmallRing);
                Assert.True(served == Clients && last, $"only {served} of {Clients} handshakes completed, and the last client served={last}");
            });
        }

        runner.Test("kestrel: control: clients over TLS with a good request leave every buffer in the ring", () =>
        {
            (int served, bool last) = Drive(null, SmallRing);
            Assert.True(served == Clients && last, $"only {served} of {Clients} handshakes completed, and the last client served={last}");
        });

        runner.Test("kestrel: incremental: clients over TLS that send a bad record leave the next one served", () =>
        {
            (int served, bool last) = Drive(BadRecords().First().Record, config => config with
            {
                Incremental = new IncrementalOptions { MaxConnections = 8, RecvSlots = 4, RecvBufferSize = 4096 },
            });
            Assert.True(served == Clients && last, $"only {served} of {Clients} handshakes completed, and the last client served={last}");
        }, skip: !TestServer.KernelAtLeast(6, 12));
    }

    private static ServerConfig SmallRing(ServerConfig config) => config with { RecvBufferSize = 4096, RecvSlots = Slots };

    private static IEnumerable<(string Name, byte[] Record)> BadRecords()
    {
        // application_data no key made: it fails its MAC.
        byte[] badMac = new byte[5 + 64];
        badMac[0] = 0x17;
        badMac[1] = 0x03;
        badMac[2] = 0x03;
        badMac[4] = 64;
        new Random(7).NextBytes(badMac.AsSpan(5));
        yield return ("a record that fails its MAC", badMac);

        // Not a TLS record at all.
        yield return ("something that isn't a record", Encoding.ASCII.GetBytes("this is not a TLS record, it is plain text"));
    }

    private static (int Served, bool Last) Drive(byte[]? record, Func<ServerConfig, ServerConfig> rings)
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
            o.OnReactorStart = _ => listening.TrySetResult();
            o.ConfigureServer = rings;
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

            int served = 0;
            for (int i = 0; i < Clients; i++)
            {
                try
                {
                    Exchange(port, record);
                    served++;
                }
                catch (Exception e) when (e is IOException or SocketException or System.Security.Authentication.AuthenticationException)
                {
                    break;   // the ring is empty: this handshake can no longer be read
                }
            }

            bool last;
            try
            {
                last = Exchange(port, null) > 0;
            }
            catch (Exception e) when (e is IOException or SocketException or System.Security.Authentication.AuthenticationException)
            {
                last = false;
            }

            return (served, last);
        }
        finally
        {
            using var stopping = new CancellationTokenSource(3_000);
            app.StopAsync(stopping.Token).GetAwaiter().GetResult();
        }
    }

    // A handshake, then the record if there is one or else a good request, then whatever comes back. Returns its size.
    private static int Exchange(int port, byte[]? record)
    {
        using var tcp = new TcpClient();
        tcp.ReceiveTimeout = 2_000;
        tcp.SendTimeout = 2_000;
        tcp.Connect(IPAddress.Loopback, port);

        using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.ReadTimeout = 2_000;
        ssl.AuthenticateAsClient("localhost");

        if (record is null)
        {
            ssl.Write(GoodRequest);
        }
        else
        {
            tcp.Client.Send(record);
        }

        var buffer = new byte[4096];
        int total = 0;
        try
        {
            int n;
            while ((n = ssl.Read(buffer)) > 0)
            {
                total += n;
            }
        }
        catch (IOException)
        {
            // The server ended it: what came before still counts.
        }

        return total;
    }
}
