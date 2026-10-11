using System.Net;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// An origin named rather than addressed: the pool resolves the name when it opens a connection,
/// sends it as the request's host - which is what a server hosting many names routes by - and tries
/// the resolved addresses in turn.
/// </summary>
internal static class HttpClientDnsTests
{
    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: a host name is resolved, and sent as the request's host", () =>
        {
            int originPort = TestServer.Start(HostEchoOrigin);
            int proxy = StartProxy(new HttpClientOptions { Host = "localhost", Port = (ushort)originPort, PoolSize = 1 });

            (_, string body) = Client.Get(proxy, "/");
            Assert.Equal($"200|localhost:{originPort}", body);
        });

        runner.Test("httpclient h1: a name that does not resolve fails the request with the resolver's reason", () =>
        {
            int proxy = StartProxy(new HttpClientOptions
            {
                Host = "no-such-host.invalid",   // RFC 6761: never resolves
                Port = (ushort)TestServer.DeadPort(),
                PoolSize = 1,
                AcquireTimeoutMs = 1_000,
            });

            (_, string body) = Client.Get(proxy, "/", timeoutMs: 15_000);
            Assert.True(body.StartsWith("599|") && body.Contains("could not resolve no-such-host.invalid"),
                $"expected the resolver's failure, got: {body}");
        });

        runner.Test("httpclient h1: a connect that fails moves on to the next resolved address", () =>
        {
            // Bound to 127.0.0.1 alone, so 127.0.0.2 refuses at once.
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            string connected = ConnectOnReactor([IPAddress.Parse("127.0.0.2"), IPAddress.Loopback], port);
            Assert.Equal("connected", connected);
            Assert.True(listener.Server.Poll(5_000_000, SelectMode.SelectRead), "the second address was never dialed");

            // Control: the refusing address alone fails, so the test above did fall through to the next.
            string refused = ConnectOnReactor([IPAddress.Parse("127.0.0.2")], port);
            Assert.True(refused.Contains("connect to 127.0.0.2"), $"expected the refusal, got: {refused}");
        });
    }

    private static int StartProxy(HttpClientOptions options)
        => TestServer.Start(TlsClientTests.ProxyHandler, onStart: reactor => HttpClientPool.Start(reactor, options));

    // ClientTransport on a reactor of its own, with the outcome handed back to the test thread.
    private static string ConnectOnReactor(IPAddress[] addresses, int port)
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        TestServer.Start((_, connection) => { connection.DecRef(); return Task.CompletedTask; },
            onStart: reactor => _ = ConnectAsync(reactor));
        Assert.True(outcome.Task.Wait(10_000), "the connect never finished");
        return outcome.Task.Result;

        async Task ConnectAsync(Reactor reactor)
        {
            try
            {
                IClientTransport transport = await ClientTransport.ConnectAsync(reactor, addresses, (ushort)port, tls: null);
                transport.Dispose();
                outcome.TrySetResult("connected");
            }
            catch (Exception e)
            {
                outcome.TrySetResult(e.Message);
            }
        }
    }

    // Answers each request with the host it was sent to.
    private static async Task HostEchoOrigin(Reactor _, TcpConnection connection)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }

                string host = "";
                while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        string head = Encoding.ASCII.GetString(item.AsSpan());
                        host = head.Split("\r\n").FirstOrDefault(line => line.StartsWith("host:", StringComparison.OrdinalIgnoreCase))?[5..].Trim() ?? host;
                        connection.ReturnBuffer(in item);
                    }
                }

                Wire.Write(connection, 200, host);
                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            connection.DecRef();
        }
    }
}
