using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// How a pooled connection is opened and how long it is kept: IPv6, the TLS name taken from the
/// host, the connect timeout, and the lifetime after which a connection is replaced.
/// </summary>
internal static class HttpClientConnectTests
{
    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: an IPv6 address is dialed over IPv6, and bracketed in the request's host", () =>
        {
            // DualStack: the origin listens on [::], which IPv6 reaches and TestServer's IPv4 probe still does.
            (int originPort, _, _) = TestServer.StartConfigured(
                TestOrigins.Route(r => (200, "", r.Headers.GetValueOrDefault("host", ""))), DualStackConfig());
            int proxy = HttpClientDnsTests.StartProxy(new HttpClientOptions { Host = "::1", Port = (ushort)originPort, PoolSize = 1 });

            (_, string body) = Client.Get(proxy, "/");
            Assert.Equal($"200|[::1]:{originPort}", body);
        });

        runner.Test("httpclient h1: over https with no ServerName, the certificate is checked against Host", () =>
        {
            using TlsTestOrigin origin = TlsTestOrigin.Start("http/1.1");
            (string certPath, _) = TestCert.Ensure();
            int proxy = HttpClientDnsTests.StartProxy(new HttpClientOptions
            {
                Host = "localhost",   // the name the origin's certificate carries
                Port = (ushort)origin.Port,
                PoolSize = 1,
                Tls = TlsClientContext.Create(new TlsClientOptions { CaFile = certPath, AlpnProtocols = ["http/1.1"] }),
            });

            (_, string body) = Client.Get(proxy, "/", timeoutMs: 20_000);
            Assert.Equal("200|hello over http/1.1", body);
        });

        runner.Test("httpclient h1: control - over https to an address with no ServerName, the connect fails and says why", () =>
        {
            using TlsTestOrigin origin = TlsTestOrigin.Start("http/1.1");
            (string certPath, _) = TestCert.Ensure();
            int proxy = HttpClientDnsTests.StartProxy(new HttpClientOptions
            {
                Host = "127.0.0.1",
                Port = (ushort)origin.Port,
                PoolSize = 1,
                AcquireTimeoutMs = 1_000,
                Tls = TlsClientContext.Create(new TlsClientOptions { CaFile = certPath, AlpnProtocols = ["http/1.1"] }),
            });

            (_, string body) = Client.Get(proxy, "/", timeoutMs: 20_000);
            Assert.True(body.StartsWith("599|") && body.Contains("set TlsClientOptions.ServerName"),
                $"expected the missing name to be named, got: {body}");
        });

        runner.Test("httpclient h1: an address that never answers the connect times out, and the next is tried", () =>
        {
            // A listener whose accept queue is full drops the SYNs, so a connect to it never completes.
            using var answering = new TcpListener(IPAddress.Loopback, 0);
            answering.Start();
            int port = ((IPEndPoint)answering.LocalEndpoint).Port;
            using var silent = new TcpListener(IPAddress.Parse("127.0.0.3"), port);
            silent.Start(0);
            Socket[] queued = FillAcceptQueue(new IPEndPoint(IPAddress.Parse("127.0.0.3"), port));

            try
            {
                long start = Environment.TickCount64;
                string alone = HttpClientDnsTests.ConnectOnReactor([IPAddress.Parse("127.0.0.3")], port, connectTimeoutMs: 1_000);
                long took = Environment.TickCount64 - start;
                Assert.True(alone.Contains("timed out after 1000 ms"), $"expected the connect to time out, got: {alone}");
                Assert.True(took < 5_000, $"the 1000 ms connect timeout took {took} ms");

                string next = HttpClientDnsTests.ConnectOnReactor(
                    [IPAddress.Parse("127.0.0.3"), IPAddress.Loopback], port, connectTimeoutMs: 1_000);
                Assert.Equal("connected", next);
            }
            finally
            {
                foreach (Socket socket in queued)
                {
                    socket.Dispose();
                }
            }
        });

        runner.Test("httpclient h1: a connect its reactor's stop cancels, and the one to the next address it goes on to, both end with the stop", () =>
        {
            // Two addresses whose full accept queues drop the SYN, so neither connect ends unless the stop ends it.
            using var first = new TcpListener(IPAddress.Parse("127.0.0.3"), 0);
            first.Start(0);
            int port = ((IPEndPoint)first.LocalEndpoint).Port;
            using var second = new TcpListener(IPAddress.Parse("127.0.0.4"), port);
            second.Start(0);
            Socket[] queued = [.. FillAcceptQueue((IPEndPoint)first.LocalEndpoint), .. FillAcceptQueue((IPEndPoint)second.LocalEndpoint)];

            try
            {
                var started = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
                (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(
                    (_, connection) => { connection.DecRef(); return Task.CompletedTask; },
                    new ServerConfig { Tcp = new TcpOptions() },
                    r => started.SetResult(ClientTransport.ConnectAsync(r, [IPAddress.Parse("127.0.0.3"), IPAddress.Parse("127.0.0.4")],
                        (ushort)port, tls: null, serverName: null, connectTimeoutMs: 0).AsTask()));

                Task connect = started.Task.Result;
                Thread.Sleep(200);   // the first connect reaches the kernel, which holds it
                Assert.True(!connect.IsCompleted, $"the connect ended before the stop: {connect.Status}");

                reactor.Stop();
                Assert.True(((IAsyncResult)connect).AsyncWaitHandle.WaitOne(3_000), "the connect is still waiting 3 s after its reactor was stopped");
                Assert.True(thread.Join(3_000), "the reactor did not stop");
                Assert.True(connect.IsFaulted, $"the connect ended {connect.Status}, connected to an address that never answers");
            }
            finally
            {
                foreach (Socket socket in queued)
                {
                    socket.Dispose();
                }
            }
        });

        runner.Test("httpclient h1: an idle connection past MaxLifetimeMs is replaced by the sweep", () =>
        {
            int clientPort = 0;
            int originPort = TestServer.Start(TestOrigins.Route(r =>
            {
                Volatile.Write(ref clientPort, r.ClientPort);
                return (200, "", $"connection {r.Connection}");
            }));
            int proxy = HttpClientDnsTests.StartProxy(new HttpClientOptions
                { Host = "127.0.0.1", Port = (ushort)originPort, PoolSize = 1, MaxLifetimeMs = 500 });

            (_, string first) = Client.Get(proxy, "/first");
            Assert.Equal("200|connection 1", first);

            HttpClientIdleCloseTests.WaitForSocket(originPort, Volatile.Read(ref clientPort),
                state => state != HttpClientIdleCloseTests.Established, "the pool kept a connection past MaxLifetimeMs");

            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 2", second);
        });

        runner.Test("httpclient h1: a connection past MaxLifetimeMs is closed as soon as its request is done", () =>
        {
            // The sweep is held off for a minute, so only the release can retire it.
            int clientPort = 0;
            int originPort = TestServer.Start(TestOrigins.Route(r =>
            {
                Volatile.Write(ref clientPort, r.ClientPort);
                return (200, "", $"connection {r.Connection}");
            }, delayMs: 600));
            int proxy = HttpClientDnsTests.StartProxy(new HttpClientOptions
            {
                Host = "127.0.0.1", Port = (ushort)originPort, PoolSize = 1, MaxLifetimeMs = 300, SweepIntervalMs = 60_000,
            });

            (_, string first) = Client.Get(proxy, "/first");
            Assert.Equal("200|connection 1", first);

            HttpClientIdleCloseTests.WaitForSocket(originPort, Volatile.Read(ref clientPort),
                state => state != HttpClientIdleCloseTests.Established,
                "a connection past MaxLifetimeMs went back to the pool when its request finished");

            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 2", second);
        });
    }

    private static ServerConfig DualStackConfig() => new()
    {
        RecvBufferSize = 4096,
        RecvSlots = 256,
        DualStack = true,
        Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
    };

    // Connects nobody accepts, until the listener's queue is full and it drops whatever comes next.
    private static Socket[] FillAcceptQueue(IPEndPoint listener)
    {
        var queued = new Socket[3];
        for (int i = 0; i < queued.Length; i++)
        {
            queued[i] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { Blocking = false };
            try
            {
                queued[i].Connect(listener);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.WouldBlock)
            {
                // Left in SYN_SENT once the queue is full: exactly the point.
            }
        }
        Thread.Sleep(200);   // the first of them through the handshake, into the queue
        return queued;
    }
}
