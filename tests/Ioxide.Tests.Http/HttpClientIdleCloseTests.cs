using System.Runtime.InteropServices;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// A pooled HTTP/1.1 connection that the origin closes while it sits idle - a keep-alive timeout,
/// the most ordinary way an upstream connection ends - and one the pool itself retires once it has
/// sat idle past <see cref="HttpClientOptions.IdleTimeoutMs"/>. Nothing reads a pooled socket
/// between requests, so the pool's sweep looks at its idle connections and replaces the ones that
/// are done, rather than any request paying to look, or resending one the origin may have acted on.
/// </summary>
internal static class HttpClientIdleCloseTests
{
    // Several sweeps at the default SweepIntervalMs.
    private const int SweepsMs = 3 * Reactor.TickMs;

    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: the sweep replaces a pooled connection the origin closed while idle", () =>
        {
            var origin = new NumberingOrigin(closeAfterResponse: true);
            int originPort = TestServer.Start((_, connection) => origin.ServeAsync(connection));
            int proxy = StartProxy(originPort, tls: null);

            (_, string first) = Client.Get(proxy, "/first");
            Assert.Equal("200|connection 1", first);

            int clientPort = origin.LastClientPort;
            WaitForSocket(originPort, clientPort, state => state == CloseWait,
                "the origin's FIN never reached the pooled connection, so this test proved nothing");
            WaitForSocket(originPort, clientPort, state => state is not (CloseWait or Established),
                "the pool kept a connection the origin had closed, for the next request to fail on");

            // Written into the closed socket, this failed as "peer closed mid-response" - an error
            // for a request the origin never saw.
            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 2", second);
        });

        runner.Test("httpclient h1: control - a pooled connection the origin keeps open is reused", () =>
        {
            // A sweep that discarded every idle connection would pass the test above by
            // reconnecting each time; only this one notices.
            var origin = new NumberingOrigin(closeAfterResponse: false);
            int originPort = TestServer.Start((_, connection) => origin.ServeAsync(connection));
            int proxy = StartProxy(originPort, tls: null);

            (_, string first) = Client.Get(proxy, "/first");
            Thread.Sleep(SweepsMs);
            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 1", first);
            Assert.Equal("200|connection 1", second);
        });

        runner.Test("httpclient h1: the sweep replaces a pooled TLS connection the origin closed while idle", () =>
        {
            // The close_notify in front of the FIN leaves the socket readable, so a check that
            // reads for end-of-stream finds data and calls the connection alive.
            using TlsTestOrigin origin = TlsTestOrigin.Start("http/1.1");
            origin.CloseAfterResponse = true;
            (string certPath, _) = TestCert.Ensure();

            int proxy = StartProxy(origin.Port, TlsClientContext.Create(new TlsClientOptions
            {
                ServerName = "localhost",
                AlpnProtocols = ["http/1.1"],
                CaFile = certPath,
            }));

            (_, string first) = Client.Get(proxy, "/first", timeoutMs: 20_000);
            Assert.Equal("200|hello over http/1.1", first);

            int clientPort = origin.LastClientPort;
            WaitForSocket(origin.Port, clientPort, state => state == CloseWait,
                "the origin's FIN never reached the pooled connection, so this test proved nothing");
            WaitForSocket(origin.Port, clientPort, state => state is not (CloseWait or Established),
                "the pool kept a TLS connection the origin had closed, for the next request to fail on");

            (_, string second) = Client.Get(proxy, "/second", timeoutMs: 20_000);
            Assert.Equal("200|hello over http/1.1", second);
        });

        runner.Test("httpclient h1: a pooled connection idle past IdleTimeoutMs is closed and reopened", () =>
        {
            var origin = new NumberingOrigin(closeAfterResponse: false);
            int originPort = TestServer.Start((_, connection) => origin.ServeAsync(connection));
            int proxy = StartProxy(originPort, tls: null, options => options with { IdleTimeoutMs = 500 });

            (_, string first) = Client.Get(proxy, "/first");
            Assert.Equal("200|connection 1", first);

            int clientPort = origin.LastClientPort;
            WaitForSocket(originPort, clientPort, state => state != Established,
                "the pool kept a connection idle past IdleTimeoutMs");

            // In the background, before any request asks for one.
            long deadlineMs = Environment.TickCount64 + 10_000;
            while (Sockets().Count(s => s.Remote == originPort && s.State == Established) == 0)
            {
                Assert.True(Environment.TickCount64 < deadlineMs, "the pool never reopened the connection it closed");
                Thread.Sleep(10);
            }

            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 2", second);
        });
    }

    // One pooled connection, so the next request can only go to the connection under test. The
    // handler skips the request-less probe TestServer opens to see the proxy listening, which would
    // otherwise put a request nobody sent on that connection.
    private static int StartProxy(int originPort, TlsClientContext? tls,
        Func<HttpClientOptions, HttpClientOptions>? tune = null)
    {
        var options = new HttpClientOptions { Host = "127.0.0.1", Port = (ushort)originPort, PoolSize = 1, Tls = tls };
        options = tune?.Invoke(options) ?? options;
        return TestServer.Start(TlsClientTests.ProxyHandler, onStart: reactor => HttpClientPool.Start(reactor, options));
    }

    private const string Established = "01";
    private const string CloseWait = "08";   // the origin's FIN has reached the socket

    // Waiting on the pooled socket's own state, by both of its ports, rather than sleeping, is what
    // makes "closed while idle" and "closed by the pool" true when the next request goes. Gone counts
    // as null.
    private static void WaitForSocket(int originPort, int clientPort, Func<string?, bool> condition, string failure)
    {
        long deadlineMs = Environment.TickCount64 + 10_000;
        while (!condition(Sockets().FirstOrDefault(s => s.Local == clientPort && s.Remote == originPort).State))
        {
            Assert.True(Environment.TickCount64 < deadlineMs, failure);
            Thread.Sleep(10);
        }
    }

    private static IEnumerable<(int Local, int Remote, string State)> Sockets()
        => File.ReadLines("/proc/net/tcp").Skip(1)
            .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Select(fields => (Port(fields[1]), Port(fields[2]), fields[3]));

    private static int Port(string address) => Convert.ToInt32(address[(address.IndexOf(':') + 1)..], 16);

    // Answers "connection N", numbering only the connections that carry a request (TestServer's
    // readiness probe carries none), and remembers the newest one's client port.
    private sealed class NumberingOrigin(bool closeAfterResponse)
    {
        private int _numbered;
        private int _lastClientPort;

        public int LastClientPort => Volatile.Read(ref _lastClientPort);

        public async Task ServeAsync(TcpConnection connection)
        {
            try
            {
                int number = 0;
                while (true)
                {
                    RecvSnapshot snapshot = await connection.ReadAsync();
                    if (snapshot.IsClosed)
                    {
                        return;
                    }
                    Wire.ReadPath(connection, snapshot);

                    if (number == 0)
                    {
                        number = Interlocked.Increment(ref _numbered);
                        Volatile.Write(ref _lastClientPort, PeerPort(connection.ClientFd));
                    }

                    Wire.Write(connection, 200, $"connection {number}");
                    await connection.FlushAsync();

                    if (closeAfterResponse)
                    {
                        return;   // DecRef sends the FIN an idle timeout would
                    }
                    connection.ResetRead();
                }
            }
            finally
            {
                connection.DecRef();
            }
        }
    }

    [DllImport("libc")]
    private static extern unsafe int getpeername(int fd, byte* address, uint* length);

    private static unsafe int PeerPort(int fd)
    {
        byte* address = stackalloc byte[16];   // sockaddr_in: sin_port, big-endian, at offset 2
        uint length = 16;
        getpeername(fd, address, &length);
        return (address[2] << 8) | address[3];
    }
}
