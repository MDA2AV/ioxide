using System.Runtime.InteropServices;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// A pooled HTTP/1.1 connection that the origin closes while it sits idle - a keep-alive timeout,
/// the most ordinary way an upstream connection ends. Nothing reads a pooled socket between
/// requests, so the pool has to look before it writes the next request into one, and look rather
/// than resend: a request that reached the origin may already have been acted on.
/// </summary>
internal static class HttpClientIdleCloseTests
{
    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: a pooled connection the origin closed while idle is replaced, not written into", () =>
        {
            var origin = new NumberingOrigin(closeAfterResponse: true);
            int originPort = TestServer.Start((_, connection) => origin.ServeAsync(connection));
            int proxy = StartProxy(originPort, tls: null);

            (_, string first) = Client.Get(proxy, "/first");
            Assert.Equal("200|connection 1", first);

            WaitForFinAtClient(originPort, origin.LastClientPort);

            // Written into the closed socket, this failed as "peer closed mid-response" - an error
            // for a request the origin never saw.
            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 2", second);
        });

        runner.Test("httpclient h1: control - a pooled connection the origin keeps open is reused", () =>
        {
            // A check that discarded every idle connection would pass the test above by
            // reconnecting each time; only this one notices.
            var origin = new NumberingOrigin(closeAfterResponse: false);
            int originPort = TestServer.Start((_, connection) => origin.ServeAsync(connection));
            int proxy = StartProxy(originPort, tls: null);

            (_, string first) = Client.Get(proxy, "/first");
            (_, string second) = Client.Get(proxy, "/second");
            Assert.Equal("200|connection 1", first);
            Assert.Equal("200|connection 1", second);
        });

        runner.Test("httpclient h1: a pooled TLS connection the origin closed while idle is replaced, not written into", () =>
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

            WaitForFinAtClient(origin.Port, origin.LastClientPort);

            (_, string second) = Client.Get(proxy, "/second", timeoutMs: 20_000);
            Assert.Equal("200|hello over http/1.1", second);
        });
    }

    // One pooled connection, so the next request can only go to the connection under test. The
    // handler skips the request-less probe TestServer opens to see the proxy listening, which would
    // otherwise put a request nobody sent on that connection.
    private static int StartProxy(int originPort, TlsClientContext? tls)
        => TestServer.Start(TlsClientTests.ProxyHandler, onStart: reactor => HttpClientPool.Start(reactor,
            new HttpClientOptions { Host = "127.0.0.1", Port = (ushort)originPort, PoolSize = 1, Tls = tls }));

    // The pooled socket enters CLOSE_WAIT (08) once the origin's FIN has reached it. Waiting for
    // that, rather than sleeping, is what makes "closed while idle" true when the next request goes.
    private static void WaitForFinAtClient(int originPort, int clientPort)
    {
        string local = $":{clientPort:X4}";
        string remote = $":{originPort:X4}";
        long deadlineMs = Environment.TickCount64 + 10_000;

        while (!File.ReadLines("/proc/net/tcp").Skip(1)
                   .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                   .Any(fields => fields[1].EndsWith(local, StringComparison.Ordinal)
                                  && fields[2].EndsWith(remote, StringComparison.Ordinal)
                                  && fields[3] == "08"))
        {
            Assert.True(Environment.TickCount64 < deadlineMs,
                "the origin's FIN never reached the pooled connection, so this test proved nothing");
            Thread.Sleep(10);
        }
    }

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
