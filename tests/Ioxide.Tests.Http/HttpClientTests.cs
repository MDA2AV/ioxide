using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// The ring-native HTTP/1.1 client, exercised the way it is meant to be used: a PROXY. One ioxide
/// server is the origin, a second one handles inbound requests by calling the origin through
/// ioxide.httpclient from inside its handler, and the test drives the proxy with a plain socket.
/// That covers the whole chain - pool on the reactor, connect/send/recv on the ring, response
/// parsing - and proves the client is usable from where handlers actually live.
///
/// The origin is a raw handler so each test can hand back an exact byte sequence (chunked, 204,
/// connection: close, oversized) that a well-behaved server would never be asked to produce.
/// </summary>
internal static class HttpClientTests
{
    // 9 MiB: comfortably past the 8 MiB ceiling that HttpClientResponse used to apply by default.
    private const int HugeBodyBytes = 9 * 1024 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("httpclient h1: GET through a proxy handler (pool on the reactor)", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (int status, string body) = Client.Get(proxy, "/plain");
            Assert.Equal(200, status);
            Assert.Equal("200|hello from origin", body);
        });

        runner.Test("httpclient h1: dead origin fails inside the acquire budget, no connect storm", () =>
        {
            // A refused connect completes in microseconds and wakes the waiter. When the acquire
            // timeout was armed per ATTEMPT rather than per acquire, every failure re-armed it, so
            // the deadline never arrived: the pool reopened at syscall speed (~94k connects in 6 s
            // on one reactor), the caller never saw an error, and the request hung forever.
            // The call must now fail within the acquire budget, and the handler must see it.
            int proxy = StartProxy(originPort: TestServer.DeadPort(), poolSize: 1, acquireTimeoutMs: 1000);

            long start = Environment.TickCount64;
            (int status, string body) = Client.Get(proxy, "/plain", timeoutMs: 15_000);
            long elapsed = Environment.TickCount64 - start;

            Assert.Equal(200, status);   // the proxy handler answers 200 and reports upstream in the body
            Assert.True(body.StartsWith("599|"), $"expected the upstream call to throw, got: {body}");
            Assert.True(elapsed < 6_000, $"took {elapsed} ms - the acquire timeout did not bound the retry loop");
        });

        runner.Test("httpclient h1: a disposed pool closes its connections and stays closed", () =>
        {
            // The pool's Sweep runs off a reactor ticker, and AddTicker has no removal API. Before
            // this the pool had no Dispose at all, so its connections were held for the rest of the
            // reactor's life and the ticker reopened any that died - forever.
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin, poolSize: 2);

            (_, string warm) = Client.Get(proxy, "/plain");
            Assert.Equal("200|hello from origin", warm);

            Client.Get(proxy, "/dispose");

            // Settled state, not the instant after: a connect already in flight cannot be
            // cancelled, so it lands and is discarded on arrival. The sleep also spans several
            // ticker intervals (250 ms each), which is where replenishment would show up.
            Thread.Sleep(1200);

            (_, string later) = Client.Get(proxy, "/poolstats");
            Assert.Equal("live=0", later);

            // And a request against the disposed pool fails cleanly rather than hanging out the
            // acquire budget waiting for connections that are never coming.
            long start = Environment.TickCount64;
            (_, string refused) = Client.Get(proxy, "/plain");
            long elapsed = Environment.TickCount64 - start;

            Assert.True(refused.StartsWith("599|"), $"expected a failure, got: {refused}");
            Assert.True(refused.Contains("disposed"), $"should say why, got: {refused}");
            Assert.True(elapsed < 2_000, $"took {elapsed} ms - should fail immediately, not on the deadline");
        });

        runner.Test("httpclient h1: keep-alive reuses connections across requests", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin, poolSize: 2);

            // Twenty sequential requests over two pooled connections: every one must succeed, and
            // the pool must still report exactly two (no churn, no leak).
            for (int i = 0; i < 20; i++)
            {
                (int status, string body) = Client.Get(proxy, "/plain");
                Assert.Equal(200, status);
                Assert.Equal("200|hello from origin", body);
            }

            (_, string stats) = Client.Get(proxy, "/poolstats");
            Assert.Equal("live=2", stats);   // /poolstats answers directly, no upstream hop
        });

        runner.Test("httpclient h1: chunked response is de-chunked", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (int status, string body) = Client.Get(proxy, "/chunked");
            Assert.Equal(200, status);
            Assert.Equal("200|chunk-one chunk-two chunk-three", body);
        });

        runner.Test("httpclient h1: 204 and HEAD-style bodyless responses", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (int status, string body) = Client.Get(proxy, "/nocontent");
            Assert.Equal(200, status);
            Assert.Equal("204|", body);
        });

        runner.Test("httpclient h1: connection close is honoured and the pool replaces the socket", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin, poolSize: 1);

            // The origin closes after each of these; the pool must notice and reconnect, so a
            // second request still works.
            (int first, string firstBody) = Client.Get(proxy, "/closeme");
            Assert.Equal(200, first);
            Assert.Equal("200|closing now", firstBody);

            (int second, string secondBody) = Client.Get(proxy, "/closeme");
            Assert.Equal(200, second);
            Assert.Equal("200|closing now", secondBody);
        });

        runner.Test("httpclient h1: response larger than the receive buffer grows correctly", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            // 100 KB body against a deliberately small 4 KB receive buffer.
            (int status, string body) = Client.Get(proxy, "/big");
            Assert.Equal(200, status);
            Assert.Equal($"200|{100_000}", body);
        });

        runner.Test("httpclient h1: a response above the arena's old default ceiling is intact", () =>
        {
            // HttpClientResponse is shared by h1, h2 and h3, and h1 bounds responses a DIFFERENT
            // way - Content-Length checked before allocating, never consulting Overflowed. Giving
            // the shared arena a default ceiling therefore did not protect h1, it truncated it:
            // parsing completed while the arena silently dropped bytes, and the caller got 200
            // with empty headers and an empty body. Raising h1's own documented limit has to work.
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin, maxResponseBytes: 32 * 1024 * 1024);

            (int status, string body) = Client.Get(proxy, "/huge", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.Equal($"200|{HugeBodyBytes}", body);
        });

        runner.Test("httpclient h1: a response past MaxResponseBytes still fails loudly", () =>
        {
            // The other half: h1's own limit must keep rejecting, so the fix above did not simply
            // remove the bound.
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin, maxResponseBytes: 64 * 1024);

            (int status, string body) = Client.Get(proxy, "/huge", timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.True(body.StartsWith("599|"), $"expected the request to fail, got: {body[..Math.Min(60, body.Length)]}");
            Assert.True(body.Contains("MaxResponseBytes"), $"should name the limit, got: {body[..Math.Min(60, body.Length)]}");
        });

        runner.Test("httpclient h1: POST body reaches the origin intact", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (int status, string body) = Client.Get(proxy, "/post");
            Assert.Equal(200, status);
            Assert.Equal("200|got 11 bytes", body);
        });

        runner.Test("httpclient h1: response headers are parsed and lowercased", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            (int status, string body) = Client.Get(proxy, "/headers");
            Assert.Equal(200, status);
            Assert.Equal("200|x-demo=Value-Kept", body);
        });

        RegisterHardening(runner);
    }

    // Hostile responses. Before the parser was Glyph11's these were accepted: the old hand-rolled
    // head parser skipped any line it could not read, took the LAST Content-Length it saw, and had
    // no opinion on Transfer-Encoding arriving alongside one. Each of these is a desync waiting for
    // the next request on the same connection.
    private static void RegisterHardening(Runner runner)
    {
        (string Path, string What)[] rejected =
        [
            ("/smuggle",    "Transfer-Encoding and Content-Length together"),
            ("/twolengths", "two conflicting Content-Length headers"),
            ("/obsfold",    "an obs-fold continuation line"),
            ("/barelf",     "a bare LF inside a header line"),
        ];

        foreach ((string path, string what) in rejected)
        {
            runner.Test($"httpclient h1: refuses {what}", () =>
            {
                int origin = TestServer.Start(OriginHandler);
                int proxy = StartProxy(origin);

                (int status, string body) = Client.Get(proxy, path);

                // The proxy handler answers 200 and reports the upstream outcome in the body; 599
                // is how it reports that the client threw rather than returning a response.
                Assert.Equal(200, status);
                Assert.True(body.StartsWith("599|"),
                    $"{what} should have been refused, got: {body[..Math.Min(80, body.Length)]}");
            });
        }

        runner.Test("httpclient h1: a HEAD response's Content-Length does not frame a body", () =>
        {
            int origin = TestServer.Start(OriginHandler);
            int proxy = StartProxy(origin);

            // The proxy forwards this as a real HEAD. Content-Length: 1024 with no body follows,
            // so framing on it would block until the origin sent 1024 bytes it is never going to
            // send - hanging until the test's timeout is the failure mode being ruled out.
            (int status, string body) = Client.Get(proxy, "/head", timeoutMs: 10_000);

            Assert.Equal(200, status);
            Assert.Equal("200|", body);
        });
    }

    // Start a proxy server: its handler calls the origin through the ring-native client and writes
    // "<upstream status>|<detail>" back. The pool is created in OnStart, so it belongs to this
    // reactor's ring - the documented way to use it.
    internal static int StartProxy(int originPort, int poolSize = 4, int? acquireTimeoutMs = null,
        int? maxResponseBytes = null)
    {
        var options = new HttpClientOptions
        {
            Host = "127.0.0.1",
            Port = (ushort)originPort,
            PoolSize = poolSize,
            ReceiveBufferSize = 4096,   // small on purpose: /big must exercise buffer growth
        };

        if (maxResponseBytes is { } max)
        {
            options = options with { MaxResponseBytes = max };
        }

        if (acquireTimeoutMs is { } timeout)
        {
            options = options with { AcquireTimeoutMs = timeout };
        }

        return TestServer.StartConfigured(
            ProxyHandler,
            new ServerConfig
            {
                RecvBufferSize = 4096,
                RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 256 * 1024, PoolMax = 8, RecvQueueEntries = 64 },
            },
            onStart: reactor => HttpClientPool.Start(reactor, options)).Port;
    }

    private static async Task ProxyHandler(Reactor reactor, TcpConnection connection)
    {
        try
        {
            HttpClientPool upstream = reactor.GetService<HttpClientPool>()!;

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                string path = Wire.ReadPath(connection, snapshot);

                if (path == "/poolstats")
                {
                    Wire.Write(connection, 200, $"live={upstream.ConnectionCount}");
                }
                else if (path == "/dispose")
                {
                    upstream.Dispose();
                    Wire.Write(connection, 200, $"live={upstream.ConnectionCount}");
                }
                else
                {
                    string detail;
                    int upstreamStatus;
                    try
                    {
                        using HttpClientResponse response = path switch
                        {
                            "/post" => await upstream.PostAsync("/post"u8.ToArray(), "hello world"u8.ToArray()),
                            // Forwarded as a real HEAD so the response's Content-Length has a
                            // request method to be interpreted against.
                            "/head" => await upstream.SendAsync(
                                new HttpClientRequest(HttpMethods.Head, "/head")),
                            _ => await upstream.GetAsync(path),
                        };

                        upstreamStatus = response.Status;
                        detail = path switch
                        {
                            "/big" or "/huge" => response.Body.Length.ToString(),
                            "/headers" => response.TryGetHeader("x-demo"u8, out ReadOnlyMemory<byte> demo)
                                ? $"x-demo={Encoding.ASCII.GetString(demo.Span)}"
                                : "x-demo=MISSING",
                            _ => Encoding.ASCII.GetString(response.Body.Span),
                        };
                    }
                    catch (Exception e)
                    {
                        upstreamStatus = 599;
                        detail = e.Message;
                    }

                    Wire.Write(connection, 200, $"{upstreamStatus}|{detail}");
                }

                await connection.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }
                connection.ResetRead();
            }
        }
        finally
        {
            connection.DecRef();
        }
    }

    // Content-length taken from the body, so the origin never promises bytes it won't send.
    private static void WriteFixed(TcpConnection connection, string body, string extraHeaders = "")
        => connection.Write(Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\n{extraHeaders}Content-Length: {body.Length}\r\n\r\n{body}"));

    // The origin: raw byte responses, so the client meets shapes a normal handler wouldn't emit.
    private static async Task OriginHandler(Reactor reactor, TcpConnection connection)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                string path = Wire.ReadPath(connection, snapshot);

                switch (path)
                {
                    case "/chunked":
                        connection.Write(Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                            + "9\r\nchunk-one\r\n"
                            + "A\r\n chunk-two\r\n"
                            + "C\r\n chunk-three\r\n"
                            + "0\r\n\r\n"));
                        break;

                    case "/nocontent":
                        connection.Write("HTTP/1.1 204 No Content\r\n\r\n"u8);
                        break;

                    // ---- Responses a hardened client has to refuse ----

                    // Both framings at once: whoever reads this next disagrees with us about where
                    // it ends, and the remainder becomes the head of the following response.
                    case "/smuggle":
                        connection.Write(Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n"
                            + "0\r\n\r\nSTOLEN"));
                        break;

                    // Two Content-Lengths that disagree - same desync, spelled differently.
                    case "/twolengths":
                        connection.Write(Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 11\r\n\r\nabcdefghijk"));
                        break;

                    // obs-fold: a continuation line, deprecated by RFC 9112 §5.2 precisely because
                    // intermediaries disagree about how to unfold it.
                    case "/obsfold":
                        connection.Write(Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Split: one\r\n  two\r\n\r\nhi"));
                        break;

                    // A bare LF INSIDE a header line, in a block that is otherwise properly
                    // terminated. Whether this splits one header or two is exactly what
                    // implementations disagree about, which is the vector. (A block with no CRLFCRLF
                    // at all is a different thing - incomplete rather than invalid - so the client
                    // waits for more bytes there, as it should.)
                    case "/barelf":
                        connection.Write(Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nX-Bad: one\ntwo\r\nContent-Length: 2\r\n\r\nhi"));
                        break;

                    // A HEAD response: Content-Length describes the body a GET would have
                    // returned, and there is no body. A client that frames on it reads the NEXT
                    // response as this one's content.
                    case "/head":
                        connection.Write("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"u8);
                        break;

                    case "/closeme":
                        WriteFixed(connection, "closing now", extraHeaders: "Connection: close\r\n");
                        break;

                    case "/big":
                        connection.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Length: {100_000}\r\n\r\n" + new string('x', 100_000)));
                        break;

                    // Past the 8 MiB that used to be the shared response arena's default ceiling,
                    // so a client raising MaxResponseBytes above it has something to prove itself
                    // against.
                    case "/huge":
                        connection.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Length: {HugeBodyBytes}\r\n\r\n"
                            + new string('h', HugeBodyBytes)));
                        break;

                    case "/post":
                        WriteFixed(connection, "got 11 bytes");
                        break;

                    case "/headers":
                        WriteFixed(connection, "ok", extraHeaders: "X-Demo: Value-Kept\r\n");
                        break;

                    default:
                        WriteFixed(connection, "hello from origin");
                        break;
                }

                await connection.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
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
