using System.Text;
using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="RingHttpClient"/>: requests by URL to any origin, a pool per origin opened on first use
/// and dropped once idle, https checked against the URL's host, and redirects followed as .NET's
/// HttpClient follows them.
/// </summary>
internal static class RingHttpClientTests
{
    public static void Register(Runner runner)
    {
        runner.Test("ring client: a URL's name is resolved, and sent as the request's host", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(r => (200, "", r.Headers.GetValueOrDefault("host", ""))));
            int client = StartClientHost();

            Assert.Equal($"200|localhost:{origin}", Get(client, "get", $"http://localhost:{origin}/x"));
        });

        runner.Test("ring client: a redirect to another origin is followed there", () =>
        {
            int final = TestServer.Start(TestOrigins.Route(r => (200, "", $"final at {r.Path}")));
            int first = TestServer.Start(TestOrigins.Route(_ => (302, $"location: http://localhost:{final}/final\r\n", "")));
            int client = StartClientHost();

            Assert.Equal("200|final at /final", Get(client, "get", $"http://localhost:{first}/go"));
        });

        runner.Test("ring client: a 303 after a POST is a GET for the relative Location, without the body", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(r => r.Path == "/post"
                ? (303, "location: /result\r\n", "")
                : (200, "", $"{r.Method} {r.Path} body={r.Body}")));
            int client = StartClientHost();

            Assert.Equal("200|GET /result body=", Get(client, "post", $"http://localhost:{origin}/post"));
        });

        runner.Test("ring client: a 307 keeps the method and the body", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(r => r.Path == "/keep"
                ? (307, "location: /echo\r\n", "")
                : (200, "", $"{r.Method} {r.Path} body={r.Body}")));
            int client = StartClientHost();

            Assert.Equal("200|POST /echo body=payload", Get(client, "post", $"http://localhost:{origin}/keep"));
        });

        runner.Test("ring client: past MaxRedirects the last redirect is the response", () =>
        {
            int hits = 0;
            int origin = TestServer.Start(TestOrigins.Route(_ =>
            {
                Interlocked.Increment(ref hits);
                return (302, "location: /loop\r\n", "again");
            }));
            int client = StartClientHost(new RingHttpClientOptions { MaxRedirects = 3 });

            Assert.Equal("302|again", Get(client, "get", $"http://localhost:{origin}/loop"));
            Assert.Equal(4, Volatile.Read(ref hits));
        });

        runner.Test("ring client: credentials follow a redirect within the origin, and not to another", () =>
        {
            static (int, string, string) Echo(OriginRequest r) => (200, "", $"auth={r.Headers.GetValueOrDefault("authorization", "none")}");
            int other = TestServer.Start(TestOrigins.Route(Echo));
            int origin = TestServer.Start(TestOrigins.Route(r => r.Path switch
            {
                "/same" => (302, "location: /echo\r\n", ""),
                "/away" => (302, $"location: http://localhost:{other}/echo\r\n", ""),
                _ => Echo(r),
            }));
            int client = StartClientHost();

            Assert.Equal("200|auth=secret", Get(client, "auth", $"http://localhost:{origin}/same"));
            Assert.Equal("200|auth=none", Get(client, "auth", $"http://localhost:{origin}/away"));
        });

        runner.Test("ring client: an origin whose connections have all gone idle is dropped", () =>
        {
            int origin = TestServer.Start(TestOrigins.Route(_ => (200, "", "ok")));
            int client = StartClientHost(new RingHttpClientOptions { Pool = new HttpClientOptions { IdleTimeoutMs = 300 } });

            Assert.Equal("200|ok", Get(client, "get", $"http://localhost:{origin}/"));
            Assert.Equal("1", Get(client, "origins", ""));

            long deadline = Environment.TickCount64 + 10_000;
            while (Get(client, "origins", "") != "0")
            {
                Assert.True(Environment.TickCount64 < deadline, "the idle origin's pool was never dropped");
                Thread.Sleep(50);
            }
        });

        runner.Test("ring client: an https URL is verified against its own host", () =>
        {
            using TlsTestOrigin origin = TlsTestOrigin.Start("http/1.1");
            (string certPath, _) = TestCert.Ensure();
            int client = StartClientHost(new RingHttpClientOptions
            {
                Tls = new TlsClientOptions { CaFile = certPath, AlpnProtocols = ["http/1.1"] },
            });

            Assert.Equal("200|hello over http/1.1", Get(client, "get", $"https://localhost:{origin.Port}/", timeoutMs: 20_000));
        });

        runner.Test("ring client: requests that find no connection open theirs in parallel", () =>
        {
            // Four requests to an origin that takes 400 ms each: one after another would take 1.6 s.
            int origin = TestServer.Start(TestOrigins.Route(_ => (200, "", "slow"), delayMs: 400));
            int client = StartClientHost();

            int elapsed = int.Parse(Get(client, "parallel", $"http://localhost:{origin}/"));
            Assert.True(elapsed < 1_200, $"four requests took {elapsed} ms, so their connections opened one at a time");
        });
    }

    private static int StartClientHost(RingHttpClientOptions? options = null)
        => TestServer.Start(ClientHost, onStart: reactor => RingHttpClient.Start(reactor, options));

    // The test thread asks the reactor's client to make a request: /<op>/<escaped url>.
    private static string Get(int client, string op, string url, int timeoutMs = 10_000)
    {
        (_, string body) = Client.Get(client, $"/{op}/{Uri.EscapeDataString(url)}", timeoutMs);
        return body;
    }

    private static async Task ClientHost(Reactor reactor, TcpConnection connection)
    {
        try
        {
            RingHttpClient http = reactor.GetService<RingHttpClient>()!;
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }

                string[] parts = Wire.ReadPath(connection, snapshot).Split('/', 3);
                string result;
                try
                {
                    result = await RunAsync(http, parts[1], parts.Length > 2 ? Uri.UnescapeDataString(parts[2]) : "");
                }
                catch (Exception e)
                {
                    result = $"599|{e.Message}";
                }

                Wire.Write(connection, 200, result);
                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            connection.DecRef();
        }
    }

    private static async Task<string> RunAsync(RingHttpClient http, string op, string url)
    {
        switch (op)
        {
            case "origins":
                return http.OriginCount.ToString();

            case "get":
            {
                using HttpClientResponse response = await http.GetAsync(url);
                return Describe(response);
            }

            case "post":
            {
                using HttpClientResponse response = await http.PostAsync(url, "payload"u8.ToArray());
                return Describe(response);
            }

            case "auth":
            {
                var request = new HttpClientRequest(HttpMethods.Get, "/");
                request.Headers.Add("authorization"u8.ToArray(), "secret"u8.ToArray());
                using HttpClientResponse response = await http.SendAsync(url, request);
                return Describe(response);
            }

            case "parallel":
            {
                long start = Native.MonotonicMs;
                HttpClientResponse[] responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => http.GetAsync(url).AsTask()));
                long elapsed = Native.MonotonicMs - start;
                foreach (HttpClientResponse response in responses)
                {
                    response.Dispose();
                }
                return elapsed.ToString();
            }

            default:
                return $"400|unknown op {op}";
        }
    }

    private static string Describe(HttpClientResponse response)
        => $"{response.Status}|{Encoding.Latin1.GetString(response.Body.Span)}";
}
