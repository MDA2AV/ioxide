using System.Collections.Concurrent;
using System.Text;
using ioxide;
using ioxide.httpclient;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Request fields that would end their line early. The head is written byte for byte as the caller
/// gave it, so a CR or LF in the method, the target, a header name or a value, from a caller passing
/// on something it was sent, adds field lines or a whole second request. NUL goes with them, since
/// servers disagree about whether it ends a field.
/// </summary>
internal static class HttpClientRequestHeadTests
{
    public static void Register(Runner runner)
    {
        (string Case, string What, string Part)[] refused =
        [
            ("/value", "a CRLF in a header value", "header value"),
            ("/lf", "a bare LF in a header value", "header value"),
            ("/nul", "a NUL in a header value", "header value"),
            ("/name", "a CRLF in a header name", "header name"),
            ("/target", "a CRLF in the request target", "target"),
            ("/method", "a CRLF in the method", "method"),
        ];

        foreach ((string testCase, string what, string part) in refused)
        {
            runner.Test($"httpclient h1: refuses {what} before writing anything", () =>
            {
                var received = new ConcurrentQueue<string>();
                int origin = TestServer.Start((_, connection) => RecordingOrigin(connection, received));
                int proxy = TestServer.Start(ProxyHandler, onStart: reactor => HttpClientPool.Start(reactor,
                    new HttpClientOptions { Host = "127.0.0.1", Port = (ushort)origin, PoolSize = 1 }));

                (_, string refusal) = Client.Get(proxy, testCase);
                Assert.True(refusal.StartsWith("599|") && refusal.Contains($"{part} contains CR, LF or NUL"),
                    $"{what} should have been refused, got: {Escape(refusal)}, and the origin received: "
                    + Escape(string.Join(" | ", received)));

                // The control, through the same pool: a clean request, and the only one the origin saw.
                (_, string fine) = Client.Get(proxy, "/fine");
                Assert.Equal("200|ok", fine);
                Assert.True(received.Count == 1 && received.Single().Contains("\r\nx-test: fine\r\n"),
                    $"the origin should have seen only the clean request, saw: {Escape(string.Join(" | ", received))}");
            });
        }
    }

    // The request each case names; anything else is the clean one. The readiness probe TestServer
    // opens carries no request and is skipped, so the origin sees only what a test sent.
    private static async Task ProxyHandler(Reactor reactor, TcpConnection connection)
    {
        try
        {
            HttpClientPool upstream = reactor.GetService<HttpClientPool>()!;

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }

                string reply;
                try
                {
                    using HttpClientResponse response = await upstream.SendAsync(Request(Wire.ReadPath(connection, snapshot)));
                    reply = $"{response.Status}|{Encoding.ASCII.GetString(response.Body.Span)}";
                }
                catch (Exception e)
                {
                    reply = $"599|{e.Message}";
                }

                Wire.Write(connection, 200, reply);
                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            connection.DecRef();
        }
    }

    private static HttpClientRequest Request(string testCase)
    {
        HttpClientRequest request = testCase switch
        {
            "/target" => new HttpClientRequest(HttpMethods.Get, "/t HTTP/1.1\r\nx-injected: yes\r\n\r\nGET /second"),
            "/method" => new HttpClientRequest(Encoding.ASCII.GetBytes("GET /m HTTP/1.1\r\nx-injected: yes\r\n\r\nGET"), "/m"),
            _ => new HttpClientRequest(HttpMethods.Get, "/h"),
        };

        (string name, string value) = testCase switch
        {
            "/value" => ("x-test", "a\r\nx-injected: yes"),
            "/lf" => ("x-test", "a\nx-injected: yes"),
            "/nul" => ("x-test", "a\0b"),
            "/name" => ("x-test\r\nx-injected", "yes"),
            _ => ("x-test", "fine"),
        };
        request.Headers.Add(Encoding.ASCII.GetBytes(name), Encoding.ASCII.GetBytes(value));
        return request;
    }

    // Answers "ok" to whatever arrives and keeps the bytes, so a test can see exactly what was sent.
    private static async Task RecordingOrigin(TcpConnection connection, ConcurrentQueue<string> received)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                var bytes = new StringBuilder();
                while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        bytes.Append(Encoding.Latin1.GetString(item.AsSpan()));
                        connection.ReturnBuffer(in item);
                    }
                }

                if (bytes.Length > 0)
                {
                    received.Enqueue(bytes.ToString());
                    Wire.Write(connection, 200, "ok");
                    await connection.FlushAsync();
                }

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

    private static string Escape(string text) => text.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "\\0");
}
