using System.Buffers;
using System.Net;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// A streamed HTTP/2 response whose handler throws, on both stacks. Once the headers are out, the
/// stream has to be reset: a streamed response has no content-length, so END_STREAM is all a client
/// has to tell a whole body from a truncated one. Before the headers, a 500 is still an answer.
/// </summary>
internal static class Http2StreamedFaultTests
{
    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp2" : "ioxide.http2";

            runner.Test($"h2 fault ({stack}): a handler that fails mid-body has its stream reset, and the connection serves on", () =>
            {
                int port = Start(ng);
                using HttpClient client = H2Client();

                string failed = Fetch(client, port, "/fail");
                Assert.True(failed.StartsWith("reset") && failed.Contains("INTERNAL_ERROR"),
                    $"expected RST_STREAM INTERNAL_ERROR, got \"{failed}\" - a truncated body passed off as whole");

                Assert.Equal("200: partial whole", Fetch(client, port, "/ok"));
            });

            runner.Test($"h2 fault ({stack}): a handler that fails before its headers answers 500", () =>
            {
                int port = Start(ng);
                using HttpClient client = H2Client();

                Assert.Equal("500: ", Fetch(client, port, "/fail-early"));
            });
        }
    }

    // "/fail-early" throws before the headers, "/fail" after part of the body, "/ok" finishes.
    private static int Start(bool native)
        => TestServer.Start(async (_, conn) =>
        {
            try
            {
                if (native)
                {
                    await new Nghttp2Connection(conn).RunAsync(async (request, writer) =>
                    {
                        string path = System.Text.Encoding.ASCII.GetString(request.Path.Span);
                        if (path == "/fail-early")
                        {
                            throw new InvalidOperationException("failed before the headers");
                        }
                        writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                        writer.Write("partial"u8);
                        await writer.FlushAsync();
                        if (path == "/fail")
                        {
                            throw new InvalidOperationException("the body failed");
                        }
                        writer.Write(" whole"u8);
                    });
                }
                else
                {
                    await new Http2Connection(conn).RunAsync(async (request, writer) =>
                    {
                        string path = System.Text.Encoding.ASCII.GetString(request.Path.Span);
                        if (path == "/fail-early")
                        {
                            throw new InvalidOperationException("failed before the headers");
                        }
                        writer.WriteHeaders(new Http2Response { Status = 200 });
                        writer.Write("partial"u8);
                        await writer.FlushAsync();
                        if (path == "/fail")
                        {
                            throw new InvalidOperationException("the body failed");
                        }
                        writer.Write(" whole"u8);
                    });
                }
            }
            finally
            {
                conn.DecRef();
            }
        });

    // Cleartext HTTP/2 with prior knowledge, one connection for every request of a test.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(10),
    };

    // "status: body" for a response read to its end; "reset: why" when the stream died under it.
    private static string Fetch(HttpClient client, int port, string path)
    {
        try
        {
            using HttpResponseMessage response = client.GetAsync($"http://127.0.0.1:{port}{path}").GetAwaiter().GetResult();
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return $"{(int)response.StatusCode}: {body}";
        }
        catch (HttpRequestException e)
        {
            return $"reset: {e.GetBaseException().Message}";
        }
    }
}
