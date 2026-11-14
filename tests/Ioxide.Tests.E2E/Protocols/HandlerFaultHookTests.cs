using System.Buffers;
using System.Net;
using System.Text;
using ioxide;
using ioxide.http2;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// <c>OnHandlerFault</c> on ioxide.http2 and nghttp3 (#572): a handler's fault reaches the host's hook,
/// with its request, from every place either stack catches one - and stderr no longer does, where a
/// host could neither route nor silence it and a full pipe would block the reactor. The stack still
/// ends the request as before, whatever the hook does. Without a hook the old stderr line stays,
/// which the controls pin.
/// </summary>
internal static class HandlerFaultHookTests
{
    private const string Http2Line = "[ioxide.http2] request handler faulted";
    private const string Nghttp3Line = "[ioxide.nghttp3] request handler faulted";

    public static void Register(Runner runner)
    {
        runner.Test("fault hook (ioxide.http2): a streamed handler's fault reaches the hook with its request, not stderr, and its stream is still reset", () =>
        {
            var faults = new Faults();
            using var stderr = new StderrCapture();
            int port = StartHttp2Streamed(new Http2Options { OnHandlerFault = faults.Add });
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, port, "/fail"));
            Assert.Equal("200: ok", Fetch(client, port, "/ok"));
            Assert.Equal("/fail: the body failed", faults.ToString());
            Assert.True(!stderr.Text.Contains(Http2Line), $"the fault reached stderr as well: [{stderr.Text}]");
        });

        runner.Test("fault hook (ioxide.http2): a buffered handler's fault reaches the hook with its request, before its task or after an await, and it is still answered 500", () =>
        {
            var faults = new Faults();
            int port = StartHttp2Buffered(new Http2Options { OnHandlerFault = faults.Add });
            using HttpClient client = H2Client();

            Assert.Equal("500: ", Fetch(client, port, "/before"));
            Assert.Equal("500: ", Fetch(client, port, "/after"));
            Assert.Equal("200: ok", Fetch(client, port, "/ok"));
            Assert.Equal("/before: the handler failed, /after: the handler failed", faults.ToString());
        });

        runner.Test("fault hook (ioxide.http2): a hook that throws does not stop the stream being reset, nor the connection serving on", () =>
        {
            var faults = new Faults();
            int port = StartHttp2Streamed(new Http2Options { OnHandlerFault = faults.AddThenThrow });
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, port, "/fail"));
            Assert.Equal("200: ok", Fetch(client, port, "/ok"));
            Assert.Equal("/fail: the body failed", faults.ToString());
        });

        runner.Test("control: fault hook (ioxide.http2): without one, a handler's fault is written to stderr, as before", () =>
        {
            using var stderr = new StderrCapture();
            int port = StartHttp2Streamed(new Http2Options());
            using HttpClient client = H2Client();

            Assert.Equal("reset 0x2", Fetch(client, port, "/fail"));
            Assert.True(stderr.Text.Contains($"{Http2Line}: the body failed"), $"stderr had: [{stderr.Text}]");
        });

        runner.Test("fault hook (nghttp3): a streamed handler's fault reaches the hook with its request, not stderr, before its task or after an await, and it is still answered 500", () =>
        {
            var faults = new Faults();
            using var stderr = new StderrCapture();
            using H3TestClient client = ConnectH3(conn => new Nghttp3Connection(conn, new Nghttp3Options { OnHandlerFault = faults.Add })
                .RunAsync((request, writer) => Fails(request, "/before") ? throw Failure() : StreamedAsync(request, writer)));

            AssertAnswered(client, "/before", 500, "");
            AssertAnswered(client, "/after", 500, "");
            AssertAnswered(client, "/ok", 200, "ok");
            Assert.Equal("/before: the handler failed, /after: the handler failed", faults.ToString());
            Assert.True(!stderr.Text.Contains(Nghttp3Line), $"the fault reached stderr as well: [{stderr.Text}]");
        });

        runner.Test("fault hook (nghttp3): a buffered handler's fault reaches the hook with its request, from either overload and on either side of its task, and it is still answered 500", () =>
        {
            var faults = new Faults();
            var options = new Nghttp3Options { OnHandlerFault = faults.Add };

            using (H3TestClient client = ConnectH3(conn => new Nghttp3Connection(conn, options)
                       .RunAsync(request => Fails(request, "/sync") ? throw Failure() : Nghttp3Response.Text("ok"))))
            {
                AssertAnswered(client, "/sync", 500, "");
            }

            using (H3TestClient client = ConnectH3(conn => new Nghttp3Connection(conn, options)
                       .RunAsync(request => Fails(request, "/before") ? throw Failure() : BufferedAsync(request))))
            {
                AssertAnswered(client, "/before", 500, "");
                AssertAnswered(client, "/after", 500, "");
                AssertAnswered(client, "/ok", 200, "ok");
            }

            Assert.Equal("/sync: the handler failed, /before: the handler failed, /after: the handler failed", faults.ToString());
        });

        runner.Test("fault hook (nghttp3): a hook that throws does not stop the request being answered, nor the connection serving on", () =>
        {
            var faults = new Faults();
            using H3TestClient client = ConnectH3(conn => new Nghttp3Connection(conn, new Nghttp3Options { OnHandlerFault = faults.AddThenThrow })
                .RunAsync((request, writer) => Fails(request, "/before") ? throw Failure() : StreamedAsync(request, writer)));

            AssertAnswered(client, "/before", 500, "");
            AssertAnswered(client, "/after", 500, "");
            AssertAnswered(client, "/ok", 200, "ok");
            Assert.Equal("/before: the handler failed, /after: the handler failed", faults.ToString());
        });

        runner.Test("fault hook: a fault thrown from the thread pool reaches the hook on the reactor, on either stack, streamed or buffered", () =>
        {
            // A handler leaves its reactor whenever a library awaits with ConfigureAwait(false), and the
            // hook is documented to run on the reactor whatever thread the handler threw on.
            var where = new Where();

            int streamed = TestServer.Start(async (reactor, conn) =>
            {
                try
                {
                    await new Http2Connection(conn, new Http2Options { OnHandlerFault = where.Note<Http2Request>("ioxide.http2 streamed", reactor) })
                        .RunAsync((_, _) => ThrowFromPool());
                }
                finally
                {
                    conn.DecRef();
                }
            });
            int buffered = TestServer.Start(async (reactor, conn) =>
            {
                try
                {
                    await new Http2Connection(conn, new Http2Options { OnHandlerFault = where.Note<Http2Request>("ioxide.http2 buffered", reactor) })
                        .RunAsync(_ => ThrowFromPool<Http2Response>());
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using (HttpClient client = H2Client())
            {
                Assert.Equal("500: ", Fetch(client, streamed, "/"));
                Assert.Equal("500: ", Fetch(client, buffered, "/"));
            }

            using (H3TestClient client = ConnectH3((reactor, conn) => new Nghttp3Connection(conn, new Nghttp3Options { OnHandlerFault = where.Note<Nghttp3Request>("nghttp3 streamed", reactor) })
                       .RunAsync((_, _) => ThrowFromPool())))
            {
                AssertAnswered(client, "/", 500, "");
            }
            using (H3TestClient client = ConnectH3((reactor, conn) => new Nghttp3Connection(conn, new Nghttp3Options { OnHandlerFault = where.Note<Nghttp3Request>("nghttp3 buffered", reactor) })
                       .RunAsync(_ => ThrowFromPool<Nghttp3Response>())))
            {
                AssertAnswered(client, "/", 500, "");
            }

            Assert.Equal("ioxide.http2 streamed on the reactor, ioxide.http2 buffered on the reactor, "
                         + "nghttp3 streamed on the reactor, nghttp3 buffered on the reactor", where.ToString());
        });

        runner.Test("control: fault hook (nghttp3): without one, a handler's fault is written to stderr, as before", () =>
        {
            using var stderr = new StderrCapture();
            using H3TestClient client = ConnectH3(conn => new Nghttp3Connection(conn)
                .RunAsync((request, writer) => Fails(request, "/before") ? throw Failure() : StreamedAsync(request, writer)));

            AssertAnswered(client, "/before", 500, "");
            Assert.True(stderr.Text.Contains($"{Nghttp3Line}: the handler failed"), $"stderr had: [{stderr.Text}]");
        });
    }

    /// <summary>
    /// What the hook was told, as "path: message" in the order it was told: the path is read from the
    /// request inside the hook, so it is the request whose handler threw, and still valid there.
    /// </summary>
    private sealed class Faults
    {
        private readonly List<string> _seen = [];

        public void Add(Http2Request request, Exception exception) => Note(request.Path, exception);

        public void Add(Nghttp3Request request, Exception exception) => Note(request.Path, exception);

        public void AddThenThrow(Http2Request request, Exception exception)
        {
            Add(request, exception);
            throw new InvalidOperationException("the hook failed");
        }

        public void AddThenThrow(Nghttp3Request request, Exception exception)
        {
            Add(request, exception);
            throw new InvalidOperationException("the hook failed");
        }

        private void Note(ReadOnlyMemory<byte> path, Exception exception)
        {
            lock (_seen)
            {
                _seen.Add($"{Encoding.ASCII.GetString(path.Span)}: {exception.Message}");
            }
        }

        public override string ToString()
        {
            lock (_seen)
            {
                return string.Join(", ", _seen);
            }
        }
    }

    /// <summary>Everything written to stderr while it is held, from any thread; the original is back once it is disposed.</summary>
    private sealed class StderrCapture : IDisposable
    {
        private readonly TextWriter _original = Console.Error;
        private readonly StringWriter _captured = new();

        public StderrCapture() => Console.SetError(_captured);

        public string Text => _captured.ToString();

        public void Dispose() => Console.SetError(_original);
    }

    /// <summary>Which thread each hook ran on, in the order the hooks ran.</summary>
    private sealed class Where
    {
        private readonly List<string> _seen = [];

        public Action<T, Exception> Note<T>(string stack, Reactor reactor) => (_, _) =>
        {
            lock (_seen)
            {
                _seen.Add($"{stack} {(reactor.OnReactorThread ? "on the reactor" : "off it")}");
            }
        };

        public override string ToString()
        {
            lock (_seen)
            {
                return string.Join(", ", _seen);
            }
        }
    }

    // Leaves the reactor, as an await on anything another thread completes does, and throws from there.
    private static async ValueTask ThrowFromPool()
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        throw Failure();
    }

    private static async ValueTask<T> ThrowFromPool<T>()
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        throw Failure();
    }

    private static bool Fails(Http2Request request, string path) => Encoding.ASCII.GetString(request.Path.Span) == path;

    private static bool Fails(Nghttp3Request request, string path) => Encoding.ASCII.GetString(request.Path.Span) == path;

    private static InvalidOperationException Failure() => new("the handler failed");

    // ---- HTTP/2 -------------------------------------------------------------------------------

    // "/fail" throws after its headers and part of its body; anything else is answered "ok".
    private static int StartHttp2Streamed(Http2Options options)
        => TestServer.Start(async (_, conn) =>
        {
            try
            {
                await new Http2Connection(conn, options).RunAsync(async (request, writer) =>
                {
                    writer.WriteHeaders(new Http2Response { Status = 200 });
                    if (Fails(request, "/fail"))
                    {
                        writer.Write("partial"u8);
                        await writer.FlushAsync();
                        throw new InvalidOperationException("the body failed");
                    }
                    writer.Write("ok"u8);
                });
            }
            finally
            {
                conn.DecRef();
            }
        });

    // "/before" throws before there is a task, "/after" from a later pass; anything else is answered "ok".
    private static int StartHttp2Buffered(Http2Options options)
        => TestServer.Start(async (_, conn) =>
        {
            try
            {
                await new Http2Connection(conn, options).RunAsync(request => Fails(request, "/before") ? throw Failure() : AfterAwait(request));
            }
            finally
            {
                conn.DecRef();
            }

            static async ValueTask<Http2Response> AfterAwait(Http2Request request)
            {
                bool fails = Fails(request, "/after");
                await TestServer.LaterPass();
                return fails ? throw Failure() : Http2Response.Text("ok");
            }
        });

    // Cleartext HTTP/2 with prior knowledge, one connection for every request of a test.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(10),
    };

    // "status: body" for a response read to its end, "reset 0xN" for one whose stream was reset under it.
    private static string Fetch(HttpClient client, int port, string path)
    {
        try
        {
            using HttpResponseMessage response = client.GetAsync($"http://127.0.0.1:{port}{path}").GetAwaiter().GetResult();
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return $"{(int)response.StatusCode}: {body}";
        }
        catch (Exception caught)
        {
            for (Exception? e = caught; e is not null; e = e.InnerException)
            {
                if (e is HttpProtocolException protocol)
                {
                    return $"reset 0x{protocol.ErrorCode:x}";
                }
            }
            return caught is TaskCanceledException ? "no answer in time" : $"failed: {caught.GetBaseException().Message}";
        }
    }

    // ---- HTTP/3 -------------------------------------------------------------------------------

    private static H3TestClient ConnectH3(Func<QuicConnection, Task> serve) => ConnectH3((_, conn) => serve(conn));

    private static H3TestClient ConnectH3(Func<Reactor, QuicConnection, Task> serve)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: serve);

        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5_000), "handshake did not complete");
        return client;
    }

    // "/after" throws from a later pass, before its headers; anything else is answered "ok".
    private static async ValueTask StreamedAsync(Nghttp3Request request, Nghttp3ResponseWriter writer)
    {
        bool fails = Fails(request, "/after");
        await TestServer.LaterPass();
        if (fails)
        {
            throw Failure();
        }
        writer.WriteHeaders(new Nghttp3Response { Status = 200 });
        writer.Write("ok"u8);
    }

    private static async ValueTask<Nghttp3Response> BufferedAsync(Nghttp3Request request)
    {
        bool fails = Fails(request, "/after");
        await TestServer.LaterPass();
        return fails ? throw Failure() : Nghttp3Response.Text("ok");
    }

    private static void AssertAnswered(H3TestClient client, string path, int status, string body)
    {
        (int answered, string text) = client.Get(path, timeoutMs: 5_000);
        Assert.True(answered == status && text == body,
            $"{path} got {(answered < 0 ? "no answer" : $"{answered} [{text}]")}, not {status} [{body}]"
            + (client.PeerClosed ? ": the server closed the connection" : ""));
    }
}
