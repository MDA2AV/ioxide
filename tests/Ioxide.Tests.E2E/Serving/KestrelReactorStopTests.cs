using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Ioxide.Tests;

/// <summary>
/// An ASP.NET app on the transport whose reactor stops under a live connection, as the listener's dispose and a
/// reactor fault both stop it. What Kestrel and the app wait on still arrives, now on the thread pool, and the
/// connection's pumps leave alone what the reactor's teardown freed.
/// </summary>
internal static class KestrelReactorStopTests
{
    private const int InboundPauseBytes = 1024 * 1024;   // HopDuplexPipe's inbound pause mark

    private enum Tls { None, Boring, KernelTx }

    public static void Register(Runner runner)
    {
        foreach ((Tls tls, string name) in new[] { (Tls.None, "plaintext"), (Tls.Boring, "TLS"), (Tls.KernelTx, "kTLS TX") })
        {
            runner.Test($"kestrel: a keep-alive connection whose reactor stops ends, and the host then stops at once: {name}",
                () => KeepAlive(tls), skip: tls == Tls.KernelTx && !Sidecars.KtlsAvailable());
        }

        runner.Test("kestrel: a request body held back when its reactor stops is aborted once the app reads it, not left waiting", Backpressure);

        runner.Test("kestrel: an app streaming a response when its reactor stops hears the request aborted, rather than writing on into nothing", Streaming);

        runner.Test("kestrel: a connection Kestrel gave up on at shutdown finishes its dispose once the app returns", Outlived);
    }

    private static void KeepAlive(Tls tls)
    {
        using var host = new Host(tls, context =>
        {
            context.Response.ContentLength = 2;
            return context.Response.WriteAsync("ok");
        });

        using Socket client = host.Connect();
        using Stream stream = host.Open(client);
        Client.Send(stream, "/");
        Assert.Equal(200, Client.ReadResponse(stream).Status);

        host.Connection.Reactor.Stop();

        Assert.True(host.Ended.Wait(2_000), "Kestrel never saw the connection end after its reactor stopped");
        Assert.True(host.Connection.Completion.Wait(2_000), "the transport never finished disposing the connection");

        long stopMs = host.Stop(budgetMs: 3_000);
        Assert.True(stopMs < 1_000, $"the host took {stopMs} ms to stop, with no connection left to wait for");
    }

    private static void Backpressure()
    {
        const int bodyLength = InboundPauseBytes + 256 * 1024;   // the rest waits in the connection's queue
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var outcome = new TaskCompletionSource<(long Read, long Wrong, Exception? Error)>(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new Host(Tls.None, async context =>
        {
            entered.TrySetResult();
            await release.Task;

            long read = 0, wrong = 0;
            var buffer = new byte[64 * 1024];
            try
            {
                int n;
                while ((n = await context.Request.Body.ReadAsync(buffer)) > 0)
                {
                    for (int i = 0; i < n; i++)
                    {
                        wrong += buffer[i] == Pattern(read + i) ? 0 : 1;
                    }
                    read += n;
                }
                outcome.TrySetResult((read, wrong, null));
            }
            catch (Exception e)
            {
                outcome.TrySetResult((read, wrong, e));
            }
        });

        HashSet<TcpSockets.Connection> earlier = TcpSockets.EstablishedTo(host.Port);
        using Socket client = host.Connect();
        TcpSockets.Connection sent = TcpSockets.WaitForNew(host.Port, earlier, 1).Single();
        var received = new TcpSockets.Connection(sent.Remote, sent.Local);

        client.Send(Encoding.ASCII.GetBytes($"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {bodyLength}\r\n\r\n"));
        var body = new byte[bodyLength];
        for (int i = 0; i < bodyLength; i++)
        {
            body[i] = Pattern(i);
        }
        client.Send(body);
        Assert.True(entered.Task.Wait(5_000), "the request never reached the app");

        // Every byte taken from the socket and handed to the connection: the pipe paused at its mark, the rest queued.
        Reactor reactor = host.Connection.Reactor;
        WaitFor(() => TcpSockets.Queues(sent) is (0, _) && TcpSockets.Queues(received) is (_, 0), "the body never left the sockets");
        Assert.True(Running(reactor), "the reactor stopped before the test stopped it");

        reactor.Stop();
        WaitFor(() => !Running(reactor), "the reactor never stopped");
        release.TrySetResult();

        Assert.True(outcome.Task.Wait(5_000), "the app's read of the body never ended after its reactor stopped");
        (long read, long wrong, Exception? error) = outcome.Task.Result;
        Assert.True(error is not null && Chain(error).Any(e => e is ConnectionAbortedException),
            $"the read ended {(error is null ? "cleanly" : $"with {error.GetType().Name}: {error.Message}")} after {read} of {bodyLength} bytes, not aborted");
        Assert.True(read >= InboundPauseBytes / 2 && read < bodyLength && wrong == 0,
            $"the app read {read} of {bodyLength} bytes before the abort, {wrong} of them wrong");
    }

    private static void Streaming()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var outcome = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new Host(Tls.None, async context =>
        {
            await context.Response.WriteAsync("started\n");
            await context.Response.Body.FlushAsync();
            started.TrySetResult();
            await stopped.Task;

            var chunk = new byte[16 * 1024];
            int writes = 0;
            try
            {
                for (var clock = Stopwatch.StartNew(); clock.ElapsedMilliseconds < 2_000; writes++)
                {
                    if (context.RequestAborted.IsCancellationRequested)
                    {
                        outcome.TrySetResult(null);
                        return;
                    }
                    await context.Response.Body.WriteAsync(chunk);
                    await context.Response.Body.FlushAsync();
                }
                outcome.TrySetResult($"the app wrote {writes} chunks over 2 s after its reactor stopped, and the request was never aborted");
            }
            catch (Exception e)
            {
                // Told by its write instead, if it is one of these.
                outcome.TrySetResult(e is IOException or OperationCanceledException ? null : $"the app's write threw {e.GetType().Name}: {e.Message}");
            }
        });

        using Socket client = host.Connect();
        using Stream stream = host.Open(client);
        Client.Send(stream, "/");
        Assert.True(started.Task.Wait(5_000), "the response never started");

        Reactor reactor = host.Connection.Reactor;
        reactor.Stop();
        WaitFor(() => !Running(reactor), "the reactor never stopped");
        stopped.TrySetResult();

        Assert.True(outcome.Task.Wait(5_000), "the app's response never finished after its reactor stopped");
        Assert.True(outcome.Task.Result is null, outcome.Task.Result ?? "");
    }

    private static void Outlived()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new Host(Tls.None, async context =>
        {
            entered.TrySetResult();
            await release.Task;   // past RequestAborted, and past the host's shutdown
            try
            {
                context.Response.ContentLength = 2;
                await context.Response.WriteAsync("ok");
            }
            finally
            {
                answered.TrySetResult();
            }
        });

        using Socket client = host.Connect();
        using Stream stream = host.Open(client);
        Client.Send(stream, "/");
        Assert.True(entered.Task.Wait(5_000), "the request never reached the app");

        // Kestrel waits out the budget and its abort, gives up on the connection, and disposes the listener: that stops the reactor.
        Reactor reactor = host.Connection.Reactor;
        host.Stop(budgetMs: 200);
        Assert.True(!Running(reactor), "the host stopped and left its reactor running");
        release.TrySetResult();

        Assert.True(answered.Task.Wait(5_000), "the app never returned");
        Assert.True(host.Ended.Wait(5_000), "Kestrel never finished with the connection once the app returned");
        Assert.True(host.Connection.Completion.Wait(3_000), "the transport never finished disposing the connection once the app returned");
    }

    private static byte Pattern(long i) => (byte)(i % 251);

    private static IEnumerable<Exception> Chain(Exception? e)
    {
        for (; e is not null; e = e.InnerException)
        {
            yield return e;
        }
    }

    private static void WaitFor(Func<bool> condition, string failure)
    {
        for (var clock = Stopwatch.StartNew(); !condition(); Thread.Sleep(10))
        {
            Assert.True(clock.ElapsedMilliseconds < 10_000, failure);
        }
    }

    // Whether a switch to the reactor resumed on it, after a pass of its loop: once it has stopped, the switch throws.
    private static bool Running(Reactor reactor)
    {
        Task<bool> hop = Switch();
        Assert.True(hop.Wait(5_000), "a switch to the reactor never resumed");
        return hop.Result;

        async Task<bool> Switch()
        {
            try
            {
                await new ReactorSwitch(reactor);
                return true;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }
    }

    // An app on one reactor, with a connection middleware that hands over the transport's connection and says when
    // Kestrel is done with it.
    private sealed class Host : IDisposable
    {
        private readonly WebApplication _app;
        private readonly TaskCompletionSource<IoxideConnectionContext> _connection = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly bool _tls;
        private bool _stopped;

        public Host(Tls tls, RequestDelegate handler)
        {
            _tls = tls != Tls.None;
            Port = TestServer.NextPort();
            var listening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, Port, listen => listen.Use(next => async connection =>
            {
                _connection.TrySetResult((IoxideConnectionContext)connection);
                try
                {
                    await next(connection);
                }
                finally
                {
                    _ended.TrySetResult();
                }
            })));
            builder.WebHost.UseIoxide(o =>
            {
                o.ReactorCount = 1;
                o.OnReactorStart = _ => listening.TrySetResult();
                if (_tls)
                {
                    (string certPath, string keyPath) = TestCert.Ensure();
                    o.UseTls(certPath, keyPath, [Port]);
                    o.Tls!.KernelTx = tls == Tls.KernelTx;
                }
            });

            _app = builder.Build();
            _app.Run(handler);
            _app.StartAsync().GetAwaiter().GetResult();
            Assert.True(listening.Task.Wait(5_000), "the reactor never came up");
        }

        public int Port { get; }

        public IoxideConnectionContext Connection
        {
            get
            {
                Assert.True(_connection.Task.Wait(5_000), "Kestrel never took the connection");
                return _connection.Task.Result;
            }
        }

        public Task Ended => _ended.Task;

        public Socket Connect()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5_000 };
            socket.Connect(IPAddress.Loopback, Port);
            return socket;
        }

        public Stream Open(Socket socket)
        {
            var stream = new NetworkStream(socket, ownsSocket: false);
            if (!_tls)
            {
                return stream;
            }

            var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient("localhost");
            return ssl;
        }

        // How long the host took, with a shutdown budget of budgetMs.
        public long Stop(int budgetMs)
        {
            if (_stopped)
            {
                return 0;
            }
            _stopped = true;

            var clock = Stopwatch.StartNew();
            using (var budget = new CancellationTokenSource(budgetMs))
            {
                _app.StopAsync(budget.Token).GetAwaiter().GetResult();
            }
            return clock.ElapsedMilliseconds;
        }

        public void Dispose()
        {
            Stop(budgetMs: 3_000);
            _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
