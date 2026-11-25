using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;
using ioxide.http2;
using ioxide.nghttp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// HTTP/2 over a connection that changes reactors, on both stacks: requests in progress, uploads and responses under way
/// go on, and the connection's state is only ever touched on the reactor it is on.
/// </summary>
internal static class MoveHttp2Tests
{
    private const int UploadLength = 600 * 1024;

    public static void Register(Runner runner)
    {
        foreach (Stack stack in new Stack[] { new Managed(false), new Managed(true), new Native(false), new Native(true) })
        {
            Register(runner, stack);
        }
    }

    private static void Register(Runner runner, Stack stack)
    {
        runner.Test($"move h2 ({stack.Name}): requests are served on whichever reactor the connection is on", () =>
        {
            using var fleet = new MoveFleet(2, conn => Serve(conn, stack.Answer(_ => new ValueTask<string>($"{Reactor.Current!.ShardIndex}"))));
            using HttpClient client = H2Client();
            string first = Get(client, fleet.Port, "/");
            TcpConnection conn = fleet.TakeAccepted();
            Assert.Equal($"{conn.Reactor.ShardIndex}", first);
            for (int i = 0; i < 10; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 2]);
                Assert.Equal($"{i % 2}", Get(client, fleet.Port, "/"));
            }
        });

        runner.Test($"move h2 ({stack.Name}): a request whose handler waits doesn't hold the connection, and is answered from where it is", () =>
        {
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int waiting = 0;
            using var fleet = new MoveFleet(2, conn => Serve(conn, stack.Answer(async path =>
            {
                string from = $"{Reactor.Current!.ShardIndex}";
                if (path == "/wait")
                {
                    Interlocked.Increment(ref waiting);
                    await release.Task.ConfigureAwait(false);   // and goes on on the thread pool
                }
                return from;
            })));
            using HttpClient client = H2Client();
            Get(client, fleet.Port, "/");
            TcpConnection conn = fleet.TakeAccepted();
            Moves.To(conn, fleet.A);

            Task<string>[] waits = Enumerable.Range(0, 5).Select(_ => client.GetStringAsync(Url(fleet.Port, "/wait"))).ToArray();
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref waiting) == waits.Length, 5_000), "the handlers never got to wait");
            Moves.To(conn, fleet.B);
            Assert.Equal("1", Get(client, fleet.Port, "/"));
            Assert.True(waits.All(wait => !wait.IsCompleted), "a request was answered before its handler was done");

            release.SetResult();
            Assert.True(Task.WaitAll(waits, 10_000), "a request in progress over the move was never answered");
            Assert.True(waits.All(wait => wait.Result == "0"), $"answers of handlers begun before the move: {string.Join(" ", waits.Select(w => w.Result))}");
            Assert.Equal("1", Get(client, fleet.Port, "/"));
        });

        runner.Test($"move h2 ({stack.Name}): a handler that goes on on the reactor its connection has left is answered for from the new one", () =>
        {
            using var started = new CountdownEvent(4);
            using var fleet = new MoveFleet(2, conn => Serve(conn, stack.Answer(async path =>
            {
                Reactor reactor = Reactor.Current!;
                if (path == "/wait")
                {
                    started.Signal();
                    await new RingTimer(reactor).DelayAsync(300);   // resumes there
                    Assert.True(ReferenceEquals(Reactor.Current, reactor), "a timer resumed on another reactor than its own");
                }
                return $"{reactor.ShardIndex}";
            })));
            using HttpClient client = H2Client();
            Get(client, fleet.Port, "/");
            TcpConnection conn = fleet.TakeAccepted();
            Moves.To(conn, fleet.A);
            Task<string>[] waits = Enumerable.Range(0, 4).Select(_ => client.GetStringAsync(Url(fleet.Port, "/wait"))).ToArray();
            Assert.True(started.Wait(5_000), "the handlers never got to wait");
            Moves.To(conn, fleet.B);
            Assert.True(Task.WaitAll(waits, 10_000), "a request in progress over the move was never answered");
            Assert.True(waits.All(wait => wait.Result == "0"), "a handler began elsewhere than it did");
        });

        foreach (bool pool in new[] { false, true })
        {
            string where = pool ? "from the thread pool" : "on the reactor";

            runner.Test($"move h2 ({stack.Name}): an upload echoed while the connection is moved all the time comes back whole ({where})", () =>
            {
                using var fleet = new MoveFleet(3, conn => Serve(conn, stack.Echo(pool)));
                using HttpClient client = H2Client();
                using var shuffle = new Moves.Shuffle(fleet.Reactors);
                byte[] upload = Pattern(UploadLength);
                for (int i = 0; i < 3 || (shuffle.Made < 20 && i < 100); i++)
                {
                    using var content = new DuplexContent(upload);
                    using HttpResponseMessage response = Finish(client.PostAsync(Url(fleet.Port, "/"), content), "the echo's headers");
                    byte[] back = Finish(response.Content.ReadAsByteArrayAsync(), "the echo");
                    Assert.True(back.AsSpan().SequenceEqual(upload), $"{back.Length} of {upload.Length} bytes came back, different from {FirstDifference(upload, back)} on");
                }
                Assert.True(shuffle.Made >= 10, $"only {shuffle.Made} moves were made");
            });
        }

        runner.Test($"move h2 ({stack.Name}): many requests at once over a connection moved all the time are each answered with their own", () =>
        {
            int onWrong = 0;
            using var fleet = new MoveFleet(4, conn => Serve(conn, stack.Answer(async path =>
            {
                switch (path.Length % 3)
                {
                    case 0:
                        await Task.Delay(1).ConfigureAwait(false);
                        break;
                    case 1:
                        await new RingTimer(Reactor.Current!).DelayAsync(1);
                        break;
                    default:
                        if (!conn.Reactor.OnReactorThread)
                        {
                            Interlocked.Increment(ref onWrong);   // dispatched off its connection's reactor
                        }
                        break;
                }
                return string.Concat(Enumerable.Repeat(path, 40));
            })));
            using HttpClient client = H2Client();
            using var shuffle = new Moves.Shuffle(fleet.Reactors);

            Task[] callers = Enumerable.Range(0, 16).Select(i => Task.Run(async () =>
            {
                for (int n = 0; n < 60; n++)
                {
                    string path = $"/{i}/{new string('x', n % 7)}{n}";
                    Assert.Equal(string.Concat(Enumerable.Repeat(path, 40)), await client.GetStringAsync(Url(fleet.Port, path)));
                }
            })).ToArray();
            Assert.True(Task.WaitAll(callers, 60_000), "a request was never answered");
            Assert.Equal(0, onWrong);
            Assert.True(shuffle.Made > 10, $"only {shuffle.Made} moves were made");
        });

        runner.Test($"move h2 ({stack.Name}): a response that goes on and on goes on over moves", () =>
        {
            var stop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, conn => Serve(conn, stack.Endless(stop.Task)));
            using HttpClient client = H2Client();
            using HttpResponseMessage response = Finish(client.GetAsync(Url(fleet.Port, "/"), HttpCompletionOption.ResponseHeadersRead), "the headers");
            TcpConnection conn = fleet.TakeAccepted();
            using Stream body = Finish(response.Content.ReadAsStreamAsync(), "the body");
            var buffer = new byte[4096];
            long got = 0;
            for (int i = 0; i < 12; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 2]);
                for (long until = got + 20_000; got < until;)
                {
                    int n = Finish(body.ReadAsync(buffer).AsTask(), "more of the body");
                    Assert.True(n > 0, $"the response ended after {got} bytes");
                    for (int k = 0; k < n; k++)
                    {
                        Assert.True(buffer[k] == (byte)((got + k) % 251), $"byte {got + k} is wrong");
                    }
                    got += n;
                }
            }
            stop.SetResult();
            int last;
            do
            {
                last = Finish(body.ReadAsync(buffer).AsTask(), "the end of the body");
            }
            while (last > 0);
        });

        runner.Test($"move h2 ({stack.Name}): a connection that moved and ends is let go of by its new reactor", () =>
        {
            using var fleet = new MoveFleet(2, conn => Serve(conn, stack.Answer(_ => new ValueTask<string>("x"))));
            TcpConnection conn;
            using (HttpClient client = H2Client())
            {
                Get(client, fleet.Port, "/");
                conn = fleet.TakeAccepted();
                Moves.To(conn, fleet.A);
                Moves.To(conn, fleet.B);
                Assert.Equal("x", Get(client, fleet.Port, "/"));
            }
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        });
    }

    private static async Task Serve(TcpConnection conn, Func<TcpConnection, Task> serve)
    {
        try
        {
            await serve(conn);
        }
        finally
        {
            conn.DecRef();
        }
    }

    /// <summary>An HTTP/2 stack, given the connection itself or a pipe over it.</summary>
    private abstract class Stack(string name, bool pipe)
    {
        public string Name { get; } = pipe ? name + ", over a pipe" : name;
        protected readonly bool Pipe = pipe;

        public abstract Func<TcpConnection, Task> Answer(Func<string, ValueTask<string>> answer);
        public abstract Func<TcpConnection, Task> Echo(bool pool);
        public abstract Func<TcpConnection, Task> Endless(Task stop);

        protected static ConfiguredTaskAwaitable LeaveReactor(bool pool)
            => Task.CompletedTask.ConfigureAwait(pool ? ConfigureAwaitOptions.ForceYielding : ConfigureAwaitOptions.None);

        protected static async ValueTask EchoBody(bool pool, Func<ValueTask<ReadOnlyMemory<byte>>> read, Action headers,
            IBufferWriter<byte> writer, Func<ValueTask<FlushResult>> flush)
        {
            await LeaveReactor(pool);
            headers();
            while (true)
            {
                await LeaveReactor(pool);
                ReadOnlyMemory<byte> chunk = await read();
                if (chunk.IsEmpty)
                {
                    return;
                }
                await LeaveReactor(pool);
                writer.Write(chunk.Span);
                if ((await flush()).IsCompleted)
                {
                    return;
                }
            }
        }

        protected static async ValueTask WriteOnAndOn(Task stop, IBufferWriter<byte> writer, Func<ValueTask<FlushResult>> flush)
        {
            for (long at = 0; !stop.IsCompleted;)
            {
                Span<byte> span = writer.GetSpan(1000)[..1000];
                for (int i = 0; i < span.Length; i++)
                {
                    span[i] = (byte)((at + i) % 251);
                }
                writer.Advance(span.Length);
                at += span.Length;
                if ((await flush()).IsCompleted)
                {
                    return;
                }
            }
        }
    }

    private sealed class Managed(bool pipe) : Stack("http2", pipe)
    {
        private Http2Connection Over(TcpConnection conn) => Pipe ? new Http2Connection(new TcpConnectionDualPipe(conn)) : new Http2Connection(conn);

        public override Func<TcpConnection, Task> Answer(Func<string, ValueTask<string>> answer)
            => conn => Over(conn).RunAsync(async request => Http2Response.Text(await answer(Encoding.ASCII.GetString(request.Path.Span))));

        public override Func<TcpConnection, Task> Echo(bool pool)
            => conn => Over(conn).RunAsync((_, body, writer) =>
                EchoBody(pool, body.ReadAsync, () => writer.WriteHeaders(new Http2Response { Status = 200 }), writer, writer.FlushAsync));

        public override Func<TcpConnection, Task> Endless(Task stop)
            => conn => Over(conn).RunAsync((_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                return WriteOnAndOn(stop, writer, writer.FlushAsync);
            });
    }

    private sealed class Native(bool pipe) : Stack("nghttp2", pipe)
    {
        private Nghttp2Connection Over(TcpConnection conn) => Pipe ? new Nghttp2Connection(new TcpConnectionDualPipe(conn)) : new Nghttp2Connection(conn);

        public override Func<TcpConnection, Task> Answer(Func<string, ValueTask<string>> answer)
            => conn => Over(conn).RunAsync(async request => Nghttp2Response.Text(await answer(Encoding.ASCII.GetString(request.Path.Span))));

        public override Func<TcpConnection, Task> Echo(bool pool)
            => conn => Over(conn).RunAsync((_, body, writer) =>
                EchoBody(pool, body.ReadAsync, () => writer.WriteHeaders(new Nghttp2Response { Status = 200 }), writer, writer.FlushAsync));

        public override Func<TcpConnection, Task> Endless(Task stop)
            => conn => Over(conn).RunAsync((_, writer) =>
            {
                writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                return WriteOnAndOn(stop, writer, writer.FlushAsync);
            });
    }

    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(60),
    };

    private static string Url(int port, string path) => $"http://127.0.0.1:{port}{path}";

    private static string Get(HttpClient client, int port, string path) => Finish(client.GetStringAsync(Url(port, path)), path);

    private static T Finish<T>(Task<T> task, string what)
    {
        Assert.True(task.Wait(20_000), $"{what} never came");
        return task.Result;
    }

    private static byte[] Pattern(int length)
    {
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)((i * 31) + (i >> 10));
        }
        return bytes;
    }

    private static int FirstDifference(byte[] expected, byte[] actual)
    {
        int common = expected.AsSpan().CommonPrefixLength(actual);
        return common;
    }

    // HttpClient sends a ByteArrayContent whole before it reads the response, which stalls an echo past its receive window.
    private sealed class DuplexContent(byte[] bytes) : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            for (int from = 0; from < bytes.Length; from += 8 * 1024)
            {
                await stream.WriteAsync(bytes.AsMemory(from, Math.Min(8 * 1024, bytes.Length - from)));
                await stream.FlushAsync();
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
