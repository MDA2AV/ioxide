using System.Net;
using System.Net.Sockets;
using System.Text;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// <see cref="Reactor.ConnectAsync"/>: an outbound connection, watched by the reactor that made it and
/// usable from any thread - to an epoxide listener and to a plain .NET socket, from the thread pool
/// and from the reactor itself, and the ways a connect fails.
/// </summary>
/// <remarks>
/// An awaiter on the connecting reactor resumes inline, inside the writable edge that settles the
/// connect; any other awaiter resumes on its own context or the thread pool, never on that reactor.
/// </remarks>
internal static class ConnectTests
{
    public static void Register(Runner runner)
    {
        runner.Test("connect: from the thread pool to an epoxide listener, the connection works from the pool", () =>
        {
            int port = TestServer.Start(Handlers.Raw);
            (Reactor client, _) = TestServer.StartClientOnly();

            string outcome = Task.Run(async () =>
            {
                TcpConnection conn = await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                try
                {
                    await Hop.ToThreadPool();   // the connect resumes on the reactor once it has waited
                    (int status, string body) = await GetAsync(conn);
                    return $"{status} {body}";
                }
                finally
                {
                    conn.DecRef();
                }
            }).Wait(10_000, out string? result) ? result! : "the exchange never finished";

            Assert.Equal("200 ok", outcome);
        });

        runner.Test("connect: on the reactor to an epoxide listener, the connect and the reads resume inline", () =>
        {
            int port = TestServer.Start(Handlers.Raw);
            (Reactor client, _) = TestServer.StartClientOnly();

            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ScheduleOnReactor(_ => _ = OnReactor(), null);

            async Task OnReactor()
            {
                try
                {
                    TcpConnection conn = await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                    string connected = Where(client);
                    try
                    {
                        (int status, string body) = await GetAsync(conn);
                        report.TrySetResult($"{status} {body}, connected on {connected}, answered on {Where(client)}");
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }
                catch (Exception e)
                {
                    report.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
            }

            Assert.True(report.Task.Wait(10_000), "the exchange never finished");
            Assert.Equal("200 ok, connected on reactor, answered on reactor", report.Task.Result);
        });

        runner.Test("connect: to a plain .NET socket listener, from the thread pool and from the reactor, byte-exact", () =>
        {
            // Not an epoxide peer: a blocking Socket echo, so nothing on the far side shares code with
            // the near one.
            using var echo = new FakeServer((_, socket) =>
            {
                var buffer = new byte[64 * 1024];
                int n;
                while ((n = socket.Receive(buffer)) > 0)
                {
                    socket.Send(buffer, n, SocketFlags.None);
                }
            });
            (Reactor client, _) = TestServer.StartClientOnly();
            var remote = new IPEndPoint(IPAddress.Loopback, echo.Port);

            string fromPool = Task.Run(() => EchoAsync(client, remote, 100_000, seed: 3)).Wait(10_000, out string? a) ? a! : "never finished";

            var onReactor = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ScheduleOnReactor(_ => _ = Run(), null);
            async Task Run() => onReactor.TrySetResult(await EchoAsync(client, remote, 100_000, seed: 5));

            // From the pool the exchange ends wherever its last wait resumed it; only the reactor's is fixed.
            Assert.True(fromPool.StartsWith("100000 bytes back intact, on ", StringComparison.Ordinal), fromPool);
            Assert.True(onReactor.Task.Wait(10_000), "the exchange on the reactor never finished");
            Assert.Equal("100000 bytes back intact, on reactor", onReactor.Task.Result);
        });

        runner.Test("connect: a refused connect fails with ConnectionRefused, from the thread pool and from the reactor", () =>
        {
            (Reactor client, _) = TestServer.StartClientOnly();
            var dead = new IPEndPoint(IPAddress.Loopback, TestServer.DeadPort());

            string fromPool = Task.Run(async () =>
            {
                try
                {
                    TcpConnection conn = await client.ConnectAsync(dead);
                    conn.DecRef();
                    return "connected to a port nobody listens on";
                }
                catch (SocketException e)
                {
                    return $"{e.SocketErrorCode}, on {Where(client)}";
                }
            }).Wait(10_000, out string? a) ? a! : "the connect never settled";

            var onReactor = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.ScheduleOnReactor(_ => _ = Run(), null);
            async Task Run()
            {
                try
                {
                    TcpConnection conn = await client.ConnectAsync(dead);
                    conn.DecRef();
                    onReactor.TrySetResult("connected to a port nobody listens on");
                }
                catch (SocketException e)
                {
                    onReactor.TrySetResult($"{e.SocketErrorCode}, on {Where(client)}");
                }
            }

            Assert.True(fromPool.StartsWith("ConnectionRefused, on ", StringComparison.Ordinal), fromPool);
            Assert.True(onReactor.Task.Wait(10_000), "the connect on the reactor never settled");
            Assert.Equal("ConnectionRefused, on reactor", onReactor.Task.Result);
        });

        runner.Test("connect: an unreachable destination fails with a SocketException instead of hanging", () =>
        {
            // TCP to a multicast group: Linux refuses the route outright with ENETUNREACH, so this is an
            // immediate failure on any machine, with no network and no timeout involved.
            (Reactor client, _) = TestServer.StartClientOnly();
            var multicast = new IPEndPoint(IPAddress.Parse("224.0.0.1"), 9);

            string outcome = Task.Run(async () =>
            {
                try
                {
                    TcpConnection conn = await client.ConnectAsync(multicast).WaitAsync(TimeSpan.FromSeconds(10));
                    conn.DecRef();
                    return "connected";
                }
                catch (SocketException e)
                {
                    return e.SocketErrorCode.ToString();
                }
                catch (TimeoutException)
                {
                    return "still connecting after 10 s";
                }
            }).Result;

            Assert.Equal(nameof(SocketError.NetworkUnreachable), outcome);
        });

        runner.Test("connect: refused connects leak no descriptor and no live connection", () =>
        {
            (Reactor client, _) = TestServer.StartClientOnly();
            var dead = new IPEndPoint(IPAddress.Loopback, TestServer.DeadPort());

            Assert.True(Refuse(client, dead) == "refused", "the warm-up connect was not refused");
            int before = FdCount.Stable();

            int refused = 0;
            for (int i = 0; i < 50; i++)
            {
                refused += Refuse(client, dead) == "refused" ? 1 : 0;
            }

            Assert.Equal(50, refused);
            Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(client) == 0, 5_000),
                $"{Internals.LiveConnections(client)} refused connections were never let go");
            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 2, $"{leaked} descriptors leaked over 50 refused connects");
        });

        runner.Test("connect: an outbound connection let go from the pool sends its FIN and closes its descriptor once the peer goes", () =>
        {
            var peerSaw = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var peer = new FakeServer((_, socket) =>
            {
                socket.ReceiveTimeout = 5_000;
                peerSaw.TrySetResult(socket.Receive(new byte[16]) == 0 ? "FIN" : "bytes");
            });
            (Reactor client, _) = TestServer.StartClientOnly();

            string recorded = Task.Run(async () =>
            {
                TcpConnection conn = await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, peer.Port));
                string socket = ExecInheritance.Target(conn.ClientFd) + " " + conn.ClientFd;
                conn.DecRef();
                return socket;
            }).Result;

            Assert.True(peerSaw.Task.Wait(5_000), "the peer saw nothing");
            Assert.Equal("FIN", peerSaw.Task.Result);

            peer.Dispose();   // the peer's close: the reactor sees it and closes the descriptor
            int space = recorded.LastIndexOf(' ');
            string target = recorded[..space];
            int fd = int.Parse(recorded[(space + 1)..]);
            Assert.True(target.StartsWith("socket:[", StringComparison.Ordinal), $"fd {fd} was not a socket: '{target}'");
            Assert.True(SpinWait.SpinUntil(() => ExecInheritance.Target(fd) != target, 5_000),
                $"fd {fd} still holds the outbound connection after it was let go and its peer closed");
            Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(client) == 0, 5_000), "the outbound connection was never recycled");
        });

        runner.Test("connect: a read awaited on another reactor resumes inline on the connection's reactor", () =>
        {
            // The connection belongs to reactor B, the code awaiting its read runs on reactor A. B
            // finishes the recv at the edge, on B's thread, and runs the continuation right there. The
            // server answers a moment late, so the read has parked by then.
            int port = TestServer.Start(async (r, conn) =>
            {
                try
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    Wire.ReadPath(conn, snapshot);
                    if (snapshot.IsClosed)
                    {
                        return;   // the harness's probe
                    }
                    await new ReactorTimer(r).DelayAsync(100);
                    Wire.Write(conn, 200, "ok");
                    await conn.FlushAsync();
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Reactor owner, _) = TestServer.StartClientOnly();
            (Reactor awaiter, _) = TestServer.StartClientOnly();

            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            awaiter.ScheduleOnReactor(_ => _ = Run(), null);

            async Task Run()
            {
                try
                {
                    TcpConnection conn = await owner.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                    try
                    {
                        await Hop.ToReactor(awaiter);   // the connect may have resumed anywhere
                        string from = WhereOf(awaiter, owner);
                        (int status, string body) = await GetAsync(conn);
                        report.TrySetResult($"{status} {body}, read from {from}, answered on {WhereOf(awaiter, owner)}");
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }
                catch (Exception e)
                {
                    report.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
            }

            Assert.True(report.Task.Wait(10_000), "the exchange never finished");
            Assert.Equal("200 ok, read from the awaiter's reactor, answered on the connection's reactor", report.Task.Result);
        });

        runner.Test("connect: after Stop() a connect fails at once with ObjectDisposedException", () =>
        {
            (Reactor client, Thread thread) = TestServer.StartClientOnly();
            client.Stop();
            Assert.True(thread.Join(5_000), "the reactor did not stop");

            Task<TcpConnection> connecting = client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, TestServer.DeadPort()));
            Assert.True(connecting.IsCompleted, "a connect on a stopped reactor did not fail at once");
            Assert.True(connecting.Exception?.InnerException is ObjectDisposedException,
                $"a connect on a stopped reactor ended as {connecting.Status}: {connecting.Exception?.InnerException?.GetType().Name}");
        });

        runner.Test("connect: on a reactor with no listener, a flush its peer stopped draining is released at the send timeout", () =>
        {
            // ServerConfig.Tcp == null is the outbound-only shape, and its connections are the same
            // TcpConnection with the same clocks (TcpOptions' defaults: 60 s each). The clocks run on
            // the TCP sweep, which such a reactor registers with its first outbound connection; without
            // it a peer that stops reading would park the flush forever. Takes the default 60 s.
            using var sink = new FakeServer((_, socket) => Thread.Sleep(Timeout.Infinite));   // accepts, never reads
            (Reactor client, _) = TestServer.StartClientOnly();

            Task<string> stalled = Task.Run(async () =>
            {
                TcpConnection conn = await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, sink.Port));
                try
                {
                    conn.Write(new byte[16 * 1024 * 1024]);
                    await conn.FlushAsync();
                    return conn.IsClosed ? "released, closed" : "completed with the connection open";
                }
                finally
                {
                    conn.DecRef();
                }
            });

            Assert.True(stalled.Wait(90_000), "the flush was still parked 90 s into a 60 s send timeout");
            Assert.Equal("released, closed", stalled.Result);
        }, timeoutMs: 110_000);

        runner.Test("connect: a connect from another thread that races Stop() settles instead of hanging", () =>
        {
            // ConnectAsync off the reactor enqueues the registration and wakes the loop; a Stop() right
            // behind it ends the loop before it drains that queue, so the teardown has to. Left there,
            // nothing settles the connect: the caller waits forever, and the socket and the live count
            // leak, so the pools are never freed either.
            int port = TestServer.Start(Handlers.Raw);
            var remote = new IPEndPoint(IPAddress.Loopback, port);

            const int Rounds = 20;
            int hung = 0;
            for (int i = 0; i < Rounds; i++)
            {
                (Reactor client, Thread thread) = TestServer.StartClientOnly();

                Task<TcpConnection> connecting = client.ConnectAsync(remote);
                client.Stop();   // straight behind it, before the loop can get to the queue
                Assert.True(thread.Join(5_000), "the reactor did not stop");

                try
                {
                    if (!connecting.Wait(2_000))
                    {
                        hung++;
                        continue;
                    }
                    connecting.Result.DecRef();   // it won the race: connected before the stop
                }
                catch (AggregateException e) when (e.InnerException is ObjectDisposedException or SocketException)
                {
                    // Refused because of the stop: settled, which is all this asks.
                }

                Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(client) == 0, 5_000),
                    $"round {i}: the connect settled but its connection was never let go");
            }

            Assert.True(hung == 0, $"{hung} of {Rounds} connects that raced Stop() never settled, each holding a socket");
        });
    }

    /// <summary>One request over a raw connection, read to the end of its body, from whatever thread this is on.</summary>
    private static async Task<(int Status, string Body)> GetAsync(TcpConnection conn)
    {
        conn.Write("GET / HTTP/1.1\r\nHost: t\r\n\r\n"u8);
        await conn.FlushAsync();

        var received = new List<byte>();
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    received.AddRange(item.AsSpan().ToArray());
                    conn.ReturnBuffer(in item);
                }
            }

            string text = Encoding.ASCII.GetString(received.ToArray());
            int end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end >= 0)
            {
                int length = int.Parse(text.Split("\r\n").First(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))["Content-Length:".Length..].Trim());
                if (text.Length - end - 4 >= length)
                {
                    return (int.Parse(text.AsSpan(9, 3)), text.Substring(end + 4, length));
                }
            }

            if (snapshot.IsClosed)
            {
                return (0, $"closed after {received.Count} bytes");
            }
            conn.ResetRead();
        }
    }

    /// <summary>Sends <paramref name="bytes"/> to an echo peer over a fresh outbound connection and checks every one comes back.</summary>
    private static async Task<string> EchoAsync(Reactor reactor, IPEndPoint remote, int bytes, int seed)
    {
        TcpConnection conn = await reactor.ConnectAsync(remote);
        try
        {
            byte[] sent = new byte[bytes];
            new Random(seed).NextBytes(sent);
            conn.Write(sent);
            await conn.FlushAsync();

            int got = 0;
            while (got < bytes)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (!item.HasBuffer)
                    {
                        continue;
                    }
                    bool same = item.AsSpan().SequenceEqual(sent.AsSpan(got, item.Len));
                    got += item.Len;
                    conn.ReturnBuffer(in item);
                    if (!same)
                    {
                        return $"the echo differed within bytes {got - item.Len}..{got}";
                    }
                }
                if (snapshot.IsClosed && got < bytes)
                {
                    return $"closed after {got} of {bytes} bytes";
                }
                conn.ResetRead();
            }
            return $"{got} bytes back intact, on {Where(reactor)}";
        }
        finally
        {
            conn.DecRef();
        }
    }

    // One connect to a port nobody listens on, from the pool: "refused", or what happened instead.
    private static string Refuse(Reactor reactor, IPEndPoint dead)
    {
        try
        {
            TcpConnection conn = reactor.ConnectAsync(dead).WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
            conn.DecRef();
            return "connected";
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return "refused";
        }
        catch (Exception e)
        {
            return $"{e.GetType().Name}: {e.Message}";
        }
    }

    private static string Where(Reactor r)
        => r.OnReactorThread ? "reactor"
         : Thread.CurrentThread.IsThreadPoolThread ? "pool"
         : $"thread {Environment.CurrentManagedThreadId}";

    private static string WhereOf(Reactor awaiter, Reactor owner)
        => awaiter.OnReactorThread ? "the awaiter's reactor"
         : owner.OnReactorThread ? "the connection's reactor"
         : Thread.CurrentThread.IsThreadPoolThread ? "the pool"
         : $"thread {Environment.CurrentManagedThreadId}";
}

internal static class TaskWaits
{
    /// <summary>Waits up to <paramref name="timeoutMs"/> and hands back the result if it came.</summary>
    public static bool Wait<T>(this Task<T> task, int timeoutMs, out T? result)
    {
        if (task.Wait(timeoutMs))
        {
            result = task.Result;
            return true;
        }
        result = default;
        return false;
    }
}
