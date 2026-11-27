using System.Buffers.Binary;
using System.Net.Sockets;
using ioxide;
using ioxide.pg;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// The pools as their reactor stops: its first pass disposes each pool started on it, so their connections close and
/// the queries waiting for one fail with ObjectDisposedException. Fake servers, so no postgres is needed.
/// </summary>
internal static class PgStopTests
{
    // AuthenticationOk, then ReadyForQuery (idle): a startup that connects.
    private static readonly byte[] Connected = [(byte)'R', 0, 0, 0, 8, 0, 0, 0, 0, (byte)'Z', 0, 0, 0, 5, (byte)'I'];

    public static void Register(Runner runner)
    {
        runner.Test("pg: a disposed pool closes a connection whose open completes after, and opens no more", () =>
        {
            int accepted = 0, closed = 0;
            using var answer = new ManualResetEventSlim();
            using var slow = new FakeServer((_, socket) =>
            {
                Interlocked.Increment(ref accepted);
                try
                {
                    answer.Wait(10_000);
                    AnswerStartup(socket);
                    while (socket.Receive(new byte[256]) > 0)
                    {
                    }
                }
                catch (Exception e) when (e is SocketException or IOException)
                {
                    // reset: closed too
                }
                Interlocked.Increment(ref closed);
            });

            string outcome = OnReactor.Run(r => DisposedWhileOpening(r, () => Volatile.Read(ref accepted), () => Volatile.Read(ref closed), answer, slow.Port));
            Assert.Equal("accepted 1, closed 1, connections 0", outcome);
        });

        runner.Test("pg: a reactor's stop closes each of its pools' connections, and fails the queries waiting for one with ObjectDisposedException", () =>
        {
            int closed = 0;
            using var answering = new FakeServer((_, socket) =>
            {
                try
                {
                    AnswerStartup(socket);
                    while (socket.Receive(new byte[256]) > 0)
                    {
                    }
                }
                catch (SocketException)
                {
                    // reset: closed too
                }
                Interlocked.Increment(ref closed);
            });
            using var silent = new FakeServer((_, _) => { });   // takes the connection and never answers its startup

            PgPool idle = null!;
            Task<string> waiting = null!;
            (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(
                (_, connection) => { connection.DecRef(); return Task.CompletedTask; },
                new ServerConfig { Tcp = new TcpOptions() },
                r =>
                {
                    idle = PgPool.Start(r, Options(answering.Port));
                    PgPool stuck = PgPool.Start(r, Options(silent.Port));
                    waiting = EndOf(stuck.QueryAsync("SELECT 1"));
                });

            Assert.True(SpinWait.SpinUntil(() => idle.ConnectionCount == 1, 5_000), "the pool never connected to the server that answers");
            reactor.Stop();
            Assert.True(thread.Join(10_000), "the reactor did not stop");

            Assert.Equal("waiting: ObjectDisposedException, connections closed: 1",
                $"waiting: {(waiting.Wait(5_000) ? waiting.Result : "still waiting")}, connections closed: {ClosedWithin(ref closed, 1)}");
        });

        runner.Test("pg: a connection opened on a stopping reactor fails with ObjectDisposedException and leaves no socket open", () =>
        {
            string outcome = "the stopper never ran";
            (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(
                (_, connection) => { connection.DecRef(); return Task.CompletedTask; },
                new ServerConfig { Tcp = new TcpOptions() },
                r => r.AddStopper(() =>
                {
                    // On the reactor once its stop has begun, as a handler the stop wakes would open one.
                    int before = FdCount.Stable();
                    Task<PgConnection>[] opens = [.. Enumerable.Range(0, 8).Select(_ => PgConnection.ConnectAsync(r, Options(TestServer.DeadPort()) with { CommandTimeoutMs = 5_000 }))];
                    outcome = $"{opens[^1].Exception?.InnerException?.GetType().Name ?? opens[^1].Status.ToString()}, sockets left open: {FdCount.Stable() - before}";
                }));

            reactor.Stop();
            Assert.True(thread.Join(10_000), "the reactor did not stop");
            Assert.Equal("ObjectDisposedException, sockets left open: 0", outcome);
        });
    }

    private static async Task<string> DisposedWhileOpening(Reactor r, Func<int> accepted, Func<int> closed, ManualResetEventSlim answer, int port)
    {
        var timer = new RingTimer(r);
        PgPool pool = PgPool.Start(r, Options(port));
        for (long deadline = Native.MonotonicMs + 5_000; accepted() == 0 && Native.MonotonicMs < deadline;)
        {
            await timer.DelayAsync(10);
        }

        pool.Dispose();
        answer.Set();   // the open completes now, on a disposed pool
        for (long deadline = Native.MonotonicMs + 2_000; closed() == 0 && Native.MonotonicMs < deadline;)
        {
            await timer.DelayAsync(10);
        }
        await timer.DelayAsync(3 * Reactor.TickMs);   // sweeps that would open another
        return $"accepted {accepted()}, closed {closed()}, connections {pool.ConnectionCount}";
    }

    internal static PgOptions Options(int port) => new()
    {
        Port = (ushort)port,
        User = "fake",
        Database = "fake",
        PoolSize = 1,
        CommandTimeoutMs = 0,   // a startup never answered waits until the stop
    };

    internal static void AnswerStartup(Socket socket)
    {
        int length = BinaryPrimitives.ReadInt32BigEndian(FakeServer.Receive(socket, 4));
        FakeServer.Receive(socket, length - 4);   // protocol version and parameters
        socket.Send(Connected);
    }

    // How a query ended: its value, or the type of what it threw.
    private static async Task<string> EndOf(ValueTask<PgResult> query)
    {
        try
        {
            return $"answered {(await query).Value}";
        }
        catch (Exception e)
        {
            return e.GetType().Name;
        }
    }

    private static int ClosedWithin(ref int closed, int expected)
    {
        long deadline = Environment.TickCount64 + 5_000;
        while (Volatile.Read(ref closed) < expected && Environment.TickCount64 < deadline)
        {
            Thread.Sleep(20);
        }
        return Volatile.Read(ref closed);
    }
}
