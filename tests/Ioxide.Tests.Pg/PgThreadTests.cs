using ioxide;
using ioxide.pg;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// The pool, its connections and threads other than their reactor's: a query or a Dispose made on one, and the
/// cold start, whose waiters must all come back to the reactor without passing through one.
/// </summary>
internal static class PgThreadTests
{
    private const string Backend = "SELECT pg_backend_pid()";

    public static void Register(Runner runner, (string Host, int Port) pg, bool pgUp)
    {
        runner.Test("pg pool: queries made before its first connection opens all resume on the reactor, none through the thread pool", () =>
        {
            string outcome = OnReactor.Run(async reactor =>
            {
                // A continuation run on another thread restores this flow's context there: on a pool thread that
                // changes this local's value, which is how a pass through the pool shows.
                int pooled = 0;
                var flow = new AsyncLocal<bool>(change =>
                {
                    if (change.ThreadContextChanged && Thread.CurrentThread.IsThreadPoolThread)
                    {
                        Interlocked.Increment(ref pooled);
                    }
                });
                flow.Value = true;

                // Still in OnStart, so no open can finish before every query is waiting for one.
                PgPool pool = PgPool.Start(reactor, Options(pg));
                ValueTask<PgResult>[] queries = [.. Enumerable.Range(0, 64).Select(_ => pool.QueryAsync("SELECT 1"))];

                int answered = 0;
                foreach (ValueTask<PgResult> query in queries)
                {
                    answered += (await query).Value == "1" ? 1 : 0;
                }
                return $"{answered} answered, {Volatile.Read(ref pooled)} context changes on pool threads";
            });

            Assert.Equal("64 answered, 0 context changes on pool threads", outcome);
        }, skip: !pgUp);

        runner.Test("pg pool: a query made on another thread takes its connection on the reactor, in the reactor's turn", () =>
        {
            string outcome = OnReactor.Run(async reactor =>
            {
                PgPool pool = PgPool.Start(reactor, Options(pg));
                var timer = new RingTimer(reactor);
                while (pool.ConnectionCount < 2)
                {
                    await timer.DelayAsync(10);
                }

                // Round-robin over two connections, so the reactor's own queries alternate backends. A pick made on
                // the other thread takes the reactor's next turn, and the query after it gets the first backend again.
                string first = (await pool.QueryAsync(Backend)).Value!;
                ValueTask<PgResult> elsewhere = OnReactor.CallFromAnotherThread(() => pool.QueryAsync(Backend));
                string second = (await pool.QueryAsync(Backend)).Value!;
                string other = (await elsewhere).Value!;
                return first != second && other.Length > 0 ? "alternated" : $"backends {first} then {second}, the other thread's {other}";
            });

            Assert.Equal("alternated", outcome);
        }, skip: !pgUp);

        runner.Test("pg connection: queries made on another thread are staged and sent from the reactor", () =>
        {
            string outcome = OnReactor.Run(async reactor =>
            {
                var host = new WatchedHost(reactor);
                PgConnection connection = await PgConnection.ConnectAsync(host, Options(pg));
                try
                {
                    string simple = (await OnReactor.CallFromAnotherThread(() => connection.QueryAsync("SELECT 1"))).Value!;
                    int simpleOff = host.SubmittedOffReactor;
                    string prepared = (await OnReactor.CallFromAnotherThread(
                        () => connection.QueryAsync("SELECT $1::int + 1", [PgParam.Int(41)]))).Value!;
                    return $"{simple} and {prepared}, ring submissions made on the other thread: {simpleOff} for the simple "
                         + $"query, {host.SubmittedOffReactor - simpleOff} for the prepared one";
                }
                finally
                {
                    connection.Dispose();
                }
            });

            Assert.Equal("1 and 42, ring submissions made on the other thread: 0 for the simple query, 0 for the prepared one", outcome);
        }, skip: !pgUp);

        runner.Test("pg connection: one disposed from another thread is disposed on its reactor", () =>
        {
            string outcome = OnReactor.Run(async reactor =>
            {
                PgConnection connection = await PgConnection.ConnectAsync(reactor, Options(pg));
                string value = (await connection.QueryAsync("SELECT 1")).Value!;

                OnReactor.CallFromAnotherThread(connection.Dispose);
                bool held = connection.IsBroken;
                await TestServer.LaterPass();
                return $"{value}, broken while the reactor was held {held}, after {connection.IsBroken}";
            });

            Assert.Equal("1, broken while the reactor was held False, after True", outcome);
        }, skip: !pgUp);
    }

    // The reactor, counting the ring submissions made on a thread other than its own.
    private sealed class WatchedHost(Reactor reactor) : IRingHost
    {
        private int _offReactor;

        public int SubmittedOffReactor => Volatile.Read(ref _offReactor);

        public bool OnReactorThread => reactor.OnReactorThread;

        public void ScheduleOnReactor(Action<object?> callback, object? state) => reactor.ScheduleOnReactor(callback, state);

        public void SubmitConnect(int fd, nint sockaddr, int sockaddrLen, IRingCompletion completion)
        {
            Note();
            reactor.SubmitConnect(fd, sockaddr, sockaddrLen, completion);
        }

        public void SubmitSend(int fd, nint buffer, int length, IRingCompletion completion)
        {
            Note();
            reactor.SubmitSend(fd, buffer, length, completion);
        }

        public void SubmitRecv(int fd, nint buffer, int length, IRingCompletion completion)
        {
            Note();
            reactor.SubmitRecv(fd, buffer, length, completion);
        }

        public void SubmitRead(int fd, nint buffer, int length, long offset, IRingCompletion completion)
        {
            Note();
            reactor.SubmitRead(fd, buffer, length, offset, completion);
        }

        public void SubmitWrite(int fd, nint buffer, int length, long offset, IRingCompletion completion)
        {
            Note();
            reactor.SubmitWrite(fd, buffer, length, offset, completion);
        }

        public void SubmitTimeout(long nanoseconds, IRingCompletion completion)
        {
            Note();
            reactor.SubmitTimeout(nanoseconds, completion);
        }

        private void Note()
        {
            if (!reactor.OnReactorThread)
            {
                Interlocked.Increment(ref _offReactor);
            }
        }
    }

    private static PgOptions Options((string Host, int Port) pg) => new()
    {
        Host = pg.Host,
        Port = (ushort)pg.Port,
        User = Environment.GetEnvironmentVariable("EXAMPLES_PG_USER") ?? "bench",
        Database = Environment.GetEnvironmentVariable("EXAMPLES_PG_DB") ?? "bench",
        Password = Environment.GetEnvironmentVariable("EXAMPLES_PG_PASSWORD"),
        PoolSize = 2,
    };
}
