using ioxide;
using ioxide.pg;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>The pool's timeout sweep, when the waiters it fails query the pool again from inside it.</summary>
internal static class PgSweepTests
{
    public static void Register(Runner runner, (string Host, int Port) pg, bool pgUp)
    {
        // The failed waiter resumes inside the sweep, and its picks evict the timed-out connection from the list the sweep is indexing.
        runner.Test("pg: queries made by a timed-out query's handler run on the live connection the sweep keeps", () =>
        {
            int port = TestServer.Start(RequeryOnTimeout, r => PgPool.Start(r, Options(pg)));

            (int status, string body) = Client.Get(port, "/timeout", timeoutMs: 15_000);
            Assert.Equal(200, status);
            Assert.Equal("listed=2 first=1 second=2", body);

            (int afterStatus, string afterBody) = Client.Get(port, "/select");
            Assert.Equal(200, afterStatus);
            Assert.Equal("42", afterBody);
        }, skip: !pgUp);
    }

    private static async Task RequeryOnTimeout(Reactor r, TcpConnection conn)
    {
        PgPool pool = r.GetService<PgPool>();

        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            string path = Wire.ReadPath(conn, snapshot);

            string body;
            if (path == "/timeout")
            {
                // Both open before the first pick, so the sleep lands on index 0 with a live connection after it.
                var timer = new RingTimer(r);
                while (pool.ConnectionCount < 2)
                {
                    await timer.DelayAsync(10);
                }

                try
                {
                    await pool.QueryAsync("SELECT pg_sleep(30)");
                    body = "the sleep returned";
                }
                catch (PgException e) when (e.Message.Contains("timed out"))
                {
                    // Still listed here only if this runs inline in the sweep, before it removes the connection.
                    int listed = pool.ConnectionCount;
                    ValueTask<PgResult> first = pool.QueryAsync("SELECT 1");
                    ValueTask<PgResult> second = pool.QueryAsync("SELECT 2");
                    body = $"listed={listed} first={await Outcome(first)} second={await Outcome(second)}";
                }
            }
            else if (path == "/select")
            {
                body = (await pool.QueryAsync("SELECT 42")).Value ?? "";
            }
            else
            {
                return;   // the harness's listen probe: it must not pick, or the sleep moves off index 0
            }

            Wire.Write(conn, 200, body);
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task<string> Outcome(ValueTask<PgResult> query)
    {
        try
        {
            return (await query).Value ?? "null";
        }
        catch (PgException e)
        {
            return e.Message;
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
        CommandTimeoutMs = 1000,
    };
}
