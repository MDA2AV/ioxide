using ioxide;
using ioxide.pg;

namespace Ioxide.Tests;

/// <summary>Postgres driver over the ring: queries, parameters, streaming, errors, timeouts.</summary>
internal static class PgTests
{
    public static void Register(Runner runner, (string Host, int Port) pg, bool pgUp)
    {
        // ---- pg pool fails fast on a dead backend (#1) - needs NO live pg ----
        runner.Test("pg: dead backend fails fast, no hang (#1)", () =>
        {
            PgOptions dead = PgOpts(pg) with { Port = (ushort)TestServer.DeadPort() };
            int port = TestServer.Start(PgHandlers.Pg, r => PgPool.Start(r, dead));
            (int status, _) = Client.Get(port, "/", timeoutMs: 8000);
            Assert.Equal(500, status);   // PgException surfaced quickly, not a hang
        });

        // ---- pg (needs the sidecar) ----
        runner.Test("pg: SELECT 42", () =>
        {
            int port = TestServer.Start(PgHandlers.Pg, r => PgPool.Start(r, PgOpts(pg)));
            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("42", body);
        }, skip: !pgUp);

        runner.Test("pg: prepared int parameter", () =>
        {
            int port = TestServer.Start(PgHandlers.Pg, r => PgPool.Start(r, PgOpts(pg)));
            (int status, string body) = Client.Get(port, "/add/41");
            Assert.Equal(200, status);
            Assert.Equal("42", body);
        }, skip: !pgUp);

        runner.Test("pg: row streaming", () =>
        {
            int port = TestServer.Start(PgHandlers.Pg, r => PgPool.Start(r, PgOpts(pg)));
            (int status, string body) = Client.Get(port, "/rows");
            Assert.Equal(200, status);
            Assert.Equal("rows=5", body);
        }, skip: !pgUp);

        // The handler throws no PgException, so the reader loop's catch is what turns it into one for the waiters.
        runner.Test("pg: a row handler that throws fails its query with a PgException carrying the message, and the pool still answers", () =>
        {
            string outcome = OnReactor.Run(async reactor =>
            {
                PgPool pool = PgPool.Start(reactor, PgOpts(pg));
                string streamed = await Outcome(pool.QueryRowsAsync(
                    "SELECT n FROM generate_series(1, 5) AS n", _ => throw new InvalidOperationException("row handler failed")));

                // Two picks, so one lands on the broken connection and moves past it.
                string first = (await pool.QueryAsync("SELECT 1")).Value!;
                string second = (await pool.QueryAsync("SELECT 2")).Value!;
                return $"{streamed}; then {first} and {second}";
            });

            Assert.Equal("PgException: row handler failed; then 1 and 2", outcome);
        }, skip: !pgUp);

        runner.Test("pg: server error then connection stays usable", () =>
        {
            int port = TestServer.Start(PgHandlers.Pg, r => PgPool.Start(r, PgOpts(pg)));
            (int badStatus, string sqlState) = Client.Get(port, "/bad");
            Assert.Equal(500, badStatus);
            Assert.Equal("42P01", sqlState);   // undefined_table

            (int okStatus, string body) = Client.Get(port, "/");
            Assert.Equal(200, okStatus);
            Assert.Equal("42", body);
        }, skip: !pgUp);

        // Refused while it is staged, before any state changes, so the connection is not broken.
        runner.Test("pg: a query larger than the send buffer fails with a PgException, and the connection still answers", () =>
        {
            const int sendBuffer = 512 * 1024;
            string outcome = OnReactor.Run(async reactor =>
            {
                using PgConnection connection = await PgConnection.ConnectAsync(reactor, PgOpts(pg));
                string text = new('x', sendBuffer);   // fills the buffer on its own, before the message around it
                string simple = await Outcome(connection.QueryAsync($"SELECT '{text}'"));
                string prepared = await Outcome(connection.QueryAsync("SELECT $1::text", [PgParam.Text(text)]));
                string after = (await connection.QueryAsync("SELECT 42")).Value!;
                return $"{simple}; {prepared}; then {after}";
            });

            string refused = $"PgException: query exceeds send buffer ({sendBuffer} bytes)";
            Assert.Equal($"{refused}; {refused}; then 42", outcome);
        }, skip: !pgUp);

        runner.Test("pg: command timeout (#2)", () =>
        {
            int port = TestServer.Start(PgHandlers.PgSlow, r => PgPool.Start(r, PgOpts(pg, commandTimeoutMs: 1000)));
            (int status, _) = Client.Get(port, "/slow", timeoutMs: 8000);
            Assert.Equal(503, status);
        }, skip: !pgUp);

        // An unstamped query reads as made at boot, so the sweep would fail it on its first pass, before the timeout.
        runner.Test("pg: a prepared query that outlasts CommandTimeoutMs fails once that long has passed, not sooner", () =>
        {
            Assert.Equal("timed out", TimedOut(pg, pool => pool.QueryAsync("SELECT pg_sleep($1)", [PgParam.Int(5)])));
        }, skip: !pgUp);

        runner.Test("pg: a simple query that outlasts CommandTimeoutMs fails once that long has passed, not sooner", () =>
        {
            Assert.Equal("timed out", TimedOut(pg, pool => pool.QueryAsync("SELECT pg_sleep(5)")));
        }, skip: !pgUp);

        // A socket outliving its close() is the visible half of a recv still armed into the freed buffer.
        runner.Test("pg: a timed-out connection's socket ends at the timeout, not when the late reply comes", () =>
        {
            HashSet<TcpSockets.Connection> earlier = TcpSockets.EstablishedTo(pg.Port);
            int port = TestServer.Start(PgHandlers.Pg, r => PgPool.Start(r, PgOpts(pg, commandTimeoutMs: 1000)));

            (int okStatus, string okBody) = Client.Get(port, "/");
            Assert.Equal(200, okStatus);
            Assert.Equal("42", okBody);

            HashSet<TcpSockets.Connection> pool = TcpSockets.WaitForNew(pg.Port, earlier, count: 2);
            Assert.True(pool.Count == 2, $"expected the pool's 2 connections ESTABLISHED to :{pg.Port}, found {pool.Count}");

            // The sleep outlasts the wait below, so its reply cannot be what ends the socket.
            (int status, string body) = Client.Get(port, "/sleep/30", timeoutMs: 15_000);
            Assert.Equal(500, status);
            Assert.True(body.Contains("timed out"), $"expected the command timeout, got [{body}]");

            List<TcpSockets.Connection> ended = TcpSockets.WaitForAnyToEnd(pool, timeoutMs: 10_000);
            Assert.True(ended.Count == 1,
                $"{ended.Count} of the pool's 2 connections ended within 10 s of the timeout; the timed-out one is still ESTABLISHED");

            // Control: the connection that did not time out is untouched, and the pool still answers.
            Assert.True(pool.Where(c => !ended.Contains(c)).All(TcpSockets.StillEstablished),
                "the connection that did not time out ended too");
            (int afterStatus, string afterBody) = Client.Get(port, "/");
            Assert.Equal(200, afterStatus);
            Assert.Equal("42", afterBody);
        }, skip: !pgUp);
    }

    // Runs query on a pool whose CommandTimeoutMs is 1000, and says whether it timed out only once that long had passed.
    private static string TimedOut((string Host, int Port) pg, Func<PgPool, ValueTask<PgResult>> query) => OnReactor.Run(async reactor =>
    {
        PgPool pool = PgPool.Start(reactor, PgOpts(pg, commandTimeoutMs: 1000));
        long made = Native.MonotonicMs;   // the sweep's clock, so the bound below needs no slack
        try
        {
            await query(pool);
            return "the query returned";
        }
        catch (PgException e) when (e.Message.Contains("timed out"))
        {
            long waited = Native.MonotonicMs - made;
            return waited > 1000 ? "timed out" : $"timed out after only {waited} ms";
        }
    });

    // What a query returned, or the type and message of what it threw.
    private static async Task<string> Outcome<T>(ValueTask<T> query)
    {
        try
        {
            return $"returned {await query}";
        }
        catch (Exception e)
        {
            return $"{e.GetType().Name}: {e.Message}";
        }
    }

    private static PgOptions PgOpts((string Host, int Port) pg, int commandTimeoutMs = 30_000) => new()
    {
        Host = pg.Host,
        Port = (ushort)pg.Port,
        User = Environment.GetEnvironmentVariable("EXAMPLES_PG_USER") ?? "bench",
        Database = Environment.GetEnvironmentVariable("EXAMPLES_PG_DB") ?? "bench",
        Password = Environment.GetEnvironmentVariable("EXAMPLES_PG_PASSWORD"),
        PoolSize = 2,
        CommandTimeoutMs = commandTimeoutMs,
    };
}
