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

        runner.Test("pg: command timeout (#2)", () =>
        {
            int port = TestServer.Start(PgHandlers.PgSlow, r => PgPool.Start(r, PgOpts(pg, commandTimeoutMs: 1000)));
            (int status, _) = Client.Get(port, "/slow", timeoutMs: 8000);
            Assert.Equal(503, status);
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
