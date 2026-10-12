using ioxide;
using ioxide.pg;

namespace Ioxide.Tests;

/// <summary>The prepared-statement cache against the statements the server actually holds.</summary>
internal static class PgPreparedTests
{
    public static void Register(Runner runner, (string Host, int Port) pg, bool pgUp)
    {
        // The Parse succeeds and the Bind rejects the value, so the statement exists on the server.
        runner.Test("pg: a statement whose Bind fails stays prepared, so the next call does not parse it again", () =>
        {
            string body = Run(pg, "SELECT $1::int + 0", "x", "y", "z", "41");
            Assert.Equal("22P02,22P02,22P02,41;statements=1", body);
        }, skip: !pgUp);

        runner.Test("pg: a statement whose Execute fails stays prepared, so the next call does not parse it again", () =>
        {
            string body = Run(pg, "SELECT 1 / $1::int", "0", "0", "0", "1");
            Assert.Equal("22012,22012,22012,1;statements=1", body);
        }, skip: !pgUp);

        // Control: the eviction the two above must not lose. A kept name would Bind to nothing (26000).
        runner.Test("control: a statement whose Parse fails is parsed again on the next call", () =>
        {
            string body = Run(pg, "SELECT $1::int FROM no_such_table_prepared", "1", "1");
            Assert.Equal("42P01,42P01;statements=0", body);
        }, skip: !pgUp);
    }

    // Runs sql once per value on one connection, then counts that connection's server-side statements for it.
    private static string Run((string Host, int Port) pg, string sql, params string[] values)
    {
        int port = TestServer.Start((r, conn) => Handle(r, conn, Options(pg), sql, values));
        (int status, string body) = Client.Get(port, "/run");
        Assert.Equal(200, status);
        return body;
    }

    private static async Task Handle(Reactor r, TcpConnection conn, PgOptions options, string sql, string[] values)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            if (Wire.ReadPath(conn, snapshot) != "/run")
            {
                return;   // the harness's listen probe
            }

            string body;
            PgConnection pg = await PgConnection.ConnectAsync(r, options);
            try
            {
                var outcomes = new List<string>();
                foreach (string value in values)
                {
                    try
                    {
                        outcomes.Add((await pg.QueryAsync(sql, [PgParam.Text(value)])).Value ?? "null");
                    }
                    catch (PgException e)
                    {
                        outcomes.Add(e.SqlState ?? e.Message);
                    }
                }

                PgResult held = await pg.QueryAsync(
                    $"SELECT count(*) FROM pg_prepared_statements WHERE statement = '{sql}'");
                body = $"{string.Join(',', outcomes)};statements={held.Value}";
            }
            finally
            {
                pg.Dispose();
            }

            Wire.Write(conn, 200, body);
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static PgOptions Options((string Host, int Port) pg) => new()
    {
        Host = pg.Host,
        Port = (ushort)pg.Port,
        User = Environment.GetEnvironmentVariable("EXAMPLES_PG_USER") ?? "bench",
        Database = Environment.GetEnvironmentVariable("EXAMPLES_PG_DB") ?? "bench",
        Password = Environment.GetEnvironmentVariable("EXAMPLES_PG_PASSWORD"),
    };
}
