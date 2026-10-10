using System.Text;
using ioxide;
using ioxide.pg;

namespace Ioxide.Tests;

/// <summary>Handlers that drive a PgPool, kept beside the suite that exercises them.</summary>
internal static class PgHandlers
{
    public static async Task Pg(Reactor r, TcpConnection conn)
    {
        PgPool pool = r.GetService<PgPool>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = Wire.ReadPath(conn, snapshot);

                try
                {
                    if (path.StartsWith("/add/", StringComparison.Ordinal) && long.TryParse(path["/add/".Length..], out long n))
                    {
                        PgResult result = await pool.QueryAsync("SELECT $1::bigint + 1", [PgParam.Int(n)]);
                        Wire.Write(conn, 200, result.Value ?? "");
                    }
                    else if (path == "/rows")
                    {
                        int rows = await pool.QueryRowsAsync("SELECT n FROM generate_series(1, 5) AS n", _ => { });
                        Wire.Write(conn, 200, $"rows={rows}");
                    }
                    else if (path == "/bad")
                    {
                        await pool.QueryAsync("SELECT * FROM no_such_table");
                        Wire.Write(conn, 200, "unreachable");
                    }
                    else if (path.StartsWith("/sleep/", StringComparison.Ordinal) && int.TryParse(path["/sleep/".Length..], out int seconds))
                    {
                        await pool.QueryAsync($"SELECT pg_sleep({seconds})");
                        Wire.Write(conn, 200, "slept");
                    }
                    else
                    {
                        PgResult result = await pool.QueryAsync("SELECT 42");
                        Wire.Write(conn, 200, result.Value ?? "");
                    }
                }
                catch (PgException e)
                {
                    Wire.Write(conn, 500, e.SqlState ?? e.Message);
                }

                await conn.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    public static async Task PgSlow(Reactor r, TcpConnection conn)
    {
        PgPool pool = r.GetService<PgPool>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                Wire.ReadPath(conn, snapshot);

                try
                {
                    await pool.QueryAsync("SELECT pg_sleep(5)");
                    Wire.Write(conn, 200, "ok");
                }
                catch (PgException)
                {
                    Wire.Write(conn, 503, "timeout");
                }

                await conn.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }
}
