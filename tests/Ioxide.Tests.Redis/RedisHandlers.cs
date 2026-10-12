using System.Text;
using ioxide;
using ioxide.redis;

namespace Ioxide.Tests;

/// <summary>Handlers that drive a RedisPool, kept beside the suite that exercises them.</summary>
internal static class RedisHandlers
{
    public static async Task Redis(Reactor r, TcpConnection conn)
    {
        RedisPool pool = r.GetService<RedisPool>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = Wire.ReadPath(conn, snapshot);

                if (path == "/incr")
                {
                    long n = (await pool.ExecuteAsync("INCR", "e2e:n")).AsInteger();
                    Wire.Write(conn, 200, n.ToString());
                }
                else if (path == "/pipe")
                {
                    RespValue[] replies = await pool.PipelineAsync(
                        new RedisCommand("SET", "e2e:p", "1"),
                        new RedisCommand("INCR", "e2e:p"),
                        new RedisCommand("GET", "e2e:p"));
                    Wire.Write(conn, 200, replies[2].AsString() ?? "");
                }
                else
                {
                    await pool.SetExAsync("e2e:k", "hello", 60);
                    string? value = await pool.GetAsync("e2e:k");
                    Wire.Write(conn, 200, value ?? "");
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
