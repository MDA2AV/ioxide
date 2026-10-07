using ioxide;
using ioxide.redis;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>The pool's timeout sweep, when the waiters it fails command the pool again from inside it.</summary>
internal static class RedisSweepTests
{
    public static void Register(Runner runner, (string Host, int Port) redis, bool redisUp)
    {
        // The failed waiter resumes inside the sweep, and its picks evict the timed-out connection from the list the sweep is indexing.
        runner.Test("redis: commands made by a timed-out command's handler run on the live connection the sweep keeps", () =>
        {
            int port = TestServer.Start(RecommandOnTimeout, r => RedisPool.Start(r, Options(redis)));

            (int status, string body) = Client.Get(port, "/timeout", timeoutMs: 15_000);
            Assert.Equal(200, status);
            Assert.Equal("listed=2 first=PONG second=PONG", body);

            (int afterStatus, string afterBody) = Client.Get(port, "/ping");
            Assert.Equal(200, afterStatus);
            Assert.Equal("PONG", afterBody);
        }, skip: !redisUp);
    }

    private static async Task RecommandOnTimeout(Reactor r, TcpConnection conn)
    {
        RedisPool pool = r.GetService<RedisPool>();

        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            string path = Wire.ReadPath(conn, snapshot);

            string body;
            if (path == "/timeout")
            {
                // Both open before the first pick, so the block lands on index 0 with a live connection after it.
                var timer = new RingTimer(r);
                while (pool.ConnectionCount < 2)
                {
                    await timer.DelayAsync(10);
                }

                try
                {
                    await pool.ExecuteAsync("BLPOP", "sweep:never-pushed", 30);
                    body = "the block returned";
                }
                catch (RedisException e) when (e.Message.Contains("timed out"))
                {
                    // Still listed here only if this runs inline in the sweep, before it removes the connection.
                    int listed = pool.ConnectionCount;
                    ValueTask<RespValue> first = pool.ExecuteAsync("PING");
                    ValueTask<RespValue> second = pool.ExecuteAsync("PING");
                    body = $"listed={listed} first={await Outcome(first)} second={await Outcome(second)}";
                }
            }
            else if (path == "/ping")
            {
                body = (await pool.ExecuteAsync("PING")).AsString() ?? "";
            }
            else
            {
                return;   // the harness's listen probe: it must not pick, or the block moves off index 0
            }

            Wire.Write(conn, 200, body);
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task<string> Outcome(ValueTask<RespValue> command)
    {
        try
        {
            return (await command).AsString() ?? "null";
        }
        catch (RedisException e)
        {
            return e.Message;
        }
    }

    private static RedisOptions Options((string Host, int Port) redis) => new()
    {
        Host = redis.Host,
        Port = (ushort)redis.Port,
        Password = Environment.GetEnvironmentVariable("EXAMPLES_REDIS_PASSWORD"),
        PoolSize = 2,
        CommandTimeoutMs = 1000,
    };
}
