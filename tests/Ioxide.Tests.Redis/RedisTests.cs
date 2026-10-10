using ioxide.redis;

namespace Ioxide.Tests;

/// <summary>Redis client over the ring: RESP2 strings/integers and pipelining.</summary>
internal static class RedisTests
{
    public static void Register(Runner runner, (string Host, int Port) redis, bool redisUp)
    {
        runner.Test("redis: SET then GET", () =>
        {
            int port = TestServer.Start(RedisHandlers.Redis, r => RedisPool.Start(r, RedisOpts(redis)));
            (int status, string body) = Client.Get(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("hello", body);
        }, skip: !redisUp);

        runner.Test("redis: INCR (RESP integer)", () =>
        {
            int port = TestServer.Start(RedisHandlers.Redis, r => RedisPool.Start(r, RedisOpts(redis)));
            (int status, string body) = Client.Get(port, "/incr");
            Assert.Equal(200, status);
            Assert.True(long.TryParse(body, out long n) && n >= 1, $"expected a positive integer, got [{body}]");
        }, skip: !redisUp);

        runner.Test("redis: pipeline SET/INCR/GET", () =>
        {
            int port = TestServer.Start(RedisHandlers.Redis, r => RedisPool.Start(r, RedisOpts(redis)));
            (int status, string body) = Client.Get(port, "/pipe");
            Assert.Equal(200, status);
            Assert.Equal("2", body);
        }, skip: !redisUp);

        // A socket outliving its close() is the visible half of a recv still armed into the freed buffer.
        runner.Test("redis: a timed-out connection's socket ends at the timeout, not when the late reply comes", () =>
        {
            HashSet<TcpSockets.Connection> earlier = TcpSockets.EstablishedTo(redis.Port);
            int port = TestServer.Start(RedisHandlers.Redis, r => RedisPool.Start(r, RedisOpts(redis, commandTimeoutMs: 1000)));

            (int okStatus, string okBody) = Client.Get(port, "/");
            Assert.Equal(200, okStatus);
            Assert.Equal("hello", okBody);

            HashSet<TcpSockets.Connection> pool = TcpSockets.WaitForNew(redis.Port, earlier, count: 2);
            Assert.True(pool.Count == 2, $"expected the pool's 2 connections ESTABLISHED to :{redis.Port}, found {pool.Count}");

            // The block outlasts the wait below, so its reply cannot be what ends the socket.
            (int status, string body) = Client.Get(port, "/block/30", timeoutMs: 15_000);
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
            Assert.Equal("hello", afterBody);
        }, skip: !redisUp);
    }

    private static RedisOptions RedisOpts((string Host, int Port) redis, int commandTimeoutMs = 30_000) => new()
    {
        Host = redis.Host,
        Port = (ushort)redis.Port,
        Password = Environment.GetEnvironmentVariable("EXAMPLES_REDIS_PASSWORD"),
        PoolSize = 2,
        CommandTimeoutMs = commandTimeoutMs,
    };
}
