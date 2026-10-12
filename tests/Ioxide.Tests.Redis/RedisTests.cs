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
    }

    private static RedisOptions RedisOpts((string Host, int Port) redis) => new()
    {
        Host = redis.Host,
        Port = (ushort)redis.Port,
        Password = Environment.GetEnvironmentVariable("EXAMPLES_REDIS_PASSWORD"),
        PoolSize = 2,
    };
}
