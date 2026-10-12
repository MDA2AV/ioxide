namespace Ioxide.Tests;

/// <summary>
/// The Redis client against a real server. Skips entirely when none is reachable:
///
///     docker run -d --name redis -p 6379:6379 redis:7-alpine
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();
        (string Host, int Port) redis = (
            Environment.GetEnvironmentVariable("IOXIDE_REDIS_HOST") ?? "127.0.0.1",
            int.TryParse(Environment.GetEnvironmentVariable("IOXIDE_REDIS_PORT"), out int p) ? p : 6379);

        bool up = Sidecars.Reachable(redis.Host, redis.Port);
        Console.WriteLine($"redis {(up ? "up" : "down")} ({redis.Host}:{redis.Port})\n");

        RedisTests.Register(runner, redis, up);
        return runner.Summary();
    }
}
