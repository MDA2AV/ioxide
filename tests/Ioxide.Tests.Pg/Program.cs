namespace Ioxide.Tests;

/// <summary>
/// The Postgres driver against a real server. Skips entirely when none is reachable, so the suite
/// is safe to run anywhere:
///
///     docker run -d --name pg -p 5432:5432 -e POSTGRES_USER=bench -e POSTGRES_PASSWORD=bench \
///       -e POSTGRES_DB=bench -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();
        (string Host, int Port) pg = (
            Environment.GetEnvironmentVariable("IOXIDE_PG_HOST") ?? "127.0.0.1",
            int.TryParse(Environment.GetEnvironmentVariable("IOXIDE_PG_PORT"), out int p) ? p : 5432);

        bool up = Sidecars.Reachable(pg.Host, pg.Port);
        Console.WriteLine($"postgres {(up ? "up" : "down")} ({pg.Host}:{pg.Port})\n");

        PgTests.Register(runner, pg, up);
        PgScramTests.Register(runner);
        return runner.Summary();
    }
}
