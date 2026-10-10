namespace Ioxide.Tests;

/// <summary>
/// The ring-native HTTP client, all three protocols and the negotiating layer on top. h1 and h3
/// run against ioxide's own servers, so they need nothing external; h2c needs a real HTTP/2
/// server and skips without one:
///
///     docker run -d --name h2c --network host -v ...:/etc/nginx/nginx.conf:ro nginx
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();

        HttpClientTests.Register(runner);
        HttpClientLeftoverTests.Register(runner);
        TlsClientTests.Register(runner);

        // Areas reserved for the failing-test review pass; empty until one lands.
        TlsClientVerificationTests.Register(runner);
        TlsClientErrorQueueTests.Register(runner);
        TlsClientPostureTests.Register(runner);
        CrossStackParityTests.Register(runner);

        return runner.Summary();
    }
}
