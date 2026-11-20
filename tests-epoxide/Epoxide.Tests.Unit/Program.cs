namespace Epoxide.Tests;

/// <summary>
/// Unit tests for what the runtime cannot afford to get wrong and that needs no server: the version
/// it reports, the clock every deadline reads, the errno its syscall wrappers hand back, and the
/// config sizes it refuses at construction. No sockets that carry traffic, no timing - so these run
/// anywhere and a failure is always a real defect rather than a flake.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var runner = new Runner(args);

        VersionTests.Register(runner);
        SyscallErrnoTests.Register(runner);
        ClockTests.Register(runner);
        ConfigValidationTests.Register(runner);

        return runner.Summary();
    }
}
