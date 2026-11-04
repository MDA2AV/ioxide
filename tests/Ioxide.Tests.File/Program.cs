namespace Ioxide.Tests;

/// <summary>Static file serving: the asset cache, ring reads, and disk revalidation.</summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();
        FileTests.Register(runner);
        LeaseTests.Register(runner);
        return runner.Summary();
    }
}
