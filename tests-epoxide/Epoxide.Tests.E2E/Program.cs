namespace Epoxide.Tests;

/// <summary>
/// The engine suite: reactor lifecycle, the TCP read and write paths, hardening against malformed
/// or hostile peers, the clocks, and what is epoxide's own - connections read and written from the
/// thread pool, and outbound connects. Everything here runs against real servers over real sockets
/// and needs no external dependency.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var runner = new Runner(args);

        CoreTests.Register(runner);
        TimerTests.Register(runner);
        AffinityTests.Register(runner);
        HardeningTests.Register(runner);
        RecvBufferReclaimTests.Register(runner);
        SendInFlightRecycleTests.Register(runner);
        PipeReaderContractTests.Register(runner);
        StreamContractTests.Register(runner);
        TcpTimeoutTests.Register(runner);
        AcceptExhaustionTests.Register(runner);
        ExecInheritanceTests.Register(runner);
        ReactorSetupTeardownTests.Register(runner);
        ThreadPoolTests.Register(runner);
        ConnectTests.Register(runner);

        return runner.Summary();
    }
}
