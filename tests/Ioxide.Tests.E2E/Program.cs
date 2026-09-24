namespace Ioxide.Tests;

/// <summary>
/// The engine suite: reactor lifecycle, the TCP read and write paths, hardening against malformed
/// or hostile peers, UDP, the QUIC transport and its ngtcp2 engine, and the two HTTP/3 layers.
/// Everything here runs against real servers over real sockets and needs no external dependency.
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();

        CoreTests.Register(runner);
        TimerTests.Register(runner);
        AffinityTests.Register(runner);
        HardeningTests.Register(runner);
        RecvBufferReclaimTests.Register(runner);
        PipeReaderContractTests.Register(runner);
        TcpTimeoutTests.Register(runner);
        ReactorSetupTeardownTests.Register(runner);
        UdpTests.Register(runner);
        QuicTests.Register(runner);
        QuicEngineTests.Register(runner);
        H3Tests.Register(runner);
        QuicMutualTlsTests.Register(runner);
        QuicSniTests.Register(runner);
        QuicRotationTests.Register(runner);
        Http3Tests.Register(runner);

        // Areas reserved for the failing-test review pass; empty until one lands.
        QuicIdentityCapTests.Register(runner);
        QuicTeardownWireTests.Register(runner);
        QuicReadTimeoutTests.Register(runner);
        QuicDeferredFaultTests.Register(runner);
        QuicStreamAllowanceTests.Register(runner);
        QuicTimerTests.Register(runner);
        QuicSniHostileTests.Register(runner);
        QuicDemuxRoutingTests.Register(runner);
        QuicMigrationTests.Register(runner);
        QuicClientCertTimingTests.Register(runner);
        H3BodyTruncationTests.Register(runner);
        H3ErrorCodeTests.Register(runner);
        H3AlpnTests.Register(runner);
        Http2BodyTests.Register(runner);
        Http2ReadTimeoutTests.Register(runner);
        Http3BodyTests.Register(runner);

        return runner.Summary();
    }
}
