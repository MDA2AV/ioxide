namespace Ioxide.Tests;

/// <summary>
/// Unit tests for the pure logic the runtime cannot afford to get wrong: the QUIC demux parse, the
/// Alt-Svc negotiation parser, and the shared HTTP message types. No sockets, no sidecars, no
/// timing - so these run anywhere and a failure is always a real defect rather than a flake.
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();

        VersionTests.Register(runner);
        SyscallErrnoTests.Register(runner);
        IoUringAbiTests.Register(runner);
        RingTests.Register(runner);
        RegisteredRingTests.Register(runner);
        BufferRingPageTests.Register(runner);
        ClockTests.Register(runner);
        RingSetupMessageTests.Register(runner);
        RingSetupSeccompTests.Register(runner);
        SpscRecvRingTests.Register(runner);
        MpscTests.Register(runner);
        ZeroCopySendTests.Register(runner);
        DemuxParseTests.Register(runner);
        MessageTests.Register(runner);
        ResponseCapTests.Register(runner);
        Http2OutputQueueTests.Register(runner);
        Http2StreamedRequestTests.Register(runner);
        Http2TrailerTests.Register(runner);
        Http2StreamedBodyTests.Register(runner);
        Http2FlowControlTests.Register(runner);
        Http2BufferedCreditTests.Register(runner);
        HpackEncodeTests.Register(runner);
        QpackStaticEncodeTests.Register(runner);
        AlpnSelectTests.Register(runner);
        SendWaitAllTests.Register(runner);
        AdapterParkTests.Register(runner);
        WaiterSlotTests.Register(runner);
        SpillSegmentTests.Register(runner);
        RecvQueueExtendTests.Register(runner);

        return runner.Summary();
    }
}
