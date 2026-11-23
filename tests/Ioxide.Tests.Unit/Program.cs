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
        Http2OutputQueueTests.Register(runner);
        Http2StreamedRequestTests.Register(runner);
        Http2TrailerTests.Register(runner);
        Http2PseudoHeaderTests.Register(runner);
        Http2ContentLengthTests.Register(runner);
        Nghttp2StreamCloseTests.Register(runner);
        Http2HeaderListTests.Register(runner);
        Nghttp2HeaderListTests.Register(runner);
        Nghttp2OversizedResponseTests.Register(runner);
        Nghttp2NullAnswerTests.Register(runner);
        Http2RequestHeaderTests.Register(runner);
        Http2RequestReuseTests.Register(runner);
        Nghttp2RequestReuseTests.Register(runner);
        Nghttp2HasBodyTests.Register(runner);
        Http2StreamedBodyTests.Register(runner);
        Http2FlowControlTests.Register(runner);
        Http2ReceiveWindowTests.Register(runner);
        Http2CreditStepTests.Register(runner);
        Http2BufferedCreditTests.Register(runner);
        Http2EarlyAnswerTests.Register(runner);
        Http2EarlyAnswerGuardTests.Register(runner);
        Nghttp2ResetResponseTests.Register(runner);
        Nghttp2EarlyAnswerTests.Register(runner);
        Http2PeerClosedFlushTests.Register(runner);
        Http2StreamResetTests.Register(runner);
        Http2ControlFrameTests.Register(runner);
        Http2PriorityResetTests.Register(runner);
        Http2StreamStateTests.Register(runner);
        Http2ClosedStreamTests.Register(runner);
        Http2MalformedRequestTests.Register(runner);
        Http2MalformedTrailerTests.Register(runner);
        Http2FieldValidityTests.Register(runner);
        HpackEncodeTests.Register(runner);
        Http2HpackDecodeTests.Register(runner);
        QpackStaticEncodeTests.Register(runner);
        AlpnSelectTests.Register(runner);
        KeylogSecretTests.Register(runner);
        SendWaitAllTests.Register(runner);
        AdapterParkTests.Register(runner);
        WaiterSlotTests.Register(runner);
        SendClockTests.Register(runner);
        SpillSegmentTests.Register(runner);
        RecvQueueExtendTests.Register(runner);
        StoppedPostTests.Register(runner);
        StoppedReturnTests.Register(runner);
        HttpClientGrowthTests.Register(runner);

        return runner.Summary();
    }
}
