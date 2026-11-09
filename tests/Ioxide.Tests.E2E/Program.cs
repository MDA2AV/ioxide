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
        ListenerReleaseTests.Register(runner);
        ListenerAddressTests.Register(runner);
        TimerTests.Register(runner);
        AffinityTests.Register(runner);
        KestrelTests.Register(runner);
        HardeningTests.Register(runner);
        IncrementalTests.Register(runner);
        RecvBufferReclaimTests.Register(runner);
        IncrementalDryRingTests.Register(runner);
        LetGoBufferTests.Register(runner);
        LetGoHandlerStyleTests.Register(runner);
        KestrelLetGoTests.Register(runner);
        SendInFlightRecycleTests.Register(runner);
        PipeReaderContractTests.Register(runner);
        WriteContractTests.Register(runner);
        StreamContractTests.Register(runner);
        PipeValidityTests.Register(runner);
        TcpTimeoutTests.Register(runner);
        AcceptExhaustionTests.Register(runner);
        ExecInheritanceTests.Register(runner);
        ReactorSetupTeardownTests.Register(runner);
        PostTests.Register(runner);
        GcTests.Register(runner);
        RingTimerTests.Register(runner);
        UdpTests.Register(runner);
        QuicTests.Register(runner);
        QuicEngineTests.Register(runner);
        H3Tests.Register(runner);
        QuicMutualTlsTests.Register(runner);
        QuicPeerCertificateTests.Register(runner);
        QuicSniTests.Register(runner);
        QuicRotationTests.Register(runner);
        Http3Tests.Register(runner);

        // Areas reserved for the failing-test review pass; empty until one lands.
        QuicIdentityCapTests.Register(runner);
        QuicTeardownWireTests.Register(runner);
        QuicReadTimeoutTests.Register(runner);
        QuicUnansweredStreamTests.Register(runner);
        QuicDeferredFaultTests.Register(runner);
        QuicStreamAllowanceTests.Register(runner);
        QuicSendStreamTests.Register(runner);
        QuicTimerTests.Register(runner);
        QuicSniHostileTests.Register(runner);
        QuicDemuxRoutingTests.Register(runner);
        QuicMigrationTests.Register(runner);
        QuicFleetJoinTests.Register(runner);
        QuicClientCertTimingTests.Register(runner);
        H3BodyTruncationTests.Register(runner);
        H3StopSendingTests.Register(runner);
        H3HeldChunkTests.Register(runner);
        H3ErrorCodeTests.Register(runner);
        Nghttp3ManyFieldsTests.Register(runner);
        H3CriticalStreamTests.Register(runner);
        H3AlpnTests.Register(runner);
        Http2BodyTests.Register(runner);
        Http2StreamedFaultTests.Register(runner);
        Http2BufferedFaultTests.Register(runner);
        Nghttp2ManyHeadersTests.Register(runner);
        StreamedPeerGoneTests.Register(runner);
        QuicStreamingCreditTests.Register(runner);
        Http3BodyTests.Register(runner);
        Http3RequestReuseTests.Register(runner);
        H3BodyModeTests.Register(runner);
        H3BufferedFaultTests.Register(runner);
        H3BodyLimitTests.Register(runner);
        H3LargeResponseTests.Register(runner);
        OffReactorStreamTests.Register(runner);
        OffReactorH2FixTests.Register(runner);
        OffReactorH3FixTests.Register(runner);
        KestrelTlsTests.Register(runner);
        KestrelListenAddressTests.Register(runner);
        KestrelBindFailureTests.Register(runner);
        KestrelAddressParityTests.Register(runner);
        KestrelBadRecordTests.Register(runner);

        return runner.Summary();
    }
}
