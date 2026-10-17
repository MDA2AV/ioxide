namespace Epoxide.Tests;

/// <summary>
/// TLS termination. The default configuration is BoringSSL in both directions and needs no kernel
/// module, so most of the suite runs anywhere. The kTLS TX opt-in tests need the Linux 'tls'
/// module, which does not survive a reboot and does not autoload for an unprivileged process, so
/// it is loaded once per boot:
///
///     sudo modprobe tls
///
/// Those tests skip when the module is absent rather than reporting a failure.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var runner = new Runner(args);
        bool ktls = Sidecars.KtlsAvailable();
        Console.WriteLine($"kTLS {(ktls ? "available" : "absent - sudo modprobe tls")}\n");

        TlsTests.Register(runner, ktls);
        DecryptFaultTests.Register(runner, ktls);
        TlsPipeTests.Register(runner, ktls);
        OffReactorFlushTests.Register(runner);
        MutualTlsTests.Register(runner, ktls);
        MutualTlsConfigTests.Register(runner);
        SniTests.Register(runner, ktls);
        SniConfigTests.Register(runner);
        RotationTests.Register(runner, ktls);
        RotationLifecycleTests.Register(runner);
        KeyAndPostureReportingTests.Register(runner);
        RotationValidatingClientTests.Register(runner);
        PostureTests.Register(runner);
        FormatTests.Register(runner);
        ReadTimeoutTests.Register(runner, ktls);

        // Areas reserved for the failing-test review pass; empty until one lands.
        IdentitySubjectTests.Register(runner);
        SessionResumptionTests.Register(runner);
        PrologueReaderTests.Register(runner);
        TruncationTests.Register(runner);
        KernelRxHandoffTests.Register(runner, ktls);
        WriterContractTests.Register(runner);
        SessionLifetimeTests.Register(runner);
        AnchorSourceTests.Register(runner);
        RotationIntegrityTests.Register(runner);
        AlpnNegotiationTests.Register(runner);
        ContextBuildTests.Register(runner);

        // epoxide's own: sessions used from the thread pool, which ioxide's TLS does not allow.
        ThreadPoolTests.Register(runner);

        return runner.Summary();
    }
}

/// <summary>
/// The epoxide core bugs this suite's <see cref="Runner.KnownCoreBug"/> tests reproduce, as reported
/// with them: kept out of the green run until the core is fixed.
/// </summary>
internal static class CoreBugs
{
    public const string FinBehindShortRecv =
        "EPX-FIN: a parked read never sees a peer FIN that came in the same epoll edge as the peer's last bytes";
}
