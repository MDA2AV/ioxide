namespace Ioxide.Tests;

/// <summary>
/// The chaos suite: weird, hostile and malformed inputs against every transport ioxide serves -
/// TCP, TLS, HTTP/2 (h2c) and QUIC/HTTP/3. Fragmentation, coalescing, oversize and undersize,
/// binary garbage, abrupt resets and slow drips.
///
/// The bar is not throughput - the benchmarks own that - but SURVIVAL. Two invariants hold after
/// every assault: a fresh, well-formed request is still answered, and no reactor died unobserved
/// (the runner's summary fails the run if one did). A handler that merely stops answering, or a
/// reactor that quietly wedges, is as much a failure here as a crash.
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();

        ReactorChaosTests.Register(runner);
        TcpChaosTests.Register(runner);
        TlsChaosTests.Register(runner);
        H2ChaosTests.Register(runner);
        Nghttp2ChaosTests.Register(runner);
        Nghttp2StreamedRequestTests.Register(runner);
        QuicChaosTests.Register(runner);
        H3ChaosTests.Register(runner);

        return runner.Summary();
    }
}
