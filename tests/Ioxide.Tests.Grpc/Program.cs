namespace Ioxide.Tests;

/// <summary>
/// gRPC over both HTTP/2 stacks, driven by Grpc.Net.Client: the four kinds of call, status and
/// metadata, and cancellation. Real reactors over real sockets; needs nothing external.
/// </summary>
internal static class Program
{
    private static int Main()
    {
        var runner = new Runner();

        GrpcCallTests.Register(runner);
        GrpcStatusTests.Register(runner);
        GrpcCancelTests.Register(runner);

        return runner.Summary();
    }
}
