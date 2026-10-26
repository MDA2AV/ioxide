using Greet;
using Grpc.Core;
using ioxide;
using ioxide.grpc;
using ioxide.http2;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  grpc-greeter - a gRPC service on ioxide.http2: the Greeter that Grpc.Tools generates from
//  greet.proto, served over h2c.
//
//      dotnet run -c Release --project Playground/Grpc/Greeter
//      grpcurl -plaintext -proto Playground/Grpc/Greeter/greet.proto \
//        -d '{"name": "ioxide"}' 127.0.0.1:8080 greet.Greeter/SayHello
//
//  The service is ordinary gRPC code: a class deriving the generated GreeterBase, bound through
//  the generated BindService. There is no reflection service, so a client needs the .proto.
//  Needs: ioxide, ioxide.http2, ioxide.grpc
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.

ushort port     = 8080;
int    reactors = Environment.ProcessorCount;

Env.Override(ref port, ref reactors);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,   // io_uring rings/threads - one per core
    RingEntries    = 8192,       // SQ/CQ depth per ring
    RecvBufferSize = 32 * 1024,  // bytes per shared recv buffer
    RecvSlots      = 4096,       // shared recv buffer-ring depth
    Tcp = new TcpOptions
    {
        Port          = port,
        ReadTimeoutMs = 60_000,  // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs = 60_000,  // close a connection whose flush takes this long to go out; 0 = off
    },
};

// Bind every service before serving: every reactor reads the table at once.
var grpc = new GrpcServices().Add(Greeter.BindService, new GreeterService());

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            await new Http2Connection(conn).RunAsync(grpc.HandleAsync);
        }
        finally
        {
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[grpc-greeter] {config.ReactorCount} reactors on :{config.Tcp!.Port}, greet.Greeter over h2c");

foreach (Thread thread in threads)
{
    thread.Join();
}

sealed class GreeterService : Greeter.GreeterBase
{
    public override Task<HelloReply> SayHello(HelloRequest request, ServerCallContext context)
        => Task.FromResult(new HelloReply { Message = $"Hello, {request.Name}" });
}
