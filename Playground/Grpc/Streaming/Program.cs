using Grpc.Core;
using ioxide;
using ioxide.grpc;
using ioxide.http2;
using ioxide.timer;
using Playground.Shared;
using Streaming;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  grpc-streaming - the three streaming kinds of gRPC call on ioxide.http2, over h2c.
//
//      dotnet run -c Release --project Playground/Grpc/Streaming
//      P="-plaintext -proto Playground/Grpc/Streaming/numbers.proto"
//      grpcurl $P -d '{"to": 5, "interval_ms": 500}' 127.0.0.1:8080 numbers.Numbers/Count
//      grpcurl $P -d '{"value": 1} {"value": 2} {"value": 3}' 127.0.0.1:8080 numbers.Numbers/Sum
//      grpcurl $P -d @ 127.0.0.1:8080 numbers.Numbers/Running   # each {"value": N} line is answered
//
//  Count streams replies, Sum reads a stream of requests, and Running does both at once, answering
//  each number while the client is still sending. Ctrl-C on a call cancels it: the method's
//  CancellationToken fires, and a write after it throws.
//  Needs: ioxide, ioxide.http2, ioxide.grpc, ioxide.timer
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

var grpc = new GrpcServices().Add(Numbers.BindService, new NumbersService());

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

Console.WriteLine($"[grpc-streaming] {config.ReactorCount} reactors on :{config.Tcp!.Port}, numbers.Numbers over h2c");

foreach (Thread thread in threads)
{
    thread.Join();
}

sealed class NumbersService : Numbers.NumbersBase
{
    public override async Task Count(CountRequest request, IServerStreamWriter<Number> responseStream, ServerCallContext context)
    {
        // A call starts on its connection's reactor; this timer waits on that reactor's ring, where
        // Task.Delay would carry the call off to the thread pool.
        var timer = new RingTimer(Reactor.Current!);

        for (int i = 1; i <= request.To && !context.CancellationToken.IsCancellationRequested; i++)
        {
            await responseStream.WriteAsync(new Number { Value = i });
            await timer.DelayAsync(request.IntervalMs);
        }
    }

    public override async Task<Total> Sum(IAsyncStreamReader<Number> requestStream, ServerCallContext context)
    {
        var total = new Total();
        while (await requestStream.MoveNext(context.CancellationToken))
        {
            total.Sum += requestStream.Current.Value;
            total.Count++;
        }
        return total;
    }

    public override async Task Running(IAsyncStreamReader<Number> requestStream, IServerStreamWriter<Total> responseStream,
        ServerCallContext context)
    {
        var total = new Total();
        while (await requestStream.MoveNext(context.CancellationToken))
        {
            total.Sum += requestStream.Current.Value;
            total.Count++;
            await responseStream.WriteAsync(total);
        }
    }
}
