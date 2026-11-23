using System.IO.Pipelines;
using epoxide;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  pipe on epoll - Playground/Tcp/Pipe line for line, on epoxide instead of ioxide: the same
//  workload, read and written through the System.IO.Pipelines adapters. Run the two against each
//  other to price epoll against io_uring with everything else held equal.
//
//      dotnet run -c Release --project Playground/Epoxide/Pipe
//      curl http://127.0.0.1:8080/
//
//  Needs: epoxide
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. An Env.Override line means the value can also be set from the environment, which is
// how bench/any.sh drives the sample; the literal is what applies otherwise.

ushort port      = 8080;
int    reactors  = Environment.ProcessorCount;
int    bodyBytes = 2;

Env.Override(ref port, ref reactors, ref bodyBytes);
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // epoll sets/threads - one per core
    MaxEvents      = 1024,                                 // events one epoll_wait takes in
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per pooled recv buffer
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored sendmsg
        RecvQueueEntries = 64,                             // per-connection recv queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

// PLAYGROUND_BODY sizes the body (2 = "ok"), matching Tcp.Pipe so the two are comparable.
byte[] body = bodyBytes == 2 ? "ok"u8.ToArray() : [.. Enumerable.Repeat((byte)'x', bodyBytes - 1), (byte)'\n'];
byte[] response =
[
    .. System.Text.Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n"),
    .. body,
];

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        var reader = new TcpConnectionPipeReader(conn);
        var writer = new TcpConnectionPipeWriter(conn);

        try
        {
            while (true)
            {
                // A recv behind the PipeReader surface - resumes inline on the reactor.
                ReadResult result = await reader.ReadAsync();

                // This sample doesn't parse the request either: consume everything. A real handler
                // would walk result.Buffer for complete requests and AdvanceTo(consumed, examined)
                // so a partial one stays buffered for the next read.
                reader.AdvanceTo(result.Buffer.End);

                response.CopyTo(writer.GetSpan(response.Length));
                writer.Advance(response.Length);
                await writer.FlushAsync();

                if (result.IsCompleted) return;
            }
        }
        finally
        {
            reader.Complete();
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[epoxide-pipe] {config.ReactorCount} reactors on :{config.Tcp.Port}");

foreach (Thread thread in threads)
{
    thread.Join();
}
