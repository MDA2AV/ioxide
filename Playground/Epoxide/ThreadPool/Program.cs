using System.IO.Pipelines;
using epoxide;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  thread pool - Playground/Epoxide/Pipe with the handler on the thread pool for the whole of its
//  connection. Every read and every flush is made from a pool thread, and nothing hops back to the
//  reactor: a recv or send is an ordinary syscall, and the reactor only resumes a read or a flush
//  that had to wait - on the pool, where its caller was.
//
//  ioxide has no equivalent: its ring has a single issuer, so a pool thread's every operation is a
//  handoff to the reactor, and the first read that waits resumes the handler ON the reactor. Run it
//  against Epoxide/Pipe to price the pool's dispatch.
//
//      dotnet run -c Release --project Playground/Epoxide/ThreadPool
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
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

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

    // Task.Run: the connection's whole life runs on the pool, where no SynchronizationContext pulls
    // it back to the reactor.
    reactor.TcpHandle = (r, conn) => Task.Run(() => ServeAsync(conn));

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[epoxide-threadpool] {config.ReactorCount} reactors on :{config.Tcp.Port}, handlers on the thread pool");

foreach (Thread thread in threads)
{
    thread.Join();
}

async Task ServeAsync(TcpConnection conn)
{
    var reader = new TcpConnectionPipeReader(conn);
    var writer = new TcpConnectionPipeWriter(conn);

    try
    {
        while (true)
        {
            // A recv on this pool thread; when the socket is empty the reactor finishes it later
            // and this resumes on the pool again.
            ReadResult result = await reader.ReadAsync();
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
}
