using System.Buffers.Text;
using System.Text.Unicode;
using ioxide;
using ioxide.timer;
using ioxide.utils;
using Playground.Shared;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  timer - a deadline that never leaves the ring. GET /<ms> answers after that many
//  milliseconds, and the wait is an io_uring timeout: one submission out, one completion back,
//  resumed inline on the reactor that took the request. Nothing is allocated per wait, and the
//  kernel is what holds the deadline - so a connection waiting costs no timer of ours.
//
//      dotnet run -c Release --project Playground/Clients/Timer
//      curl http://127.0.0.1:8080/50
//
//  Needs: ioxide, ioxide.timer
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ── Knobs ────────────────────────────────────────────────────────────────────────────────────
// Edit these. That is the whole mechanism - there is no config file and nothing else to find.
// Env.Override exists only so bench/run.sh can drive the sample from outside; delete those lines
// when you copy this out and the literals above them are the entire configuration.

ushort port     = 8080;                        // http://127.0.0.1:8080/
int    reactors = Environment.ProcessorCount;  // one ring per reactor, one reactor per core

Env.Override(ref port, ref reactors);

// The wait when the path names no number, so plain `curl http://127.0.0.1:8080/` shows the
// feature. A path that does name one wins, up to the ceiling - which is here because the delay
// comes from the request, and an unbounded one would let a client hold a connection all day.
int defaultDelayMs = 25;
int maxDelayMs     = 60_000;

// true = await Task.Delay instead of the ring, so the two are measurable against each other
// rather than asserted. Same server, same response; only the wait changes.
bool useTaskDelay = false;

Env.Override(ref defaultDelayMs, "PLAYGROUND_DELAY_MS");
Env.Override(ref useTaskDelay, "PLAYGROUND_TASK_DELAY");
// ─────────────────────────────────────────────────────────────────────────────────────────────

var config = new ServerConfig
{
    ReactorCount   = reactors,                             // io_uring rings/threads - one per core
    RingEntries    = 8192,                                 // SQ/CQ depth per ring
    DualStack      = false,                                // true = one IPv6 socket also accepts IPv4-mapped
    RecvBufferSize = 32 * 1024,                            // bytes per shared recv buffer
    RecvSlots      = 4096,                                 // shared recv buffer-ring depth
    Incremental    = null,                                 // per-connection recv rings (6.12+) - see Tcp/Incremental
    Udp            = null,                                 // no raw UDP sockets (TCP-only server)
    Quic           = null,                                 // no QUIC transport - see Http3/* and Quic/Alpn
    Tcp = new TcpOptions
    {
        Port             = port,
        ExtraPorts       = [],                             // extra listener ports (one handler, several doors)
        ListenBacklog    = 1024,                           // accept-queue depth per SO_REUSEPORT listener
        WriteSlabSize    = 16 * 1024,                      // per-connection write buffer before overflow kicks in
        PoolMax          = 1024,                           // pooled connection objects kept per reactor
        WriteOverflow    = WriteOverflowStrategy.Grow,     // Grow = realloc one slab; Segmented = chain + vectored SENDMSG
        ZeroCopySend     = false,                          // SEND_ZC: kernel copies less, wins on large writes
        RecvQueueEntries = 4096,                           // per-connection recv completion queue depth
        ReadTimeoutMs    = 60_000,                         // close a connection whose read waits this long on a silent peer; 0 = off
        SendTimeoutMs    = 60_000,                         // close a connection whose flush takes this long to go out; 0 = off
    },
};

var threads = new Thread[config.ReactorCount];

for (int i = 0; i < threads.Length; i++)
{
    var reactor = new Reactor(i, config);

    reactor.TcpHandle = async (r, conn) =>
    {
        // One timer for the connection's whole life, re-armed per request. A timer carries ONE
        // wait at a time - one request's worth on HTTP/1.1; waiting on several deadlines at
        // once wants a timer each. The reactor is what it submits to, so the deadline rides the
        // ring this connection already lives on.
        var timer = new RingTimer(r);

        // The body names the wait, so the response cannot be pre-encoded the way Tcp/Raw's is.
        // Per connection rather than per request, so it still allocates nothing per answer.
        byte[] response = new byte[128];

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                int ms = defaultDelayMs;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        ms = ParseDelay(item.AsSpan(), defaultDelayMs);
                        conn.ReturnBuffer(in item);
                    }
                }

                ms = Math.Clamp(ms, 0, maxDelayMs);

                int result;
                if (useTaskDelay)
                {
                    // The deadline goes to the thread-pool timer queue and the continuation is
                    // posted back - the round trip Tcp/Hop is about.
                    await Task.Delay(ms);
                    result = RingTimer.ETime;
                }
                else
                {
                    // The wait rides this reactor's ring and resumes on this thread, with the
                    // connection's state still warm.
                    result = await timer.DelayAsync(ms);
                }

                // An expired timeout reports -ETIME, which is this call's SUCCESS - so the check
                // is Expired(), not result >= 0. Anything else is an errno.
                conn.Write(response.AsSpan(0, Format(response, ms, result)));
                await conn.FlushAsync();

                if (snapshot.IsClosed) return;
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    };

    threads[i] = new Thread(reactor.Run) { Name = $"reactor-{i}" };
    threads[i].Start();
}

Console.WriteLine($"[timer] {config.ReactorCount} reactors on :{config.Tcp.Port} - GET /<ms> waits that long "
                + $"({(useTaskDelay ? "Task.Delay" : "RingTimer")}, default {defaultDelayMs}ms)");

foreach (Thread thread in threads)
{
    thread.Join();
}

// "GET /50 HTTP/1.1" -> 50. The request line is in the first buffer of any request worth the
// name, so this looks at one and does not reassemble across reads.
static int ParseDelay(ReadOnlySpan<byte> request, int fallback)
{
    int afterMethod = request.IndexOf((byte)' ');
    if (afterMethod < 0) return fallback;

    ReadOnlySpan<byte> target = request[(afterMethod + 1)..];
    int end = target.IndexOf((byte)' ');
    if (end < 0) return fallback;

    target = target[..end].TrimStart((byte)'/');
    return Utf8Parser.TryParse(target, out int ms, out int consumed) && consumed == target.Length
        ? ms
        : fallback;
}

// The response, formatted into the connection's own buffer: how long the wait was, or the errno
// if the completion was not an expiry.
static int Format(Span<byte> destination, int ms, int result)
{
    Span<byte> body = stackalloc byte[24];
    int bodyLength;

    if (RingTimer.Expired(result))
    {
        Utf8.TryWrite(body, $"{ms}ms", out bodyLength);
    }
    else
    {
        Utf8.TryWrite(body, $"errno {result}", out bodyLength);
    }

    Utf8.TryWrite(destination,
        $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {bodyLength}\r\n\r\n",
        out int headerLength);

    body[..bodyLength].CopyTo(destination[headerLength..]);
    return headerLength + bodyLength;
}
