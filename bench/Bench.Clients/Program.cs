// Load driver for the ring-native HTTP/1.1 client:
//
//     Bench.Clients <host> <port> <seconds> [concurrency]
//
// BENCH_REACTORS reactors (default 4) each drive `concurrency` request loops over BENCH_POOL
// pooled connections (default 4); every await resumes inline on its reactor. BENCH_TLS=1 speaks
// TLS without verifying the certificate - the Playground's is self-signed - which makes this a
// driver for the h1s samples where wrk is not installed (bench/ab.sh). Prints one
// machine-readable line:
//
//     client-h1 4r: 812345 req/s (4874070 ok, 0 failed)
using System.Diagnostics;
using ioxide;
using ioxide.httpclient;

string host     = args[0];
ushort port     = ushort.Parse(args[1]);
int seconds     = int.Parse(args[2]);
int concurrency = args.Length > 3 ? int.Parse(args[3]) : 64;
int reactors    = int.TryParse(Environment.GetEnvironmentVariable("BENCH_REACTORS"), out int r) ? r : 4;
int poolSize    = int.TryParse(Environment.GetEnvironmentVariable("BENCH_POOL"), out int p) ? p : 4;
bool useTls     = Environment.GetEnvironmentVariable("BENCH_TLS") == "1";

TlsClientContext? tls = useTls
    ? TlsClientContext.Create(new TlsClientOptions
    {
        ServerName = "localhost",
        VerifyCertificate = false,
        AlpnProtocols = ["http/1.1"],
    })
    : null;

long completed = 0, failed = 0;
var stop = new ManualResetEventSlim(false);
byte[] path = System.Text.Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("BENCH_PATH") ?? "/");

var threads = new Thread[reactors];
for (int i = 0; i < reactors; i++)
{
    var config = new ServerConfig
    {
        ReactorCount = reactors,
        RecvBufferSize = 4096,
        RecvSlots = 256,
        Tcp = null,   // client-only reactors: nothing listens
        Udp = null,
    };
    var reactor = new Reactor(i, config)
    {
        OnStart = r =>
        {
            HttpClientPool pool = HttpClientPool.Start(r, new HttpClientOptions
                { Host = host, Port = port, PoolSize = poolSize, Tls = tls });
            for (int loop = 0; loop < concurrency; loop++)
            {
                _ = LoopAsync(() => pool.GetAsync(path));
            }
        },
    };
    threads[i] = new Thread(reactor.Run) { IsBackground = true, Name = $"bench-{i}" };
    threads[i].Start();
}

async Task LoopAsync(Func<ValueTask<HttpClientResponse>> send)
{
    while (!stop.IsSet)
    {
        try
        {
            using HttpClientResponse response = await send();
            if (response.Status == 200)
            {
                Interlocked.Increment(ref completed);
            }
            else
            {
                Interlocked.Increment(ref failed);
            }
        }
        catch (Exception e)
        {
            if (Interlocked.Increment(ref failed) <= 3)
            {
                Console.Error.WriteLine($"FAIL: {e.GetType().Name}: {e.Message}");
            }
            await Task.Yield();
        }
    }
}

Thread.Sleep(2000);   // connect + handshake, outside the window
Interlocked.Exchange(ref completed, 0);
Interlocked.Exchange(ref failed, 0);
var watch = Stopwatch.StartNew();
Thread.Sleep(seconds * 1000);
watch.Stop();
long ok = Interlocked.Read(ref completed), bad = Interlocked.Read(ref failed);
stop.Set();
Console.WriteLine($"client-{(useTls ? "h1s" : "h1")} {reactors}r: {ok / watch.Elapsed.TotalSeconds:F0} req/s ({ok} ok, {bad} failed)");
Environment.Exit(bad > ok ? 1 : 0);
