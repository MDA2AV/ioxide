using System.Text;
using ioxide;
using ioxide.utils;

// count - the C# twin of the Kotlin playground's tcp-count: Tcp/Raw answering once per request, a request being
// anything ending in "\r\n\r\n", found by a byte state machine that carries across reads. GET-only load.

ushort port = ushort.TryParse(Environment.GetEnvironmentVariable("PLAYGROUND_PORT"), out ushort p) ? p : (ushort)8080;
int reactors = int.TryParse(Environment.GetEnvironmentVariable("PLAYGROUND_REACTORS"), out int n) ? n : Environment.ProcessorCount;

var config = new ServerConfig
{
    ReactorCount = reactors,
    RingEntries = 8192,
    RecvBufferSize = 32 * 1024,
    RecvSlots = 4096,
    Tcp = new TcpOptions { Port = port, ListenBacklog = 1024, WriteSlabSize = 16 * 1024, PoolMax = 1024, RecvQueueEntries = 64 },
};

byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");

var threads = new Thread[reactors];
for (int i = 0; i < reactors; i++)
{
    var reactor = new Reactor(i, config);
    reactor.TcpHandle = async (r, conn) =>
    {
        try
        {
            int state = 0;   // how much of "\r\n\r\n" the bytes so far end with
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                int requests = 0;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (!item.HasBuffer)
                    {
                        continue;
                    }
                    ReadOnlySpan<byte> bytes = item.AsSpan();
                    foreach (byte b in bytes)
                    {
                        switch (b)
                        {
                            case 13: state = state == 2 ? 3 : 1; break;
                            case 10: state = state == 1 ? 2 : state == 3 ? Count(ref requests) : 0; break;
                            default: state = 0; break;
                        }
                    }
                    conn.ReturnBuffer(in item);
                }

                for (int k = 0; k < requests; k++)
                {
                    conn.Write(response);
                }
                if (requests > 0)
                {
                    await conn.FlushAsync();
                }

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

Console.WriteLine($"[count] {reactors} reactors on :{port}");
foreach (Thread t in threads) t.Join();

static int Count(ref int requests)
{
    requests++;
    return 0;
}
