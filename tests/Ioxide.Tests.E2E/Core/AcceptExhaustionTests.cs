using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A reactor that runs out of file descriptors while connections wait in the listen backlog (#222).
/// </summary>
internal static class AcceptExhaustionTests
{
    private const int RlimitNofile = 7;

    [StructLayout(LayoutKind.Sequential)]
    private struct RLimit
    {
        public ulong Cur;
        public ulong Max;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getrlimit(int resource, out RLimit limit);

    [DllImport("libc", SetLastError = true)]
    private static extern int setrlimit(int resource, in RLimit limit);

    public static void Register(Runner runner)
    {
        runner.Test("tcp: out of file descriptors, a reactor stops accepting instead of spinning, then resumes", () =>
        {
            // Made before the limit drops: connecting needs no new descriptor, accepting does.
            const int Clients = 24;
            var clients = new Socket[Clients];
            for (int i = 0; i < Clients; i++)
            {
                clients[i] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                {
                    ReceiveTimeout = 5_000,
                };
            }

            Assert.Equal(0, getrlimit(RlimitNofile, out RLimit original));

            FileStream? stat = null;
            double busy;
            try
            {
                // OnStart runs before the reactor arms its accept, and io_uring reads the limit when an
                // accept is armed: lowered any later, the armed multishot accept never sees it. Room for
                // the harness's readiness probe and four accepts.
                int port = TestServer.Start(Greeter, _ =>
                {
                    stat = new FileStream("/proc/thread-self/stat", FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 0);
                    var tight = new RLimit { Cur = LimitLeavingFree(6), Max = original.Max };
                    if (setrlimit(RlimitNofile, in tight) != 0)
                    {
                        throw new InvalidOperationException($"setrlimit failed: {Marshal.GetLastPInvokeError()}");
                    }
                });

                // The kernel completes every handshake; the reactor can accept a few of them.
                foreach (Socket client in clients)
                {
                    client.Connect(IPAddress.Loopback, port);
                }

                Thread.Sleep(300);
                long before = CpuTicks(stat!);
                Thread.Sleep(1_000);
                busy = (CpuTicks(stat!) - before) / 100.0;   // of one core, at 100 ticks a second

                int greetedEarly = clients.Count(c => c.Available > 0);
                Assert.True(greetedEarly < Clients,
                    "every connection was accepted under the tight limit, so it never ran out and nothing was tested");
            }
            finally
            {
                setrlimit(RlimitNofile, in original);
                stat?.Dispose();
            }

            // With descriptors back, every waiting connection is accepted and greeted.
            int greeted = 0;
            foreach (Socket client in clients)
            {
                byte[] greeting = new byte[2];
                try
                {
                    if (client.Receive(greeting) == 2)
                    {
                        greeted++;
                    }
                }
                catch (SocketException)
                {
                    // Counted as not greeted.
                }
                client.Dispose();
            }

            Assert.True(busy < 0.3,
                $"the reactor used {busy:P0} of a core while out of descriptors: it kept re-arming an accept that could only fail");
            Assert.Equal(Clients, greeted);
        });
    }

    private static async Task Greeter(Reactor reactor, TcpConnection conn)
    {
        try
        {
            conn.Write("hi"u8);
            await conn.FlushAsync();
            await conn.ReadAsync();   // the client only closes
        }
        finally
        {
            conn.DecRef();
        }
    }

    // RLIMIT_NOFILE caps descriptor numbers, not how many are open, and earlier tests leave holes in
    // the table: the limit that leaves exactly this many free numbers below it.
    private static ulong LimitLeavingFree(int free)
    {
        FdCount.Stable();
        var open = new HashSet<int>();
        foreach (string entry in Directory.EnumerateFileSystemEntries("/proc/self/fd"))
        {
            open.Add(int.Parse(Path.GetFileName(entry)));
        }
        for (int n = 0; ; n++)
        {
            if (!open.Contains(n) && --free == 0)
            {
                return (ulong)n + 1;
            }
        }
    }

    // utime + stime, in clock ticks, of the thread whose stat file this is. Re-read from the start,
    // which procfs regenerates.
    private static long CpuTicks(FileStream stat)
    {
        byte[] buffer = new byte[1024];
        stat.Position = 0;
        string text = System.Text.Encoding.ASCII.GetString(buffer, 0, stat.Read(buffer));
        string[] fields = text[(text.LastIndexOf(')') + 2)..].Split(' ');
        return long.Parse(fields[11]) + long.Parse(fields[12]);
    }
}
