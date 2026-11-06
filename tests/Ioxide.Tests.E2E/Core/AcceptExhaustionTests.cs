using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A reactor that runs out of file descriptors while connections wait in the listen backlog (#222),
/// and <see cref="TcpOptions.MaxConnections"/>, which sheds accepts before that (#97).
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

        RegisterMaxConnections(runner, "shared", incremental: null);
        RegisterMaxConnections(runner, "incremental", new IncrementalOptions { MaxConnections = 64, RecvSlots = 4, RecvBufferSize = 1024 });
    }

    private static void RegisterMaxConnections(Runner runner, string mode, IncrementalOptions? incremental)
    {
        runner.Test($"tcp ({mode}): an accept whose descriptor reaches MaxConnections is shed, and accepting resumes once a number frees (#97)", () =>
        {
            // Sockets earlier tests dropped close when finalized, which would free numbers below the cap mid-test.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            FdCount.Stable();

            // Far above every number open now, so the server's own descriptors and its readiness probe land below it.
            int cap = HighestOpenFd() + 64;
            var handled = new ConcurrentQueue<int>();

            int port = TestServer.StartConfigured((r, conn) =>
            {
                handled.Enqueue(conn.ClientFd);
                return Handlers.Raw(r, conn);
            }, new ServerConfig
            {
                RecvBufferSize = 4096,
                RecvSlots = 64,
                Incremental = incremental,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64, MaxConnections = cap },
            }).Port;

            // The probe's number must be free before the table is filled, not free up below the cap afterwards.
            Assert.True(SpinWait.SpinUntil(() => !handled.IsEmpty, 5_000), "the readiness probe never reached the handler");
            Assert.True(handled.TryPeek(out int probe) && SpinWait.SpinUntil(() => !IsOpen(probe), 5_000),
                "the server never closed the readiness probe's connection");

            var placeholders = new List<int>();
            var clients = new Socket[4];
            try
            {
                // Every number below the cap taken, the clients' own sockets above it, then two numbers
                // given back: the server's accepts are all that compete for them.
                while (true)
                {
                    int fd = Native.open("/dev/null", 0, 0);
                    Assert.True(fd >= 0, $"open failed after {placeholders.Count} placeholders: errno {Marshal.GetLastPInvokeError()}");
                    if (fd >= cap)
                    {
                        Native.close(fd);
                        break;
                    }
                    placeholders.Add(fd);
                }

                for (int i = 0; i < clients.Length; i++)
                {
                    clients[i] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5_000 };
                }

                for (int i = 0; i < 2; i++)
                {
                    Native.close(placeholders[^1]);
                    placeholders.RemoveAt(placeholders.Count - 1);
                }

                Assert.Equal("served", Ask(clients[0], port));
                Assert.Equal("served", Ask(clients[1], port));
                Assert.Equal("shed", Ask(clients[2], port));   // every number below the cap was open

                // One leaves. Once the server has closed its side, that number is the lowest free one again.
                int leaving = handled.ElementAt(1);
                clients[0].Dispose();
                Assert.True(SpinWait.SpinUntil(() => !IsOpen(leaving), 5_000), "the server never closed the connection whose client left");
                Assert.Equal("served", Ask(clients[3], port));

                int[] numbers = [.. handled];
                Assert.True(numbers.Length == 4 && numbers.All(n => n < cap),
                    $"handlers saw descriptors {string.Join(", ", numbers)} under a cap of {cap}: only the probe and three clients should have");
            }
            finally
            {
                foreach (Socket? client in clients)
                {
                    client?.Dispose();
                }
                foreach (int fd in placeholders)
                {
                    Native.close(fd);
                }
            }
        }, skip: incremental is not null && !TestServer.KernelAtLeast(6, 12));
    }

    // "served", "shed" when it is closed or reset with no answer, or what else became of it.
    private static string Ask(Socket client, int port)
    {
        client.Connect(IPAddress.Loopback, port);
        try
        {
            client.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n"u8);
            byte[] buffer = new byte[256];
            int n = client.Receive(buffer);
            string answer = Encoding.ASCII.GetString(buffer, 0, n);
            return n == 0 ? "shed" : answer.Contains("200") ? "served" : $"answered \"{answer}\"";
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.Shutdown)
        {
            return "shed";
        }
        catch (SocketException e)
        {
            return $"failed: {e.SocketErrorCode}";
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int fcntl(int fd, int command);

    private const int FGetFd = 1;

    private static bool IsOpen(int fd) => fcntl(fd, FGetFd) != -1;

    private static int HighestOpenFd()
        => Directory.EnumerateFileSystemEntries("/proc/self/fd").Max(entry => int.Parse(Path.GetFileName(entry)));

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
