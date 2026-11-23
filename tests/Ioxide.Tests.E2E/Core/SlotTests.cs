using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// The connection table (#658): a completion finds its connection by the slot the reactor gave it, not by its descriptor,
/// so a descriptor's number means nothing to the reactor and its table is as long as the most connections it has held at
/// once.
/// </summary>
internal static class SlotTests
{
    public static void Register(Runner runner)
    {
        bool incremental = TestServer.KernelAtLeast(6, 12);

        runner.Test("slots: a connection's slot is the reactor's, whatever its descriptor's number", () =>
        {
            // So many open descriptors that every one accepted after has a high number.
            var held = Enumerable.Range(0, 300).Select(_ => new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)).ToArray();
            try
            {
                var seen = new List<(int Fd, int Slot)>();
                (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(Echo, Shared(new TcpOptions()));

                for (int i = 0; i < 3; i++)
                {
                    using Socket client = Connect(port);
                    string token = $"token-{i:D4}";
                    Assert.Equal(token, Exchange(client, token));
                    seen.Add(Last(reactor));
                }

                Assert.True(seen.All(s => s.Fd >= held.Length), $"descriptors {string.Join(", ", seen.Select(s => s.Fd))} are not high, so this proved nothing");
                Assert.True(seen.All(s => s.Slot < 8), $"slots {string.Join(", ", seen.Select(s => s.Slot))} follow the descriptors");
                Assert.True(UsedOf(reactor) < 16, $"the table has {UsedOf(reactor)} slots for three connections one after another");
            }
            finally
            {
                foreach (Socket socket in held)
                {
                    socket.Dispose();
                }
            }
        });

        runner.Test("slots: connections that come one after another keep taking the same few", () =>
        {
            (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(Echo, Shared(new TcpOptions()));

            for (int i = 0; i < 300; i++)
            {
                using Socket client = Connect(port);
                string token = $"token-{i:D4}";
                Assert.Equal(token, Exchange(client, token));
            }
            Assert.True(UsedOf(reactor) < 16, $"three hundred connections, one at a time, used {UsedOf(reactor)} slots");
        });

        runner.Test("slots: the table grows under connections that are open, and each still gets its own answer", () =>
        {
            const int Count = 1_300;   // past the table's first size
            (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(Echo, Shared(new TcpOptions()));

            var clients = new List<Socket>();
            try
            {
                for (int i = 0; i < Count; i++)
                {
                    clients.Add(Connect(port));
                    Assert.Equal($"first {i}", Exchange(clients[i], $"first {i}"));
                }
                Assert.True(UsedOf(reactor) >= Count, $"{UsedOf(reactor)} slots for {Count} open connections");
                for (int i = 0; i < Count; i++)
                {
                    Assert.Equal($"again {i}", Exchange(clients[i], $"again {i}"));
                }
            }
            finally
            {
                clients.ForEach(client => client.Dispose());
            }
        });

        // A connection that is over keeps its recv until the cancel that names its slot reaches it. One that missed would
        // go on taking what the client sends, for nobody, as long as the handler holds the connection.
        runner.Test("slots: the cancel behind a failed send reaches its own connection's recv", () =>
        {
            var failed = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    if (await EchoOnce(conn) != 0)
                    {
                        conn.ShutdownWrite();
                        conn.Write(new byte[16]);
                        await conn.FlushAsync();   // EPIPE
                        failed.TrySetResult(conn.ClientFd);
                        await release.Task;
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, Shared(new TcpOptions())).Port;

            using Socket client = Connect(port);
            Assert.Equal("hello", Exchange(client, "hello"));
            Assert.True(failed.Task.Wait(5_000), "the flush behind the write shutdown never came back");
            try
            {
                AssertLeftUnread(client, failed.Task.Result);
            }
            finally
            {
                release.TrySetResult();
            }
        });

        runner.Test("slots: the cancel behind a full recv queue reaches its own connection's recv", () =>
        {
            var holding = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    if (await EchoOnce(conn) != 0)
                    {
                        holding.TrySetResult(conn);
                        await release.Task;   // reads no more
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, Shared(new TcpOptions { RecvQueueEntries = 8 })).Port;

            using Socket client = Connect(port);
            Assert.Equal("hello", Exchange(client, "hello"));
            Assert.True(holding.Task.Wait(5_000), "the handler never got to hold its connection");
            TcpConnection conn = holding.Task.Result;
            try
            {
                for (int i = 0; i < 1_000 && !conn.IsClosed; i++)
                {
                    client.Send("x"u8);
                    Thread.Sleep(2);
                }
                Assert.True(conn.IsClosed, "the recv queue never filled");
                AssertLeftUnread(client, conn.ClientFd);
            }
            finally
            {
                release.TrySetResult();
            }
        });

        // Whatever carries a slot carries all of it: the tags, and the queues of flushes and of buffers handed back, so
        // the handler does both off the reactor. The ring of a connection of its own is run through several times over.
        foreach ((string name, ServerConfig config, bool skip) in new[]
        {
            ("shared ring", Shared(new TcpOptions()), false),
            ("ring per connection", new ServerConfig { Tcp = new TcpOptions(), Incremental = new IncrementalOptions { MaxConnections = 64, RecvSlots = 2, RecvBufferSize = 256 } }, !incremental),
        })
        {
            runner.Test($"slots: one past 65,535 is served like any other ({name})", () =>
            {
                const int Held = 70_000;
                int lowest = int.MaxValue;
                (int port, Reactor _, Thread _) = TestServer.StartConfigured(async (_, conn) =>
                {
                    InterlockedMin(ref lowest, SlotOf(conn));
                    try
                    {
                        while (true)
                        {
                            RecvSnapshot snapshot = await conn.ReadAsync();
                            await Task.Yield();
                            int got = 0;
                            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                            {
                                if (item.HasBuffer)
                                {
                                    got += item.AsSpan().Length;
                                    conn.ReturnBuffer(in item);
                                }
                            }
                            if (got == 0)
                            {
                                return;
                            }
                            conn.Write(Encoding.ASCII.GetBytes(new string('x', got)));
                            await conn.FlushAsync();
                        }
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, config, onStart: reactor =>
                {
                    // As it is once that many connections have come and gone: the highest slots are taken first.
                    SlotsOf(reactor) = new TcpConnection?[Held];
                    UsedOf(reactor) = Held;
                    for (int slot = 0; slot < Held; slot++)
                    {
                        FreeOf(reactor).Push(slot);
                    }
                });

                string token = new('x', 100);
                var clients = Enumerable.Range(0, 8).Select(_ => Connect(port)).ToList();
                try
                {
                    foreach (Socket client in clients)
                    {
                        for (int round = 0; round < 20; round++)
                        {
                            Assert.Equal(token, Exchange(client, token));
                        }
                    }
                    Assert.True(Volatile.Read(ref lowest) > ushort.MaxValue, $"one was given slot {lowest}, so this proved nothing");
                }
                finally
                {
                    clients.ForEach(client => client.Dispose());
                }
            }, skip: skip);
        }

        // The answer each client gets is the one its own connection was asked for, through a reactor that gives the same
        // slots to one after another, with handlers that let go and flush on another thread.
        foreach ((string name, ServerConfig config, bool skip) in new[]
        {
            ("shared ring", Shared(new TcpOptions()), false),
            ("ring per connection", new ServerConfig { Tcp = new TcpOptions(), Incremental = new IncrementalOptions { MaxConnections = 512 } }, !incremental),
        })
        {
            runner.Test($"slots: under churn, each client gets its own answer ({name})", () =>
            {
                const int Threads = 16, PerThread = 150;
                (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(async (_, conn) =>
                {
                    try
                    {
                        while (true)
                        {
                            (byte first, string text) = await ReadText(conn);
                            if (first == 0)
                            {
                                return;
                            }
                            await Task.Yield();                 // off the reactor
                            if ((first & 1) == 0)
                            {
                                await Task.Delay(1);
                            }
                            conn.Write(Encoding.ASCII.GetBytes(text));
                            await conn.FlushAsync();
                        }
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, config);

                var failed = new List<string>();
                var threads = new Thread[Threads];
                for (int t = 0; t < Threads; t++)
                {
                    int k = t;
                    threads[k] = new Thread(() =>
                    {
                        for (int i = 0; i < PerThread; i++)
                        {
                            try
                            {
                                using Socket client = Connect(port);
                                string token = $"{k:D2}-{i:D4}-" + new string((char)('a' + i % 26), 40 + i % 60);
                                if (Exchange(client, token) is { } got && got != token)
                                {
                                    throw new Exception($"asked {token[..12]}, answered {got[..Math.Min(12, got.Length)]}");
                                }
                                if (i % 3 == 0)
                                {
                                    client.LingerState = new LingerOption(true, 0);   // a reset
                                }
                            }
                            catch (Exception e)
                            {
                                lock (failed)
                                {
                                    failed.Add($"{k}.{i}: {e.Message}");
                                }
                                return;
                            }
                        }
                    }) { IsBackground = true };
                    threads[k].Start();
                }
                foreach (Thread thread in threads)
                {
                    Assert.True(thread.Join(120_000), "a client never finished");
                }
                Assert.True(failed.Count == 0, string.Join("; ", failed.Take(3)));
                Assert.True(UsedOf(reactor) <= 4 * Threads, $"{UsedOf(reactor)} slots for {Threads} clients at a time");
            }, skip: skip);
        }
    }

    private static ServerConfig Shared(TcpOptions tcp) => new() { Tcp = tcp, RecvSlots = 1024, RecvBufferSize = 4096 };

    private static async Task Echo(Reactor reactor, TcpConnection conn)
    {
        try
        {
            while (await EchoOnce(conn) != 0)
            {
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static void InterlockedMin(ref int target, int value)
    {
        for (int seen = Volatile.Read(ref target); value < seen;)
        {
            int now = Interlocked.CompareExchange(ref target, value, seen);
            if (now == seen)
            {
                return;
            }
            seen = now;
        }
    }

    // From the cancel on, what the client sends stays in the socket.
    private static void AssertLeftUnread(Socket client, int fd)
    {
        for (int i = 0; i < 100; i++)
        {
            client.Send("x"u8);
            Thread.Sleep(20);
            if (Unread(fd) > 0)
            {
                Thread.Sleep(100);
                Assert.True(Unread(fd) > 0, "what the client sent was taken after all");
                return;
            }
        }
        throw new Exception("the recv went on taking what the client sent");
    }

    // The slot of the connection the reactor accepted last.
    private static (int Fd, int Slot) Last(Reactor reactor)
    {
        TcpConnection?[] slots = SlotsOf(reactor);
        (int Fd, int Slot) last = (-1, -1);
        long newest = long.MinValue;
        for (int i = 0; i < UsedOf(reactor); i++)
        {
            if (slots[i] is { } conn && GenerationOf(conn) > newest)
            {
                newest = GenerationOf(conn);
                last = (conn.ClientFd, i);
            }
        }
        return last;
    }

    private static Socket Connect(int port)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, ReceiveTimeout = 10_000 };
        client.Connect(IPAddress.Loopback, port);
        return client;
    }

    private static string Exchange(Socket client, string token)
    {
        client.Send(Encoding.ASCII.GetBytes(token));
        var buffer = new byte[token.Length];
        int got = 0;
        while (got < buffer.Length)
        {
            int n = client.Receive(buffer, got, buffer.Length - got, SocketFlags.None);
            if (n == 0)
            {
                throw new Exception($"closed after {got} of {buffer.Length} bytes");
            }
            got += n;
        }
        return Encoding.ASCII.GetString(buffer);
    }

    private static async Task<int> EchoOnce(TcpConnection conn)
    {
        (byte first, string text) = await ReadText(conn);
        if (first == 0)
        {
            return 0;
        }
        conn.Write(Encoding.ASCII.GetBytes(text));
        await conn.FlushAsync();
        return text.Length;
    }

    // One delivery as text; first is 0 when the peer closed instead.
    private static async Task<(byte First, string Text)> ReadText(TcpConnection conn)
    {
        RecvSnapshot snapshot = await conn.ReadAsync();
        var text = new StringBuilder();
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                text.Append(Encoding.ASCII.GetString(item.AsSpan()));
                conn.ReturnBuffer(in item);
            }
        }
        string all = text.ToString();
        return (all.Length > 0 ? (byte)all[0] : (byte)0, all);
    }

    private static int Unread(int fd) => ioctl(fd, 0x541B /* FIONREAD */, out int waiting) == 0 ? waiting : -1;

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request, out int value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_slots")]
    private static extern ref TcpConnection?[] SlotsOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_slotsUsed")]
    private static extern ref int UsedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_freeSlots")]
    private static extern ref Stack<int> FreeOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "Slot")]
    private static extern ref int SlotOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_generation")]
    private static extern ref int GenerationOf(TcpConnection connection);
}
