using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// A write shutdown deferred behind a flush (#653): made by the tick, from a queue of its own rather than a walk of the
/// table. The client sees it as the FIN its server's kernel sends. Every server here runs with both clocks off, so the
/// sweep never walks.
/// </summary>
internal static class WriteShutdownTests
{
    // Far past what the server's send buffer, bounded per connection by StallSends, and the client's default receive
    // buffer can absorb between them, so a flush of it cannot complete before the client reads.
    private const int StallingBody = 2 * 1024 * 1024;

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int optname, ref int optval, int optlen);

    // The client's receive buffer is left at its default on purpose: a 4 KiB SO_RCVBUF can leave the advertised window
    // below the sender's MSS, and a SEND_ZC transfer then crawls at one window probe per RTO (seen here: 700 KB in
    // 72 s). Bounding the server's send buffer instead keeps the flush in flight without that, on any tcp_wmem.
    private static void StallSends(TcpConnection conn)
    {
        int bytes = 64 * 1024;
        if (setsockopt(conn.ClientFd, 1 /* SOL_SOCKET */, 7 /* SO_SNDBUF */, ref bytes, sizeof(int)) != 0)
        {
            throw new InvalidOperationException($"SO_SNDBUF failed: {Marshal.GetLastPInvokeError()}");
        }
    }

    private static readonly TcpOptions NoClocks = new()
    {
        WriteSlabSize = 256 * 1024,
        PoolMax = 64,
        RecvQueueEntries = 64,
        ReadTimeoutMs = 0,
        SendTimeoutMs = 0,
    };

    public static void Register(Runner runner)
    {
        RegisterSendShapes(runner);
        RegisterManyOffThread(runner);
        RegisterOffThreadShutdownWrite(runner);
        RegisterStopWithOneDeferred(runner);
        RegisterLetGoInsideCompletion(runner);
        RegisterAcceptPausedWithNoClocks(runner);
        RegisterShutdownWriteOnReactor(runner);
    }

    // ShutdownWrite on the reactor thread with the flush still the kernel's. The handler keeps the connection, so no
    // let-go can be what shut it down.
    private static void RegisterShutdownWriteOnReactor(Runner runner)
    {
        runner.Test("tcp/half-close: with no clock set, ShutdownWrite behind a flush on the reactor shuts the write side down after the last byte", () =>
        {
            byte[] body = Pattern(StallingBody);
            var shut = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks), async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    StallSends(conn);
                    conn.Write(body);
                    ValueTask flush = conn.FlushAsync();
                    bool outstanding = !flush.IsCompleted;
                    conn.ShutdownWrite();
                    shut.TrySetResult(outstanding);
                    await flush;

                    await conn.ReadAsync();   // until the client closes, having read to the FIN
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            // Not a byte is read before ShutdownWrite has run, so the flush cannot have finished by then.
            Assert.True(shut.Task.Wait(5_000), "the handler never shut its write side");
            Assert.True(shut.Task.Result, "the flush was already over at ShutdownWrite, so this proved nothing");

            byte[] got = ReadToFin(stream, body.Length);
            Assert.Equal(body.Length, got.Length);
            Assert.True(got.AsSpan().SequenceEqual(body), "every byte arrived before the FIN, but not intact");
        });
    }

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

    // The sweep re-arms an accept paused on EMFILE before it decides whether to walk the table, so the re-arm has to
    // survive the early return with both clocks off. AcceptExhaustionTests covers the pause with the default clocks,
    // where the walk is made anyway.
    private static void RegisterAcceptPausedWithNoClocks(Runner runner)
    {
        runner.Test("tcp: with no clock set, a reactor out of file descriptors still resumes accepting", () =>
        {
            const int Clients = 24;
            var clients = new Socket[Clients];
            for (int i = 0; i < Clients; i++)
            {
                clients[i] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 3_000 };
            }

            Assert.Equal(0, getrlimit(RlimitNofile, out RLimit original));
            try
            {
                // As AcceptExhaustionTests: lowered in OnStart, before the reactor arms its accept.
                int port = TestServer.StartConfigured(Greeter, Config(NoClocks), _ =>
                {
                    var tight = new RLimit { Cur = LimitLeavingFree(6), Max = original.Max };
                    if (setrlimit(RlimitNofile, in tight) != 0)
                    {
                        throw new InvalidOperationException($"setrlimit failed: {Marshal.GetLastPInvokeError()}");
                    }
                }).Port;

                foreach (Socket client in clients)
                {
                    client.Connect(System.Net.IPAddress.Loopback, port);
                }

                Thread.Sleep(600);   // a couple of ticks, out of descriptors
                Assert.True(clients.Count(c => c.Available > 0) < Clients,
                    "every connection was accepted under the tight limit, so it never ran out and nothing was tested");
            }
            finally
            {
                setrlimit(RlimitNofile, in original);
            }

            // With descriptors back, every waiting connection is accepted and greeted. The first one never greeted
            // ends the count: the rest are queued behind the same accept.
            int greeted = 0;
            foreach (Socket client in clients)
            {
                byte[] greeting = new byte[2];
                try
                {
                    if (client.Receive(greeting) != 2)
                    {
                        break;
                    }
                    greeted++;
                }
                catch (SocketException)
                {
                    break;
                }
            }
            foreach (Socket client in clients)
            {
                client.Dispose();
            }
            Assert.True(greeted == Clients, $"{greeted} of {Clients} waiting connections were accepted once descriptors were back");
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

    // RLIMIT_NOFILE caps descriptor numbers, not how many are open: the limit that leaves this many free numbers below it.
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

    // A handler resumed inline, inside its first flush's completion, that writes its last part there, flushes it without
    // waiting and lets go: the write shutdown waits for that second flush.
    private static void RegisterLetGoInsideCompletion(Runner runner)
    {
        runner.Test("tcp/exit: with no clock set, a handler that lets go behind a second flush, from inside the first one's completion, gets both out before the FIN", () =>
        {
            byte[] body = Pattern(StallingBody);
            var letGo = new TaskCompletionSource<(bool OnReactor, bool Outstanding)>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks), async (reactor, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                StallSends(conn);
                conn.Write("head"u8);
                await conn.FlushAsync();   // resumes inline, inside the first flush's FinishSend

                conn.Write(body);
                ValueTask second = conn.FlushAsync();
                bool outstanding = !second.IsCompleted;
                conn.DecRef();
                letGo.TrySetResult((reactor.OnReactorThread, outstanding));
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            Assert.True(letGo.Task.Wait(5_000), "the handler never let go");
            (bool onReactor, bool outstanding) = letGo.Task.Result;
            Assert.True(onReactor && outstanding,
                $"the let-go was not behind a second flush on the reactor (on reactor {onReactor}, outstanding {outstanding})");

            byte[] got = ReadToFin(stream, 4 + body.Length);
            Assert.Equal(4 + body.Length, got.Length);
            Assert.True(got.AsSpan(0, 4).SequenceEqual("head"u8) && got.AsSpan(4).SequenceEqual(body),
                "every byte arrived before the FIN, but not intact");
        });
    }

    // Every shape of send holds its flush in flight until the last byte is the kernel's: one SEND, several partial SENDs,
    // a vectored SENDMSG, a SEND_ZC whose notif comes after its data, and the incremental loop's own dispatcher.
    private static void RegisterSendShapes(Runner runner)
    {
        (string Name, ServerConfig Config, bool Skip)[] shapes =
        [
            ("plain SEND", Config(NoClocks), false),
            ("SEND without MSG_WAITALL", Config(NoClocks with { SendWaitAll = false }), false),
            ("vectored SENDMSG", Config(NoClocks with { WriteSlabSize = 4 * 1024, WriteOverflow = WriteOverflowStrategy.Segmented }), false),
            ("SEND_ZC", Config(NoClocks with { ZeroCopySend = true }), false),
            ("incremental", Config(NoClocks) with { Incremental = new IncrementalOptions { MaxConnections = 8 } },
                !TestServer.KernelAtLeast(6, 12)),
        ];

        foreach ((string name, ServerConfig config, bool skip) in shapes)
        {
            runner.Test($"tcp/exit ({name}): with no clock set, a handler that lets go behind a flush shuts the write side down after the last byte", () =>
            {
                byte[] body = Pattern(StallingBody);
                var letGo = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                int port = Start(config, async (_, conn) =>
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        conn.DecRef();
                        return;
                    }

                    StallSends(conn);
                    conn.Write(body);
                    ValueTask flush = conn.FlushAsync();
                    bool outstanding = !flush.IsCompleted;
                    conn.DecRef();   // on the reactor thread, with the flush still the kernel's
                    letGo.TrySetResult(outstanding);
                });

                using var client = new TcpClient();
                client.Connect("127.0.0.1", port);
                client.ReceiveTimeout = 5_000;
                NetworkStream stream = client.GetStream();
                stream.Write("hi"u8);

                // Not a byte is read before the handler has let go, so its flush cannot have finished by then.
                Assert.True(letGo.Task.Wait(5_000), "the handler never let go");
                Assert.True(letGo.Task.Result, "the flush was already over when the handler let go, so this proved nothing");

                Thread.Sleep(600);   // a couple of ticks that find the flush still in flight, and leave it alone

                byte[] got = ReadToFin(stream, body.Length);
                Assert.Equal(body.Length, got.Length);
                Assert.True(got.AsSpan().SequenceEqual(body), "every byte arrived before the FIN, but not intact");
            }, skip: skip);
        }
    }

    // The queue under load: many let-gos from the thread pool at once, each behind a flush that cannot complete yet.
    private static void RegisterManyOffThread(Runner runner)
    {
        runner.Test("tcp/exit: with no clock set, sixteen handlers letting go behind their flushes from the thread pool all shut their write side down", () =>
        {
            const int Clients = 16;
            byte[] body = Pattern(StallingBody);
            using var allLetGo = new CountdownEvent(Clients);
            int overBeforeLetGo = 0;

            int port = Start(Config(NoClocks), async (_, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                StallSends(conn);
                conn.Write(body);
                ValueTask flush = conn.FlushAsync();
                await Task.Run(() =>
                {
                    if (flush.IsCompleted)
                    {
                        Interlocked.Increment(ref overBeforeLetGo);
                    }
                    conn.DecRef();
                    allLetGo.Signal();
                });
            });

            var clients = new TcpClient[Clients];
            try
            {
                for (int i = 0; i < Clients; i++)
                {
                    clients[i] = new TcpClient();
                    clients[i].Connect("127.0.0.1", port);
                    clients[i].ReceiveTimeout = 10_000;
                    clients[i].GetStream().Write("hi"u8);
                }

                // Nobody reads before every handler has let go.
                Assert.True(allLetGo.Wait(10_000), $"only {Clients - allLetGo.CurrentCount} of {Clients} handlers let go");
                Assert.Equal(0, Volatile.Read(ref overBeforeLetGo));

                var outcomes = new string[Clients];
                var readers = new Thread[Clients];
                for (int i = 0; i < Clients; i++)
                {
                    int k = i;
                    readers[k] = new Thread(() =>
                    {
                        try
                        {
                            byte[] got = ReadToFin(clients[k].GetStream(), body.Length);
                            outcomes[k] = got.Length == body.Length && got.AsSpan().SequenceEqual(body)
                                ? "ok"
                                : $"{got.Length} bytes, intact={got.AsSpan().SequenceEqual(body.AsSpan(0, Math.Min(got.Length, body.Length)))}";
                        }
                        catch (Exception e)
                        {
                            outcomes[k] = e.Message;
                        }
                    }) { IsBackground = true };
                    readers[k].Start();
                }
                foreach (Thread reader in readers)
                {
                    Assert.True(reader.Join(60_000), "a reader never finished");
                }

                string failed = string.Join("; ", outcomes.Select((o, i) => (o, i)).Where(x => x.o != "ok").Select(x => $"#{x.i}: {x.o}"));
                Assert.True(failed.Length == 0, failed);
            }
            finally
            {
                foreach (TcpClient? client in clients)
                {
                    client?.Dispose();
                }
            }
        });
    }

    // ShutdownWrite from another thread goes through the same queue as an off-reactor DecRef.
    private static void RegisterOffThreadShutdownWrite(Runner runner)
    {
        runner.Test("tcp/half-close: with no clock set, ShutdownWrite from another thread behind a flush shuts the write side down after the last byte, and the read side stays open", () =>
        {
            byte[] body = Pattern(StallingBody);
            var shut = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var heard = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks), async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    StallSends(conn);
                    conn.Write(body);
                    ValueTask flush = conn.FlushAsync();
                    bool outstanding = !flush.IsCompleted;

                    // Off the reactor, which this blocks meanwhile, so it is deferred with the flush in flight.
                    var shutter = new Thread(conn.ShutdownWrite) { IsBackground = true };
                    shutter.Start();
                    shutter.Join();
                    shut.TrySetResult(outstanding);

                    await flush;

                    var got = new List<byte>();
                    while (got.Count < 4)
                    {
                        RecvSnapshot snapshot = await conn.ReadAsync();
                        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                        {
                            if (item.HasBuffer)
                            {
                                got.AddRange(item.AsSpan().ToArray());
                                conn.ReturnBuffer(in item);
                            }
                        }
                        if (snapshot.IsClosed)
                        {
                            break;
                        }
                    }
                    heard.TrySetResult(Encoding.ASCII.GetString(got.ToArray()));
                }
                catch (Exception e)
                {
                    heard.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            Assert.True(shut.Task.Wait(5_000), "the handler never shut its write side");
            Assert.True(shut.Task.Result, "the flush was already over at ShutdownWrite, so this proved nothing");

            byte[] received = ReadToFin(stream, body.Length);
            Assert.Equal(body.Length, received.Length);
            Assert.True(received.AsSpan().SequenceEqual(body), "every byte arrived before the FIN, but not intact");

            stream.Write("more"u8);
            Assert.True(heard.Task.Wait(5_000), "the read side closed with the write side");
            Assert.Equal("more", heard.Task.Result);
        });
    }

    // The stop's first pass closes every connection while one is still in the queue: a tick after it finds the connection
    // torn down (its write shutdown suppressed, or its slot gone) and must leave it alone.
    private static void RegisterStopWithOneDeferred(Runner runner)
    {
        runner.Test("stop: a reactor stopped with a let-go still deferred behind a flush stops, and the peer is let go", () =>
        {
            byte[] body = Pattern(StallingBody);
            var queued = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor _, Thread thread) = TestServer.StartConfigured(async (reactor, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                // In the post drain, so the stop comes right behind the let-go.
                reactor.ScheduleOnReactor(_ =>
                {
                    StallSends(conn);
                    conn.Write(body);   // the client never reads: the flush stays the kernel's
                    _ = conn.FlushAsync();

                    var letGo = new Thread(conn.DecRef) { IsBackground = true };
                    letGo.Start();
                    letGo.Join();

                    int fd = conn.ClientFd;
                    reactor.Stop();
                    queued.TrySetResult(fd);
                }, null);
            }, Config(NoClocks));

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            Assert.True(queued.Task.Wait(5_000), "the handler never let go");
            Assert.True(thread.Join(10_000), "the reactor never stopped, with a let-go queued behind its flush");

            // The peer is ended, by a reset or a FIN, not left connected to a server that is gone.
            string end = "connected";
            var buffer = new byte[64 * 1024];
            try
            {
                while (stream.Read(buffer, 0, buffer.Length) > 0)
                {
                }
                end = "fin";
            }
            catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset })
            {
                end = "reset";
            }
            catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
            {
                end = "still connected after the receive timeout";
            }
            Assert.True(end is "reset" or "fin", $"the peer was not let go: {end}");
        });
    }

    private static ServerConfig Config(TcpOptions tcp) => new()
    {
        RecvBufferSize = 4096,
        RecvSlots = 256,
        Tcp = tcp,
    };

    private static int Start(ServerConfig config, Func<Reactor, TcpConnection, Task> handle)
        => TestServer.StartConfigured(handle, config).Port;

    // Byte i of a body: a hash of its position, so a byte lost, repeated or moved shows wherever it falls.
    private static byte[] Pattern(int count)
    {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++)
        {
            bytes[i] = (byte)(((ulong)i * 0x9E3779B97F4A7C15UL) >> 56);
        }
        return bytes;
    }

    // Everything up to the FIN, which must come within the receive timeout of the last byte. Never more than
    // `expected` bytes: a server that sends more is as wrong as one that sends less.
    private static byte[] ReadToFin(NetworkStream stream, int expected)
    {
        var got = new MemoryStream(expected);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            int n = ReadOnce(stream, (int)got.Length, buffer);
            if (n == 0)
            {
                return got.ToArray();
            }
            got.Write(buffer, 0, n);
            if (got.Length > expected)
            {
                throw new Exception($"{got.Length} bytes, past the {expected} sent");
            }
        }
    }

    // One read, telling a lost FIN (the receive timeout) from a reset or anything else.
    private static int ReadOnce(NetworkStream stream, int readSoFar, byte[] buffer)
    {
        try
        {
            return stream.Read(buffer, 0, buffer.Length);
        }
        catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
        {
            throw new Exception($"no FIN: nothing more after {readSoFar} bytes until the receive timeout");
        }
    }

    private static async Task<bool> IsThisTestsConnection(TcpConnection conn)
    {
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();

            bool received = false;
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    received = true;
                    conn.ReturnBuffer(in item);
                }
            }

            if (received)
            {
                return true;
            }
            if (snapshot.IsClosed)
            {
                return false;   // TestServer's listen probe
            }
        }
    }
}
