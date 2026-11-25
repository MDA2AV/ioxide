using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What the tick does for TCP without walking the connection table (#653): it makes the write shutdowns deferred behind
/// a flush, from a queue of their own, re-arms paused accepts, and gives back what a let-go connection holds of a ring of
/// its own. A client sees a write shutdown as the FIN its server's kernel sends. Both clocks are off wherever a test is
/// not about one, so the table is walked only for a recv starved of the shared ring's buffers.
/// </summary>
internal static class TcpSweepTests
{
    // Far past what the server's send buffer, bounded per connection by StallSends, and the client's receive buffer,
    // bounded by Connect, can absorb between them, so a flush of it cannot complete before the client reads.
    private const int StallingBody = 2 * 1024 * 1024;

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int optname, ref int optval, int optlen);

    private static void StallSends(TcpConnection conn)
    {
        int bytes = 64 * 1024;
        if (setsockopt(conn.ClientFd, 1 /* SOL_SOCKET */, 7 /* SO_SNDBUF */, ref bytes, sizeof(int)) != 0)
        {
            throw new InvalidOperationException($"SO_SNDBUF failed: {Marshal.GetLastPInvokeError()}");
        }
    }

    // The receive buffer is bounded so that no tcp_rmem can absorb a stalling body, but not tiny: 4 KiB can leave the
    // advertised window below the sender's MSS, and a SEND_ZC transfer then crawls at one window probe per RTO (seen
    // here: 700 KB in 72 s).
    private static TcpClient Connect(int port, string hello = "hi", int receiveTimeoutMs = 5_000)
    {
        var client = new TcpClient(AddressFamily.InterNetwork)
        {
            ReceiveBufferSize = 256 * 1024,
            ReceiveTimeout = receiveTimeoutMs,
            NoDelay = true,
        };
        client.Connect(IPAddress.Loopback, port);
        client.GetStream().Write(Encoding.ASCII.GetBytes(hello));
        return client;
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
        RegisterShutdownWrite(runner);
        RegisterLetGoInsideCompletion(runner);
        RegisterFlushEndedWithoutASend(runner);
        RegisterDeferredConnectionGone(runner);
        RegisterReadClockAfterDeferred(runner);
        RegisterSendClockAlone(runner);
        RegisterAcceptPaused(runner);
        RegisterWalkForBuffers(runner);
        RegisterStopWhileWaiting(runner);
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
                var letGo = new TaskCompletionSource<Func<bool>>(TaskCreationOptions.RunContinuationsAsynchronously);

                int port = Start(config, async (_, conn) =>
                {
                    if (await FirstByte(conn) == 0)
                    {
                        conn.DecRef();
                        return;
                    }

                    StallSends(conn);
                    conn.Write(body);
                    ValueTask flush = conn.FlushAsync();
                    conn.DecRef();   // on the reactor thread, with the flush still the kernel's
                    letGo.TrySetResult(() => !flush.IsCompleted);
                });

                using TcpClient client = Connect(port);
                Assert.True(letGo.Task.Wait(5_000), "the handler never let go");

                Thread.Sleep(600);   // two ticks that find the flush in flight, and must leave it alone
                Assert.True(letGo.Task.Result(), "the flush was over before the client read a byte, so this proved nothing");

                AssertWholeThenFin(client, body);
            }, skip: skip);
        }
    }

    // Many let-gos from the thread pool at once, each behind a flush that cannot complete yet.
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
                if (await FirstByte(conn) == 0)
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

            var clients = new TcpClient?[Clients];
            try
            {
                for (int i = 0; i < Clients; i++)
                {
                    clients[i] = Connect(port, receiveTimeoutMs: 10_000);
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
                            AssertWholeThenFin(clients[k]!, body);
                            outcomes[k] = "ok";
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

    // The handler keeps the connection, so no let-go can be what shut it down.
    private static void RegisterShutdownWrite(Runner runner)
    {
        runner.Test("tcp/half-close: with no clock set, ShutdownWrite behind a flush shuts the write side down after the last byte, and the read side stays open", () =>
        {
            byte[] body = Pattern(StallingBody);
            var shut = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var heard = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks), async (_, conn) =>
            {
                try
                {
                    if (await FirstByte(conn) == 0)
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

                    heard.TrySetResult(await ReadText(conn, 4));
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

            using TcpClient client = Connect(port);

            // Not a byte is read before ShutdownWrite has run, so the flush cannot have finished by then.
            Assert.True(shut.Task.Wait(5_000), "the handler never shut its write side");
            Assert.True(shut.Task.Result, "the flush was already over at ShutdownWrite, so this proved nothing");
            AssertWholeThenFin(client, body);

            client.GetStream().Write("more"u8);
            Assert.True(heard.Task.Wait(5_000), "the read side closed with the write side");
            Assert.Equal("more", heard.Task.Result);
        });
    }

    // A handler resumed inline, inside its first flush's completion, that writes its last part there, flushes it without
    // waiting and lets go: the write shutdown waits for that second flush.
    private static void RegisterLetGoInsideCompletion(Runner runner)
    {
        runner.Test("tcp/exit: with no clock set, a handler that lets go behind a second flush, from inside the first one's completion, gets both out before the FIN", () =>
        {
            byte[] body = Pattern(StallingBody);
            byte[] all = [.. "head"u8, .. body];
            var letGo = new TaskCompletionSource<(bool OnReactor, bool Outstanding)>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks), async (reactor, conn) =>
            {
                if (await FirstByte(conn) == 0)
                {
                    conn.DecRef();
                    return;
                }

                StallSends(conn);
                conn.Write("head"u8);
                await conn.FlushAsync();   // resumes inline, inside the first flush's completion

                conn.Write(body);
                ValueTask second = conn.FlushAsync();
                bool outstanding = !second.IsCompleted;
                conn.DecRef();
                letGo.TrySetResult((reactor.OnReactorThread, outstanding));
            });

            using TcpClient client = Connect(port);
            Assert.True(letGo.Task.Wait(5_000), "the handler never let go");
            (bool onReactor, bool outstanding) = letGo.Task.Result;
            Assert.True(onReactor && outstanding,
                $"the let-go was not behind a second flush on the reactor (on reactor {onReactor}, outstanding {outstanding})");
            AssertWholeThenFin(client, all);
        });
    }

    // A flush can end without a send of its own, here one MarkClosed releases while it is still queued to the reactor, so
    // no completion follows it and only the tick can find it over. The handler keeps the connection, so no let-go makes
    // the shutdown.
    private static void RegisterFlushEndedWithoutASend(Runner runner)
    {
        runner.Test("tcp/half-close: with no clock set, a write shutdown deferred behind a flush that ends without a send is still made", () =>
        {
            var deferred = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks), async (reactor, conn) =>
            {
                try
                {
                    if (await FirstByte(conn) == 0)
                    {
                        return;
                    }

                    reactor.ScheduleOnReactor(_ =>
                    {
                        // Off the reactor, which this blocks meanwhile: armed and queued, but not the kernel's.
                        bool outstanding = false;
                        var flusher = new Thread(() =>
                        {
                            conn.Write("x"u8);
                            outstanding = !conn.FlushAsync().IsCompleted;
                        });
                        flusher.Start();
                        flusher.Join();

                        conn.ShutdownWrite();
                        conn.MarkClosed();
                        deferred.TrySetResult(outstanding);
                    }, null);

                    await release.Task;
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using TcpClient client = Connect(port, receiveTimeoutMs: 2_000);
            try
            {
                Assert.True(deferred.Task.Wait(5_000), "ShutdownWrite never ran");
                Assert.True(deferred.Task.Result, "the flush was over at ShutdownWrite, so nothing was deferred");
                Assert.Equal(0, ReadOnce(client.GetStream(), 0, new byte[16]));
            }
            finally
            {
                release.TrySetResult();
            }
        });
    }

    // A connection that goes with its shutdown still deferred leaves its entry in the queue, and its slot to the next one
    // accepted. The tick drops the entry, and leaves that one alone: here an open connection that gets an entry of an
    // earlier life of its slot.
    private static void RegisterDeferredConnectionGone(Runner runner)
    {
        runner.Test("tcp/exit: with no clock set, a let-go whose connection is gone is dropped, and its slot's next connection left alone", () =>
        {
            byte[] body = Pattern(StallingBody);
            var letGo = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var open = new TaskCompletionSource<(int Slot, int TagGen)>(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(async (_, conn) =>
            {
                byte first = await FirstByte(conn);
                if (first == (byte)'L')
                {
                    StallSends(conn);
                    conn.Write(body);
                    ValueTask flush = conn.FlushAsync();
                    conn.DecRef();
                    letGo.TrySetResult();
                    return;
                }

                try
                {
                    if (first != 0)
                    {
                        open.TrySetResult((SlotOf(conn), TagGenOf(conn)));
                    }
                    while (first != 0)
                    {
                        conn.Write("pong"u8);
                        await conn.FlushAsync();
                        first = await FirstByte(conn);
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config(NoClocks));

            TcpClient reset = Connect(port, "L");
            Assert.True(letGo.Task.Wait(5_000), "the handler never let go");
            reset.LingerState = new LingerOption(true, 0);
            reset.Dispose();   // with the flush in flight and the shutdown deferred

            using TcpClient client = Connect(port, "P", 2_000);
            NetworkStream stream = client.GetStream();
            Assert.Equal(4, ReadOnce(stream, 0, new byte[4]));
            (int slot, int tagGen) = open.Task.Result;
            DeferredOf(reactor).Enqueue(((ulong)(ushort)(tagGen - 1) << 32) | (uint)slot);

            WaitFor(() => DeferredOf(reactor).IsEmpty, 2_000, "an entry whose connection is gone was never dropped");
            for (int i = 0; i < 2; i++)
            {
                stream.Write("P"u8);
                Assert.True(ReadOnce(stream, 0, new byte[4]) == 4, "the open connection's write side was shut down");
            }
        });
    }

    // The read clock bounds how long a let-go connection waits for its peer to close, from its write shutdown - for a
    // deferred one, not before the flush is over.
    private static void RegisterReadClockAfterDeferred(Runner runner)
    {
        runner.Test("timeout: a let-go deferred behind a flush is on the read clock from its write shutdown", () =>
        {
            byte[] body = Pattern(StallingBody);
            var letGo = new TaskCompletionSource<(int Fd, string? Socket)>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks with { ReadTimeoutMs = 500, SendTimeoutMs = 10_000 }), async (_, conn) =>
            {
                if (await FirstByte(conn) == 0)
                {
                    conn.DecRef();
                    return;
                }

                StallSends(conn);
                conn.Write(body);
                ValueTask flush = conn.FlushAsync();
                var socket = (conn.ClientFd, LinkOf(conn.ClientFd));
                conn.DecRef();
                letGo.TrySetResult(socket);
            });

            using TcpClient client = Connect(port);
            Assert.True(letGo.Task.Wait(5_000), "the handler never let go");
            (int fd, string? socket) = letGo.Task.Result;

            Thread.Sleep(1_200);   // past the read timeout, with the flush still in flight
            Assert.True(LinkOf(fd) == socket, "closed on the read clock with its flush in flight");

            AssertWholeThenFin(client, body);
            WaitFor(() => LinkOf(fd) != socket, 3_000, "not closed on the read clock after its write shutdown");
        });
    }

    // With the send clock set alone the walk is made, or a flush its peer drains too slowly would never be cut:
    // TCP_USER_TIMEOUT does not see a peer that keeps draining.
    private static void RegisterSendClockAlone(Runner runner)
    {
        runner.Test("timeout: with only the send clock set, a flush to a slow reader is cut at its deadline", () =>
        {
            var flushed = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = Start(Config(NoClocks with { SendTimeoutMs = 700 }), async (_, conn) =>
            {
                try
                {
                    if (await FirstByte(conn) == 0)
                    {
                        return;
                    }

                    StallSends(conn);
                    conn.Write(new byte[8 * 1024 * 1024]);
                    long start = Stopwatch.GetTimestamp();
                    await conn.FlushAsync();
                    flushed.TrySetResult((long)Stopwatch.GetElapsedTime(start).TotalMilliseconds);
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using TcpClient client = Connect(port);
            NetworkStream stream = client.GetStream();
            var buffer = new byte[64 * 1024];
            try
            {
                while (!flushed.Task.IsCompleted && stream.Read(buffer, 0, buffer.Length) > 0)
                {
                    Thread.Sleep(60);   // about 1 MB a second: the whole body would take 8 s
                }
            }
            catch (IOException)
            {
                // cut
            }

            Assert.True(flushed.Task.Wait(2_000), "the flush was never cut");
            Assert.True(flushed.Task.Result is > 500 and < 3_000, $"a 700 ms deadline cut the flush after {flushed.Task.Result} ms");
        });
    }

    // The tick re-arms paused accepts before it decides whether to walk. AcceptExhaustionTests runs a server out of
    // descriptors to pause one; here it is put on the list, so nothing else in the process goes short.
    private static void RegisterAcceptPaused(Runner runner)
    {
        runner.Test("tcp: with no clock set, the tick still re-arms a paused accept", () =>
        {
            (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    if (await FirstByte(conn) != 0)
                    {
                        conn.Write("pong"u8);
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config(NoClocks));

            using var paused = new SemaphoreSlim(0);
            reactor.ScheduleOnReactor(_ =>
            {
                PausedOf(reactor).Add(ListenFdsOf(reactor)[0]);
                paused.Release();
            }, null);
            Assert.True(paused.Wait(5_000), "the reactor never ran the post");
            WaitFor(() => PausedOf(reactor).Count == 0, 2_000, "the paused accept was never re-armed");

            using TcpClient client = Connect(port);
            Assert.Equal(4, ReadOnce(client.GetStream(), 0, new byte[4]));
        });
    }

    // From the shared ring, what any connection its handler let go holds can end a recv's wait for a buffer, so the table
    // is walked for them. With a ring per connection only its own can, so it is not: the mark the walk leaves on a
    // connection with a flush in progress, held here by hand, never appears.
    private static void RegisterWalkForBuffers(Runner runner)
    {
        (string Ring, ServerConfig Config, bool Walks, bool Skip)[] modes =
        [
            ("of the shared ring", Config(NoClocks) with { RecvSlots = 4 }, true, false),
            ("of its own ring", Config(NoClocks) with { Incremental = new IncrementalOptions { MaxConnections = 8, RecvSlots = 2, RecvBufferSize = 1024 } },
                false, !TestServer.KernelAtLeast(6, 12)),
        ];

        foreach ((string ring, ServerConfig config, bool walks, bool skip) in modes)
        {
            runner.Test($"tcp: with no clock set, a recv waiting for a buffer {ring} {(walks ? "brings" : "does not bring")} the walk", () =>
            {
                var marked = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

                (int port, Reactor reactor, Thread _) = TestServer.StartConfigured(async (_, conn) =>
                {
                    try
                    {
                        byte first = await FirstByte(conn);
                        if (first == (byte)'M')
                        {
                            Volatile.Write(ref FlushInProgressOf(conn), 1);
                            marked.TrySetResult(conn);
                            await release.Task;
                            Volatile.Write(ref FlushInProgressOf(conn), 0);
                        }
                        else if (first != 0)
                        {
                            await release.Task;   // an upload this handler is too busy to read
                        }
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, config);

                using TcpClient mark = Connect(port, "M");
                Assert.True(marked.Task.Wait(5_000), "the marked connection was never accepted");
                using TcpClient upload = Connect(port, "U");
                try
                {
                    upload.GetStream().Write(new byte[32 * 1024]);
                    WaitFor(() => StarvedOf(reactor).Count > 0, 5_000, "the upload never ran out of buffers");
                    Thread.Sleep(600);   // two ticks
                    Assert.Equal(1, StarvedOf(reactor).Count);
                    Assert.Equal(walks, Volatile.Read(ref FlushSeenOf(marked.Task.Result)) != 0);
                }
                finally
                {
                    release.TrySetResult();
                }
            }, skip: skip);
        }
    }

    // A stop ends every connection, but a recv that waits for a buffer has no completion coming to say so. Here nothing
    // gives one back either, as with a handler that faulted with every item in hand: only the tick's pass over the recvs
    // waiting lets go of the connection, with a walk or without one.
    private static void RegisterStopWhileWaiting(Runner runner)
    {
        runner.Test("stop: with no clock set, a connection whose recv waits for a buffer its handler never gave back is let go of", () =>
        {
            const int Slots = 2, BufferSize = 1024;
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            ServerConfig config = Config(NoClocks) with { Incremental = new IncrementalOptions { MaxConnections = 8, RecvSlots = Slots, RecvBufferSize = BufferSize } };

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    int taken = 0;
                    while (taken < Slots * BufferSize)
                    {
                        RecvSnapshot snapshot = await conn.ReadAsync();
                        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                        {
                            taken += item.Len;
                        }
                        if (snapshot.IsClosed)
                        {
                            return;
                        }
                    }
                    await release.Task;
                }
                finally
                {
                    conn.DecRef();
                }
            }, config);

            using TcpClient upload = Connect(port, "U");
            upload.GetStream().Write(new byte[32 * 1024]);
            WaitFor(() => StarvedOf(reactor).Count > 0, 5_000, "the upload never ran out of buffers");

            reactor.Stop();
            release.TrySetResult();
            Assert.True(thread.Join(10_000), "the reactor never stopped");
            Assert.Equal(0, LiveOf(reactor));
        }, skip: !TestServer.KernelAtLeast(6, 12));
    }

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_TcpLive")]
    private static extern int LiveOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_recvStarved")]
    private static extern ref List<ulong> StarvedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushInProgress")]
    private static extern ref int FlushInProgressOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "FlushSeenMs")]
    private static extern ref long FlushSeenOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_acceptPaused")]
    private static extern ref List<int> PausedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_listenFds")]
    private static extern ref int[] ListenFdsOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_deferredWriteShutdowns")]
    private static extern ref ConcurrentQueue<ulong> DeferredOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "TagGen")]
    private static extern ref int TagGenOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "Slot")]
    private static extern ref int SlotOf(TcpConnection connection);

    private static ServerConfig Config(TcpOptions tcp) => new()
    {
        RecvBufferSize = 4096,
        RecvSlots = 256,
        Tcp = tcp,
    };

    private static int Start(ServerConfig config, Func<Reactor, TcpConnection, Task> handle)
        => TestServer.StartConfigured(handle, config).Port;

    // What a descriptor of this process is open on, to tell a closed or reused number from the socket it was.
    private static string? LinkOf(int fd) => new FileInfo($"/proc/self/fd/{fd}").LinkTarget;

    private static void WaitFor(Func<bool> done, int timeoutMs, string otherwise)
    {
        long start = Stopwatch.GetTimestamp();
        while (!done())
        {
            Assert.True(Stopwatch.GetElapsedTime(start).TotalMilliseconds < timeoutMs, otherwise);
            Thread.Sleep(5);
        }
    }

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

    // Everything up to the FIN, which must come within the receive timeout of the last byte. Never more than expected: a
    // server that sends more is as wrong as one that sends less.
    private static void AssertWholeThenFin(TcpClient client, byte[] expected)
    {
        NetworkStream stream = client.GetStream();
        var got = new MemoryStream(expected.Length);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            int n = ReadOnce(stream, (int)got.Length, buffer);
            if (n == 0)
            {
                break;
            }
            got.Write(buffer, 0, n);
            Assert.True(got.Length <= expected.Length, $"{got.Length} bytes, past the {expected.Length} sent");
        }

        Assert.Equal(expected.Length, (int)got.Length);
        Assert.True(got.GetBuffer().AsSpan(0, (int)got.Length).SequenceEqual(expected), "every byte arrived before the FIN, but not intact");
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

    // The first byte of the next delivery; 0 when the peer closed instead, as TestServer's listen probe does.
    private static async Task<byte> FirstByte(TcpConnection conn)
    {
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            byte first = 0;
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    if (first == 0 && item.Len > 0)
                    {
                        first = item.AsSpan()[0];
                    }
                    conn.ReturnBuffer(in item);
                }
            }

            if (first != 0 || snapshot.IsClosed)
            {
                return first;
            }
        }
    }

    private static async Task<string> ReadText(TcpConnection conn, int count)
    {
        var text = new StringBuilder();
        while (text.Length < count)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    text.Append(Encoding.ASCII.GetString(item.AsSpan()));
                    conn.ReturnBuffer(in item);
                }
            }
            if (snapshot.IsClosed)
            {
                break;
            }
        }
        return text.ToString();
    }
}
