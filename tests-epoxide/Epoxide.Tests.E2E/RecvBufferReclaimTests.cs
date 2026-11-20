using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Recv buffers a <see cref="TcpConnectionPipeReader"/> or <see cref="TcpConnectionStream"/> is still
/// holding when its connection is recycled.
/// </summary>
/// <remarks>
/// The reader pulls buffers out of the connection's recv queue to hand their memory straight to the
/// caller - <c>TryGetItem</c> is a dequeue, so from that moment the connection has no record of
/// them. <c>DrainRecv</c> at recycle walks that queue and finds nothing, so anything the reader
/// holds comes back only if someone hands it back.
///
/// In ioxide a stranded buffer is a slot out of a fixed group, and the group running dry is what
/// the tests saw. epoxide's pool grows when it is empty, so a stranded buffer never stops service -
/// it is memory, gone for the life of the process - and every connection here is served whether or
/// not anything leaks. So each test also counts the reactor's pool once its connections are gone
/// (<see cref="Internals.RecvPool"/>), and every buffer must be back.
/// </remarks>
internal static class RecvBufferReclaimTests
{
    /// <summary>Many times what one connection holds, so a per-connection leak cannot hide in the count.</summary>
    private const int Connections = 64;

    private static ServerConfig SmallBuffers() => new()
    {
        RecvBufferSize = 1024,
        Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, RecvQueueEntries = 16 },
    };

    /// <summary>
    /// Opens <see cref="Connections"/> connections in turn, each sending a request and expecting a
    /// one-byte answer, and says how many were served.
    /// </summary>
    private static int DriveConnections(int port, byte[]? request = null, int delayMs = 0)
    {
        request ??= "x"u8.ToArray();
        int answered = 0;

        for (int i = 0; i < Connections; i++)
        {
            try
            {
                using var client = new TcpClient();
                client.Connect("127.0.0.1", port);
                client.ReceiveTimeout = 2_000;

                if (delayMs > 0)
                {
                    Thread.Sleep(delayMs);   // let the handler reach the state under test first
                }

                client.GetStream().Write(request);

                var reply = new byte[1];
                if (client.GetStream().Read(reply, 0, 1) == 1)
                {
                    answered++;
                }
            }
            catch (Exception)
            {
                break;   // this connection can no longer be read from
            }
        }

        return answered;
    }

    /// <summary>
    /// Every connection recycled, then every buffer back in the pool. A stranded one stays rented
    /// for the life of the process, and recycle is the last moment anything could hand it back.
    /// </summary>
    private static void AssertEveryBufferBack(Reactor reactor)
    {
        Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(reactor) == 0, 10_000),
            $"{Internals.LiveConnections(reactor)} connections were never recycled");

        Internals.PoolCount pool = Internals.RecvPool(reactor);
        Assert.True(pool.Total > 0, "the reactor never rented a recv buffer, so nothing was tested");
        Assert.True(pool.Rented == 0,
            $"{pool.Rented} of {pool.Total} recv buffers never came back to the pool after every connection was recycled");
    }

    public static void Register(Runner runner)
    {
        runner.Test("recv buffers: a handler that never completes its reader does not strand them", () =>
        {
            // The leaky shape, on purpose: read (which pulls a buffer into the reader's chain),
            // answer, and return without Complete() and without advancing. Every connection walks
            // off with at least one buffer.
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);

                ReadResult result = await reader.ReadAsync();

                if (!result.Buffer.IsEmpty)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                // No reader.Complete() - the whole point.
                conn.DecRef();
            }, SmallBuffers());

            Assert.Equal(Connections, DriveConnections(port));
            AssertEveryBufferBack(reactor);
        });

        runner.Test("recv buffers: completing one reader does not de-register a live one", () =>
        {
            // The reclaim hangs off a single slot on the connection, so completing a reader must not
            // evict a different one that registered after it: a reader that holds nothing, completed
            // after a second one registered, would put the original leak straight back.
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                var first = new TcpConnectionPipeReader(conn);
                var second = new TcpConnectionPipeReader(conn);   // now the registered holder

                ReadResult result = await second.ReadAsync();     // 'second' is the one holding

                if (!result.Buffer.IsEmpty)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                first.Complete();     // holds nothing - and must not evict 'second'
                conn.DecRef();        // 'second' never completed: recycle has to reclaim from it
            }, SmallBuffers());

            Assert.Equal(Connections, DriveConnections(port));
            AssertEveryBufferBack(reactor);
        });

        runner.Test("recv buffers: completing a reader with a read still parked does not strand what lands after", () =>
        {
            // Complete() must not de-register, because completing does not disarm a parked read. The
            // awaiter stays armed, the next readable edge resumes it, and the reader ingests buffers
            // AFTER it was completed - with nobody registered to reclaim them, which is the original
            // leak reintroduced by the fix for it.
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);

                // Parks: the client deliberately has not sent yet.
                Task<ReadResult> parked = reader.ReadAsync().AsTask();

                reader.Complete();            // completed, but that read is still armed

                ReadResult result = await parked;   // the client's bytes land in a completed reader

                if (!result.Buffer.IsEmpty)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                conn.DecRef();
            }, SmallBuffers());

            Assert.Equal(Connections, DriveConnections(port, delayMs: 30));
            AssertEveryBufferBack(reactor);
        });

        runner.Test("recv buffers: a stream stopped mid-slice does not strand its buffer", () =>
        {
            // TcpConnectionStream is the other holder: it keeps the slice it is copying out and
            // returns it only once drained. Reading one byte of several leaves that buffer held - the
            // shape an aborted SslStream handshake or a truncated record produces.
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                var stream = new TcpConnectionStream(conn);

                var one = new byte[1];
                int n = await stream.ReadAsync(one);              // one byte out of eight

                if (n > 0)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                // Neither drained nor disposed: the rest of the slice is still held.
                conn.DecRef();
            }, SmallBuffers());

            Assert.Equal(Connections, DriveConnections(port, request: "xxxxxxxx"u8.ToArray()));
            AssertEveryBufferBack(reactor);
        });

        runner.Test("recv buffers: disposing a stream returns its buffer without waiting for recycle", () =>
        {
            // Recycle cannot help here: one connection, held open for the whole run, so the reclaim
            // never fires. The only thing that can give a buffer back is Dispose - the idiomatic
            // `new SslStream(stream, leaveInnerStreamOpen: false)` depends on it. A fresh stream per
            // round, each reading one byte of eight and leaving the rest held.
            var report = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                int served = 0;
                try
                {
                    for (int i = 0; i < Connections; i++)
                    {
                        var stream = new TcpConnectionStream(conn);

                        var one = new byte[1];
                        if (await stream.ReadAsync(one) <= 0)
                        {
                            break;
                        }

                        stream.Dispose();   // returns the slice, with seven bytes still unread in it
                        conn.ResetRead();

                        conn.Write("."u8);
                        await conn.FlushAsync();
                        served++;
                    }
                }
                catch (Exception)
                {
                    // Reported as a short count.
                }
                finally
                {
                    report.TrySetResult(served);
                    conn.DecRef();
                }
            }, SmallBuffers());

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 2_000;
            NetworkStream io = client.GetStream();

            int answered = 0;
            for (int i = 0; i < Connections; i++)
            {
                try
                {
                    io.Write("xxxxxxxx"u8);

                    var reply = new byte[1];
                    if (io.Read(reply, 0, 1) != 1)
                    {
                        break;
                    }
                    answered++;
                }
                catch (Exception)
                {
                    break;   // this connection can no longer be read from
                }
            }

            Assert.Equal(Connections, answered);

            // The connection is still open - the client holds it - so only Dispose can have returned them.
            Internals.PoolCount pool = Internals.RecvPool(reactor);
            Assert.True(pool.Total > 0, "the reactor never rented a recv buffer, so nothing was tested");
            Assert.True(pool.Rented == 0,
                $"{pool.Rented} recv buffers were still out on a connection whose every stream was disposed");
        });

        runner.Test("recv buffers: a reader completed, or a stream disposed, on the thread pool after its handler let go hands each back once", () =>
        {
            // The idiomatic spellings release after DecRef - `using var stream`, or Complete() below a
            // try/finally that lets go - and from the thread pool that release runs while the reactor
            // recycles the connection and reclaims the same buffers. Returned twice, a buffer links the
            // pool's free list into a cycle, and every rent after it hands that buffer to everyone.
            const int Connections = 5_000;
            foreach (bool stream in new[] { false, true })
            {
                int handled = 0;
                (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
                {
                    TcpConnectionPipeReader? reader = stream ? null : new TcpConnectionPipeReader(conn);
                    TcpConnectionStream? adapter = stream ? new TcpConnectionStream(conn) : null;
                    bool client;   // the harness's probe sends nothing, and is not counted
                    await Hop.ToThreadPool();
                    try
                    {
                        if (reader is not null)
                        {
                            ReadResult result = await reader.ReadAsync();
                            client = !result.Buffer.IsEmpty;
                            reader.AdvanceTo(result.Buffer.Start, result.Buffer.End);   // examined, not consumed: still held
                        }
                        else
                        {
                            client = await adapter!.ReadAsync(new byte[1]) > 0;   // one byte out, the rest of its buffer held
                        }
                    }
                    finally
                    {
                        conn.DecRef();
                    }

                    Thread.SpinWait(Random.Shared.Next(4_000));   // across the moment the reactor reclaims
                    reader?.Complete();
                    adapter?.Dispose();
                    if (client)
                    {
                        Interlocked.Increment(ref handled);
                    }
                }, new ServerConfig { RecvBufferSize = 1024, Tcp = new TcpOptions { ReadTimeoutMs = 0 } });

                var request = new byte[100];
                Parallel.For(0, Connections, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ =>
                {
                    using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    client.Connect(IPAddress.Loopback, port);
                    client.Send(request);
                    client.Shutdown(SocketShutdown.Both);
                });

                Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref handled) == Connections, 20_000),
                    $"{Volatile.Read(ref handled)} of {Connections} {(stream ? "stream" : "reader")} handlers finished");
                AssertEveryBufferBack(reactor);
            }
        });

        runner.Test("recv buffers: an adapter released by another task while its read is parked or completing hands each back once", () =>
        {
            // A duplex handler's other half - a write loop that ended, a dispose in a finally - releases
            // the reader while its read loop, on another pool thread, is parked or in the middle of
            // taking a recv. The read must end, and nothing it was handed may be lost or returned twice.
            const int Connections = 400;
            foreach (bool stream in new[] { false, true })
            {
                int handled = 0;
                var faults = new ConcurrentQueue<string>();
                (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
                {
                    TcpConnectionPipeReader? reader = stream ? null : new TcpConnectionPipeReader(conn);
                    TcpConnectionStream? adapter = stream ? new TcpConnectionStream(conn) : null;
                    bool client = false;
                    try
                    {
                        await Hop.ToThreadPool();

                        // The first bytes, before the race: the harness's probe sends none, and is not counted.
                        if (reader is not null)
                        {
                            ReadResult first = await reader.ReadAsync();
                            client = !first.Buffer.IsEmpty;
                            reader.AdvanceTo(first.Buffer.End);
                        }
                        else
                        {
                            client = await adapter!.ReadAsync(new byte[4096]) > 0;
                        }
                        if (!client)
                        {
                            return;
                        }

                        Task loop = Task.Run(async () =>
                        {
                            try
                            {
                                var buffer = new byte[4096];
                                while (true)
                                {
                                    if (reader is not null)
                                    {
                                        ReadResult result = await reader.ReadAsync();
                                        reader.AdvanceTo(result.Buffer.End);
                                        if (result.IsCompleted)
                                        {
                                            return;
                                        }
                                    }
                                    else if (await adapter!.ReadAsync(buffer) == 0)
                                    {
                                        return;
                                    }
                                }
                            }
                            catch (InvalidOperationException)
                            {
                                // A read after the Complete, refused - as it should be.
                            }
                            catch (Exception e)
                            {
                                faults.Enqueue($"{e.GetType().Name}: {e.Message}");
                            }
                        });

                        Thread.SpinWait(Random.Shared.Next(200_000));
                        reader?.Complete();
                        adapter?.Dispose();
                        await loop;
                    }
                    finally
                    {
                        conn.DecRef();
                        if (client)
                        {
                            Interlocked.Increment(ref handled);
                        }
                    }
                }, new ServerConfig { RecvBufferSize = 4096, Tcp = new TcpOptions { ReadTimeoutMs = 0 } });

                var blob = new byte[64 * 1024];
                Parallel.For(0, Connections, new ParallelOptions { MaxDegreeOfParallelism = 4 }, _ =>
                {
                    using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { SendTimeout = 200 };
                    client.Connect(IPAddress.Loopback, port);
                    try
                    {
                        for (long until = Environment.TickCount64 + 5; Environment.TickCount64 < until;)
                        {
                            client.Send(blob);
                        }
                    }
                    catch (SocketException)
                    {
                        // The server stopped reading.
                    }
                });

                Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref handled) == Connections, 20_000),
                    $"{Volatile.Read(ref handled)} of {Connections} {(stream ? "stream" : "reader")} handlers finished");
                Assert.True(faults.IsEmpty, $"{faults.Count} read loops faulted, first: {faults.FirstOrDefault()}");
                AssertEveryBufferBack(reactor);
            }
        });

        runner.Test("recv buffers: completing the reader returns them, with or without reclaim", () =>
        {
            // The control. Same shape, same small buffers, but the handler completes its reader - the
            // path that always worked. If this ever fails, buffers are going missing for some other
            // reason than the defects above and their assertions prove nothing.
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                try
                {
                    ReadResult result = await reader.ReadAsync();

                    if (!result.Buffer.IsEmpty)
                    {
                        conn.Write("."u8);
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            }, SmallBuffers());

            Assert.Equal(Connections, DriveConnections(port));
            AssertEveryBufferBack(reactor);
        });
    }
}
