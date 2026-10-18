using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// What is epoxide's own: a connection any thread may read and write. A handler on the thread pool
/// reads, writes and flushes there, each an ordinary syscall on its own thread. Only a read with
/// nothing to read, or a flush the socket cannot take, parks; the reactor finishes it at the next
/// edge, on its own thread, and resumes the awaiter inline there, wherever it awaited from.
/// </summary>
/// <remarks>
/// Every handler here leaves its reactor with <see cref="Hop.ToThreadPool"/>, except the one that
/// pins an awaiter on the reactor; those about the pool's side go back to it after each wait.
/// </remarks>
internal static class ThreadPoolTests
{
    /// <summary>Far past what a loopback socket takes while its peer is not reading, so a flush parks.</summary>
    private const int ParkingBytes = 16 * 1024 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("threadpool: a handler on the thread pool reads, writes and flushes from there", () =>
        {
            // Twenty requests on one connection, every one read, answered and flushed from a pool
            // thread. A read that waits resumes it on the reactor, so it goes back after each; a
            // flush this small never waits, so it finishes where it was made.
            var places = new ConcurrentQueue<string>();

            int port = TestServer.Start(async (r, conn) =>
            {
                try
                {
                    while (true)
                    {
                        await Hop.ToThreadPool();
                        places.Enqueue("read from " + Where(r));
                        RecvSnapshot snapshot = await conn.ReadAsync();
                        Wire.ReadPath(conn, snapshot);
                        if (snapshot.IsClosed)
                        {
                            return;
                        }

                        await Hop.ToThreadPool();
                        Wire.Write(conn, 200, "tp");
                        places.Enqueue("write on " + Where(r));
                        await conn.FlushAsync();
                        places.Enqueue("flush on " + Where(r));
                        conn.ResetRead();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });

            List<(int Status, string Body)> replies = Client.GetKeepAlive(port, "/", 20);
            Assert.Equal(20, replies.Count);
            foreach ((int status, string body) in replies)
            {
                Assert.Equal(200, status);
                Assert.Equal("tp", body);
            }

            string[] seen = places.ToArray();
            Assert.True(seen.Count(p => p.StartsWith("flush", StringComparison.Ordinal)) >= 20,
                $"only {seen.Length} steps were recorded, so the handler did not do what it is credited with");
            string[] off = seen.Where(p => !p.EndsWith(" pool", StringComparison.Ordinal)).ToArray();
            Assert.True(off.Length == 0, $"{off.Length} steps ran off the thread pool: {string.Join(", ", off.Take(4))}");
        });

        runner.Test("threadpool: a parked read awaited from the thread pool resumes inline on the reactor", () =>
        {
            // Five reads, each made from the pool, that find the socket empty and park; the client sends
            // only after a pause. The reactor finishes each recv at the readable edge, on its own thread,
            // and runs the awaiter right there instead of handing it back to the pool.
            const int Rounds = 5;
            var resumed = new ConcurrentQueue<string>();
            var report = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(async (r, conn) =>
            {
                int parked = 0;
                try
                {
                    for (int i = 0; i < Rounds; i++)
                    {
                        await Hop.ToThreadPool();
                        ValueTask<RecvSnapshot> read = conn.ReadAsync();
                        bool waited = !read.IsCompleted;
                        RecvSnapshot snapshot = await read;
                        if (waited)
                        {
                            parked++;
                            resumed.Enqueue(Where(r));
                        }

                        if (Drain(conn, snapshot) == 0)
                        {
                            return;   // the harness's probe, or the client gone
                        }
                        conn.Write("."u8);
                        await conn.FlushAsync();
                        conn.ResetRead();
                    }
                    report.TrySetResult(parked);
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
            for (int i = 0; i < Rounds; i++)
            {
                Thread.Sleep(100);   // the read has parked by now
                stream.Write("x"u8);
                Assert.Equal(1, stream.Read(new byte[1], 0, 1));
            }

            Assert.True(report.Task.Wait(5_000), "the handler never finished its rounds");
            Assert.Equal(Rounds, report.Task.Result);
            string[] where = resumed.ToArray();
            Assert.True(where.All(w => w == "reactor"), $"parked reads resumed on: {string.Join(", ", where)}");
        });

        runner.Test("threadpool: a parked flush awaited from the thread pool resumes inline on the reactor", () =>
        {
            // Far more than the socket takes, from the pool, at a client that is not reading yet: the
            // flush sends what fits, parks, and the reactor sends the rest at the writable edges -
            // finishing on its own thread, where the awaiter then runs.
            const int Rounds = 3;
            var resumed = new ConcurrentQueue<string>();
            var report = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (r, conn) =>
            {
                int parked = 0;
                try
                {
                    for (int i = 0; i < Rounds; i++)
                    {
                        if (Drain(conn, await conn.ReadAsync()) == 0)
                        {
                            return;   // the harness's probe, or the client gone
                        }

                        await Hop.ToThreadPool();
                        conn.Write(new byte[ParkingBytes / 4]);
                        ValueTask flush = conn.FlushAsync();
                        bool waited = !flush.IsCompleted;
                        await flush;
                        if (waited)
                        {
                            parked++;
                            resumed.Enqueue(Where(r));
                        }
                        conn.ResetRead();
                    }
                    report.TrySetResult(parked);
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config()).Port;

            using var client = new TcpClient { ReceiveBufferSize = 4096 };
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 10_000;
            for (int i = 0; i < Rounds; i++)
            {
                client.GetStream().Write("go"u8);
                Thread.Sleep(300);   // not reading: the flush has parked by now
                ReadExactly(client, ParkingBytes / 4);
            }

            Assert.True(report.Task.Wait(10_000), "the handler never finished its rounds");
            Assert.Equal(Rounds, report.Task.Result);
            string[] where = resumed.ToArray();
            Assert.True(where.All(w => w == "reactor"), $"parked flushes resumed on: {string.Join(", ", where)}");
        });

        runner.Test("threadpool: an awaiter on the reactor still resumes inline, inside the edge", () =>
        {
            // The other half of the rule, and the reason for it: a handler that never left keeps the
            // fast path. A parked read resumes inside the readable edge's own call, and a parked flush
            // inside the writable edge's.
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    if (Drain(conn, await conn.ReadAsync()) == 0)
                    {
                        return;   // the harness's probe
                    }

                    conn.ResetRead();
                    ValueTask<RecvSnapshot> read = conn.ReadAsync();
                    bool readParked = !read.IsCompleted;
                    Drain(conn, await read);
                    string afterRead = Where(r);

                    conn.Write(new byte[ParkingBytes / 4]);
                    ValueTask flush = conn.FlushAsync();
                    bool flushParked = !flush.IsCompleted;
                    await flush;
                    string afterFlush = Where(r);

                    report.TrySetResult(readParked && flushParked
                        ? $"read: {afterRead}; flush: {afterFlush}"
                        : $"nothing parked (read {readParked}, flush {flushParked}), so nothing was tested");
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config()).Port;

            using var client = new TcpClient { ReceiveBufferSize = 4096 };
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 10_000;
            client.GetStream().Write("a"u8);
            Thread.Sleep(200);                    // the second read has parked
            client.GetStream().Write("b"u8);
            Thread.Sleep(300);                    // not reading: the flush has parked
            ReadExactly(client, ParkingBytes / 4);

            Assert.True(report.Task.Wait(10_000), "the handler never reported");
            Assert.Equal("read: reactor; flush: reactor", report.Task.Result);
        });

        runner.Test("threadpool: a read on one pool thread and a flush on another share a connection, full duplex, byte-exact", () =>
        {
            // One reader and one writer at a time, as with any stream - and the two at once, on two
            // threads, neither of them the reactor's: each goes back to the pool after a wait, which
            // resumes it on the reactor. 8 MiB each way through small socket buffers, with the client
            // pausing now and then on each side, so both directions park repeatedly while the other is
            // mid-syscall.
            const int Bytes = 8 * 1024 * 1024, Mebibyte = 1024 * 1024;
            var serverRead = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int parkedReads = 0, parkedFlushes = 0;

            int port = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    // The stream's first bytes, which tell this connection from the harness's probe.
                    byte[] head = Take(conn, await conn.ReadAsync());
                    if (head.Length == 0)
                    {
                        return;   // the harness's probe
                    }
                    conn.ResetRead();

                    Task<string> reading = Task.Run(async () =>
                    {
                        for (int i = 0; i < head.Length; i++)
                        {
                            if (head[i] != Pattern(i, 17))
                            {
                                return $"byte {i} arrived as 0x{head[i]:X2}, expected 0x{Pattern(i, 17):X2}";
                            }
                        }

                        long got = head.Length;
                        while (got < Bytes)
                        {
                            ValueTask<RecvSnapshot> pending = conn.ReadAsync();
                            bool waited = !pending.IsCompleted;
                            if (waited)
                            {
                                Interlocked.Increment(ref parkedReads);
                            }
                            RecvSnapshot snapshot = await pending;
                            if (waited)
                            {
                                await Hop.ToThreadPool();
                            }
                            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                            {
                                if (!item.HasBuffer)
                                {
                                    continue;
                                }
                                ReadOnlySpan<byte> span = item.AsSpan();
                                for (int i = 0; i < span.Length; i++)
                                {
                                    if (span[i] != Pattern(got + i, 17))
                                    {
                                        conn.ReturnBuffer(in item);
                                        return $"byte {got + i} arrived as 0x{span[i]:X2}, expected 0x{Pattern(got + i, 17):X2}";
                                    }
                                }
                                got += span.Length;
                                conn.ReturnBuffer(in item);
                            }
                            if (snapshot.IsClosed && got < Bytes)
                            {
                                return $"the connection closed after {got} of {Bytes} bytes";
                            }
                            conn.ResetRead();
                        }
                        return Thread.CurrentThread.IsThreadPoolThread ? "ok" : "the reader ran off the pool";
                    });

                    Task writing = Task.Run(async () =>
                    {
                        byte[] chunk = new byte[64 * 1024];
                        for (long sent = 0; sent < Bytes; sent += chunk.Length)
                        {
                            for (int i = 0; i < chunk.Length; i++)
                            {
                                chunk[i] = Pattern(sent + i, 91);
                            }
                            conn.Write(chunk);
                            ValueTask flush = conn.FlushAsync();
                            if (!flush.IsCompleted)
                            {
                                Interlocked.Increment(ref parkedFlushes);
                                await flush;
                                await Hop.ToThreadPool();
                            }
                        }
                    });

                    serverRead.TrySetResult(await reading.ConfigureAwait(false));
                    await writing.ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    serverRead.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config()).Port;

            using var client = new TcpClient { ReceiveBufferSize = 64 * 1024, SendBufferSize = 64 * 1024 };
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 30_000;

            string clientRead = "";
            var reader = new Thread(() =>
            {
                try
                {
                    byte[] buffer = new byte[64 * 1024];
                    long got = 0;
                    while (got < Bytes)
                    {
                        int n = client.Client.Receive(buffer);
                        if (n == 0)
                        {
                            clientRead = $"EOF after {got} of {Bytes} bytes";
                            return;
                        }
                        for (int i = 0; i < n; i++)
                        {
                            if (buffer[i] != Pattern(got + i, 91))
                            {
                                clientRead = $"byte {got + i} arrived as 0x{buffer[i]:X2}, expected 0x{Pattern(got + i, 91):X2}";
                                return;
                            }
                        }
                        if ((got + n) / Mebibyte != got / Mebibyte)
                        {
                            Thread.Sleep(20);   // a slow reader now and then, so the server's flushes park
                        }
                        got += n;
                    }
                    clientRead = "ok";
                }
                catch (Exception e)
                {
                    clientRead = $"{e.GetType().Name}: {e.Message}";
                }
            }) { IsBackground = true };
            reader.Start();

            byte[] outgoing = new byte[64 * 1024];
            for (long sent = 0; sent < Bytes; sent += outgoing.Length)
            {
                for (int i = 0; i < outgoing.Length; i++)
                {
                    outgoing[i] = Pattern(sent + i, 17);
                }
                client.Client.Send(outgoing);
                if ((sent + outgoing.Length) % Mebibyte == 0)
                {
                    Thread.Sleep(20);   // a slow sender now and then, so the server's reads park
                }
            }

            Assert.True(serverRead.Task.Wait(30_000), "the server's reader never finished");
            Assert.True(reader.Join(30_000), "the client's reader never finished");
            Assert.Equal("ok", serverRead.Task.Result);
            Assert.Equal("ok", clientRead);
            Assert.True(Volatile.Read(ref parkedReads) > 0 && Volatile.Read(ref parkedFlushes) > 0,
                $"{parkedReads} reads and {parkedFlushes} flushes parked: the two directions never waited on the socket, so they never overlapped a park");
        });

        runner.Test("threadpool: a peer reset while a pool-thread handler's flush is parked ends the flush, with the connection closed", () =>
        {
            var parked = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    if (Drain(conn, await conn.ReadAsync()) == 0)
                    {
                        return;   // the harness's probe
                    }
                    await Hop.ToThreadPool();

                    conn.Write(new byte[ParkingBytes]);
                    ValueTask flush = conn.FlushAsync();
                    if (flush.IsCompleted)
                    {
                        outcome.TrySetResult("the flush never parked, so nothing was tested");
                        return;
                    }
                    parked.TrySetResult(ExecInheritance.Target(conn.ClientFd) + " " + conn.ClientFd);

                    await flush;
                    outcome.TrySetResult($"{(conn.IsClosed ? "closed" : "open")}, on {Where(r)}");
                }
                catch (Exception e)
                {
                    outcome.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config()).Port;

            var client = new TcpClient { ReceiveBufferSize = 4096 };
            client.Connect("127.0.0.1", port);
            client.GetStream().Write("x"u8);
            Assert.True(parked.Task.Wait(10_000), $"the flush never parked: {(outcome.Task.IsCompleted ? outcome.Task.Result : "no word")}");
            Thread.Sleep(200);   // and awaited: a reset that beat the await would resume it where it awaited
            client.LingerState = new LingerOption(true, 0);
            client.Close();   // RST, with the server's flush parked

            Assert.True(outcome.Task.Wait(10_000), "the flush stayed parked after its peer reset the connection");
            Assert.Equal("closed, on reactor", outcome.Task.Result);
            AssertClosesAfterRelease(parked.Task.Result);
        });

        runner.Test("threadpool: a peer reset while a pool-thread handler's read is parked wakes it with the end", () =>
        {
            var parked = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    if (Drain(conn, await conn.ReadAsync()) == 0)
                    {
                        return;   // the harness's probe
                    }
                    await Hop.ToThreadPool();

                    conn.ResetRead();
                    ValueTask<RecvSnapshot> read = conn.ReadAsync();
                    if (read.IsCompleted)
                    {
                        outcome.TrySetResult("the read never parked, so nothing was tested");
                        return;
                    }
                    parked.TrySetResult(ExecInheritance.Target(conn.ClientFd) + " " + conn.ClientFd);

                    RecvSnapshot snapshot = await read;
                    outcome.TrySetResult($"{(snapshot.IsClosed ? "the end" : "no end")}, on {Where(r)}");
                }
                catch (Exception e)
                {
                    outcome.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config()).Port;

            var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.GetStream().Write("x"u8);
            Assert.True(parked.Task.Wait(10_000), $"the read never parked: {(outcome.Task.IsCompleted ? outcome.Task.Result : "no word")}");
            Thread.Sleep(200);   // and awaited: a reset that beat the await would resume it where it awaited
            client.LingerState = new LingerOption(true, 0);
            client.Close();   // RST, with the server's read parked

            Assert.True(outcome.Task.Wait(10_000), "the read stayed parked after its peer reset the connection");
            Assert.Equal("the end, on reactor", outcome.Task.Result);
            AssertClosesAfterRelease(parked.Task.Result);
        });

        runner.Test("threadpool: a DecRef on a pool thread closes the descriptor once the peer goes, and the next accept reuses the connection", () =>
        {
            // The handler lets go first, from the pool: its FIN goes out at once, the reactor keeps the
            // connection until the peer closes, and only then closes the descriptor and pools the object.
            var handled = new ConcurrentQueue<(TcpConnection Conn, string Socket)>();
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    if (Drain(conn, await conn.ReadAsync()) == 0)
                    {
                        return;   // the harness's probe
                    }
                    await Hop.ToThreadPool();

                    Wire.Write(conn, 200, "bye");
                    await conn.FlushAsync();
                    handled.Enqueue((conn, ExecInheritance.Target(conn.ClientFd) + " " + conn.ClientFd));
                }
                finally
                {
                    conn.DecRef();   // on the pool, for the test's connections
                }
            }, Config());

            TcpConnection first = RoundTrip(port, handled, peerClosesFirst: false, out string socket);
            Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(reactor) == 0, 5_000), "the connection was never recycled");
            AssertClosesAfterRelease(socket);

            TcpConnection second = RoundTrip(port, handled, peerClosesFirst: false, out _);
            Assert.True(ReferenceEquals(first, second), "the next accept was not handed the pooled connection");
        });

        runner.Test("threadpool: a DecRef on a pool thread after the peer has gone recycles the connection from there", () =>
        {
            // The other order: the peer closes first, the pool-thread reader sees the end, and the
            // handler's release is the last ref - so the recycle is queued from a pool thread and must
            // still close the descriptor and pool the object on the reactor.
            var handled = new ConcurrentQueue<(TcpConnection Conn, string Socket)>();
            (int port, Reactor reactor, _) = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    if (Drain(conn, await conn.ReadAsync()) == 0)
                    {
                        return;   // the harness's probe
                    }
                    await Hop.ToThreadPool();

                    Wire.Write(conn, 200, "bye");
                    await conn.FlushAsync();
                    string socket = ExecInheritance.Target(conn.ClientFd) + " " + conn.ClientFd;

                    // Read on until the peer's close, then hold on a moment so the reactor's end is in first.
                    RecvSnapshot snapshot;
                    do
                    {
                        conn.ResetRead();
                        snapshot = await conn.ReadAsync();
                        Drain(conn, snapshot);
                    }
                    while (!snapshot.IsClosed);

                    // The read resumed on the reactor: waiting here for the reactor's own work would hold it.
                    await Hop.ToThreadPool();
                    Assert.True(SpinWait.SpinUntil(() => Internals.Refs(conn) == 1, 5_000), "the reactor never let go of the closed connection");

                    handled.Enqueue((conn, socket));
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config());

            TcpConnection first = RoundTrip(port, handled, peerClosesFirst: true, out string socket);
            Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(reactor) == 0, 5_000), "the connection was never recycled");
            AssertClosesAfterRelease(socket);

            TcpConnection second = RoundTrip(port, handled, peerClosesFirst: true, out _);
            Assert.True(ReferenceEquals(first, second), "the next accept was not handed the pooled connection");
        });

        runner.Test("threadpool: Stop() while pool-thread handlers hold their connections closes each descriptor as its handler lets go", () =>
        {
            // The reactor can stop with handlers still out on the pool: it ends every connection for its
            // peer at once, but closes no descriptor under a handler that may be mid-syscall - each closes
            // when its handler lets go, and the last one frees the pools. No leak, no crash.
            const int Held = 8;
            int before = FdCount.Stable();

            using var holding = new CountdownEvent(Held);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var sockets = new ConcurrentQueue<string>();
            var after = new ConcurrentQueue<string>();

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
            {
                try
                {
                    if (Drain(conn, await conn.ReadAsync()) == 0)
                    {
                        return;   // the harness's probe
                    }
                    await Hop.ToThreadPool();
                    sockets.Enqueue(ExecInheritance.Target(conn.ClientFd) + " " + conn.ClientFd);
                    holding.Signal();

                    await gate.Task;   // on the pool, past the stop

                    // The connection still works as a closed one: the read sees the end at once, and a
                    // flush drops what it was given instead of parking.
                    conn.ResetRead();
                    ValueTask<RecvSnapshot> read = conn.ReadAsync();
                    bool immediate = read.IsCompleted;
                    RecvSnapshot snapshot = await read;
                    Wire.Write(conn, 200, "late");
                    ValueTask flush = conn.FlushAsync();
                    bool dropped = flush.IsCompleted;
                    await flush;
                    after.Enqueue($"{(immediate && snapshot.IsClosed ? "ended" : "read waited")} {(dropped ? "dropped" : "flush parked")}");
                }
                catch (Exception e)
                {
                    after.Enqueue($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config());

            var clients = new List<TcpClient>();
            try
            {
                for (int i = 0; i < Held; i++)
                {
                    var client = new TcpClient();
                    client.Connect("127.0.0.1", port);
                    client.ReceiveTimeout = 5_000;
                    client.GetStream().Write("x"u8);
                    clients.Add(client);
                }
                Assert.True(holding.Wait(10_000), $"only {Held - holding.CurrentCount} of {Held} handlers reached the pool");

                reactor.Stop();
                Assert.True(thread.Join(5_000), "the reactor did not stop while its handlers held connections");

                foreach (TcpClient client in clients)
                {
                    Assert.Equal(0, ReceiveOrReset(client));   // the stop ended it for its peer
                }

                string[] held = sockets.ToArray();
                foreach (string socket in held)
                {
                    (string target, int fd) = Split(socket);
                    Assert.True(ExecInheritance.Target(fd) == target, $"fd {fd} was closed by the stop, under the handler still holding it");
                }
                Assert.Equal(Held, Internals.LiveConnections(reactor));
                Assert.True(Internals.RecvPool(reactor).Total > 0, "the recv pool was freed with handlers still holding connections");

                gate.SetResult();
                Assert.True(SpinWait.SpinUntil(() => after.Count == Held, 10_000), $"only {after.Count} of {Held} handlers finished after the stop");
                string[] outcomes = after.ToArray();
                Assert.True(outcomes.All(o => o == "ended dropped"), $"after the stop: {string.Join("; ", outcomes.Distinct())}");

                foreach (string socket in held)
                {
                    AssertClosesAfterRelease(socket);
                }
                Assert.Equal(0, Internals.LiveConnections(reactor));
                Assert.True(Internals.RecvPool(reactor).Total == 0, "the last connection let go and the recv pool outlived it");
                Assert.True(Internals.WriteSlabPool(reactor).Total == 0, "the last connection let go and the write-slab pool outlived it");
            }
            finally
            {
                foreach (TcpClient client in clients)
                {
                    client.Dispose();
                }
            }

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 2, $"{leaked} descriptors outlived the stopped server and every one of its handlers");
        });

        runner.Test("threadpool: many connections served from the pool, under load, are all answered byte-exact", () =>
        {
            // Two reactors, 48 clients, 40 requests each, answered from the pool with bodies from one
            // byte to well past the slab and the socket: correctness and no hang, nothing about speed.
            const int Clients = 48, Requests = 40;
            int[] sizes = [1, 700, 20_000, 300_000];
            int port = TestServer.StartSharded(2, static (_, r, conn) => PoolServe(r, conn));

            var errors = new ConcurrentQueue<string>();
            int answered = 0;
            var threads = new Thread[Clients];
            for (int c = 0; c < Clients; c++)
            {
                int index = c;
                threads[c] = new Thread(() =>
                {
                    try
                    {
                        using var client = new TcpClient { ReceiveBufferSize = 16 * 1024 };
                        client.Connect("127.0.0.1", port);
                        client.ReceiveTimeout = 30_000;
                        for (int i = 0; i < Requests; i++)
                        {
                            int n = sizes[(index + i) % sizes.Length];
                            client.GetStream().Write(Encoding.ASCII.GetBytes($"{n}\n"));
                            byte[] body = ReadExactly(client, n);
                            for (int j = 0; j < n; j++)
                            {
                                if (body[j] != Body(j, n))
                                {
                                    errors.Enqueue($"client {index}, request {i}: byte {j} of {n} is 0x{body[j]:X2}");
                                    return;
                                }
                            }
                            Interlocked.Increment(ref answered);
                        }
                    }
                    catch (Exception e)
                    {
                        errors.Enqueue($"client {index}: {e.GetType().Name}: {e.Message}");
                    }
                }) { IsBackground = true };
                threads[c].Start();
            }

            foreach (Thread t in threads)
            {
                Assert.True(t.Join(60_000), "a client never finished: a connection served from the pool hung");
            }

            Assert.True(errors.IsEmpty, $"{errors.Count} clients failed: {string.Join("; ", errors.Take(3))}");
            Assert.Equal(Clients * Requests, answered);
        });

        runner.Test("threadpool: the pipe reader, the pipe writer and the stream resume a pool-thread caller inline on the reactor", () =>
        {
            // The adapters chain onto the connection's own sources and resume their callers inline from
            // that continuation, which runs on the reactor wherever the caller awaited from.
            foreach (string adapter in (string[])["pipe", "stream"])
            {
                var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

                int port = TestServer.StartConfigured(async (r, conn) =>
                {
                    try
                    {
                        if (Drain(conn, await conn.ReadAsync()) == 0)
                        {
                            return;   // the harness's probe
                        }
                        conn.ResetRead();
                        await Hop.ToThreadPool();

                        report.TrySetResult(adapter == "pipe" ? await ThroughPipes(r, conn) : await ThroughStream(r, conn));
                    }
                    catch (Exception e)
                    {
                        report.TrySetResult($"{e.GetType().Name}: {e.Message}");
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, Config()).Port;

                using var client = new TcpClient { ReceiveBufferSize = 4096 };
                client.Connect("127.0.0.1", port);
                client.ReceiveTimeout = 10_000;
                client.GetStream().Write("a"u8);
                Thread.Sleep(200);                 // the adapter's read has parked
                client.GetStream().Write("b"u8);
                Thread.Sleep(300);                 // not reading: the adapter's flush has parked
                ReadExactly(client, ParkingBytes / 4);

                Assert.True(report.Task.Wait(10_000), $"{adapter}: the handler never reported");
                Assert.Equal($"{adapter}: read parked, resumed on reactor; flush parked, resumed on reactor", report.Task.Result);
            }
        });
    }

    private static async Task<string> ThroughPipes(Reactor r, TcpConnection conn)
    {
        var reader = new TcpConnectionPipeReader(conn);
        var writer = new TcpConnectionPipeWriter(conn);
        try
        {
            ValueTask<ReadResult> read = reader.ReadAsync();
            bool readParked = !read.IsCompleted;
            ReadResult result = await read;
            string afterRead = Where(r);
            reader.AdvanceTo(result.Buffer.End);

            writer.Write((ReadOnlySpan<byte>)new byte[ParkingBytes / 4]);
            ValueTask<FlushResult> flush = writer.FlushAsync();
            bool flushParked = !flush.IsCompleted;
            await flush;
            string afterFlush = Where(r);

            return $"pipe: read {Parked(readParked)}, resumed on {afterRead}; flush {Parked(flushParked)}, resumed on {afterFlush}";
        }
        finally
        {
            reader.Complete();
            writer.Complete();
        }
    }

    private static async Task<string> ThroughStream(Reactor r, TcpConnection conn)
    {
        using var stream = new TcpConnectionStream(conn);

        ValueTask<int> read = stream.ReadAsync(new byte[16]);
        bool readParked = !read.IsCompleted;
        await read;
        string afterRead = Where(r);

        ValueTask write = stream.WriteAsync(new byte[ParkingBytes / 4]);
        bool flushParked = !write.IsCompleted;
        await write;
        string afterFlush = Where(r);

        return $"stream: read {Parked(readParked)}, resumed on {afterRead}; flush {Parked(flushParked)}, resumed on {afterFlush}";
    }

    private static string Parked(bool parked) => parked ? "parked" : "did not park";

    /// <summary>"reactor", "pool", or the thread it is - where handler code is running right now.</summary>
    private static string Where(Reactor r)
        => r.OnReactorThread ? "reactor"
         : Thread.CurrentThread.IsThreadPoolThread ? "pool"
         : $"thread {Environment.CurrentManagedThreadId}";

    // A keep-alive server whose handler leaves the reactor at once: each line is a size, answered with
    // that many bytes of Body, written and flushed from the pool - going back to it after any wait,
    // which resumes it on the reactor.
    private static async Task PoolServe(Reactor r, TcpConnection conn)
    {
        var carry = new List<byte>();
        try
        {
            await Hop.ToThreadPool();
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                if (r.OnReactorThread)
                {
                    await Hop.ToThreadPool();
                }
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        carry.AddRange(item.AsSpan().ToArray());
                        conn.ReturnBuffer(in item);
                    }
                }

                int at;
                while ((at = carry.IndexOf((byte)'\n')) >= 0)
                {
                    int n = int.Parse(Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(carry)[..at]));
                    carry.RemoveRange(0, at + 1);
                    conn.Write(Bodies.GetOrAdd(n, static size => [.. Enumerable.Range(0, size).Select(j => Body(j, size))]));
                    await conn.FlushAsync();
                    if (r.OnReactorThread)
                    {
                        await Hop.ToThreadPool();
                    }
                }

                if (snapshot.IsClosed)
                {
                    return;
                }
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static readonly ConcurrentDictionary<int, byte[]> Bodies = new();

    private static byte Body(int index, int size) => (byte)(index * 7 + size);

    private static byte Pattern(long index, int seed) => (byte)((index * 131 + seed) ^ (index >> 11));

    /// <summary>
    /// One connection: a request, the answer, and the close - by the peer before or after the server's
    /// FIN - then the connection object and socket the handler recorded for it.
    /// </summary>
    private static TcpConnection RoundTrip(int port, ConcurrentQueue<(TcpConnection Conn, string Socket)> handled,
        bool peerClosesFirst, out string socket)
    {
        int seen = handled.Count;
        using (var client = new TcpClient())
        {
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            Client.Send(client.GetStream(), "/");
            (int status, string body) = Client.ReadResponse(client.GetStream());
            Assert.Equal(200, status);
            Assert.Equal("bye", body);

            if (!peerClosesFirst)
            {
                Assert.Equal(0, client.Client.Receive(new byte[1]));   // the handler's FIN, from the pool
            }
        }

        Assert.True(SpinWait.SpinUntil(() => handled.Count > seen, 5_000), "the handler never recorded the connection");
        (TcpConnection conn, string recorded) = handled.ToArray()[seen];
        socket = recorded;
        return conn;
    }

    // "socket:[inode] fd" as the handlers record it.
    private static (string Target, int Fd) Split(string recorded)
    {
        int space = recorded.LastIndexOf(' ');
        return (recorded[..space], int.Parse(recorded[(space + 1)..]));
    }

    /// <summary>The descriptor a handler recorded stops being that socket: the connection's close happened.</summary>
    private static void AssertClosesAfterRelease(string recorded)
    {
        (string target, int fd) = Split(recorded);
        Assert.True(target.StartsWith("socket:[", StringComparison.Ordinal), $"fd {fd} was not a socket when recorded: '{target}'");
        Assert.True(SpinWait.SpinUntil(() => ExecInheritance.Target(fd) != target, 5_000),
            $"fd {fd} still holds the connection's socket after its handler let go and its peer went");
    }

    private static int ReceiveOrReset(TcpClient client)
    {
        try
        {
            return client.Client.Receive(new byte[16]);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
        {
            return 0;
        }
    }

    // Copies every buffer of a snapshot out and hands it back to the pool.
    private static byte[] Take(TcpConnection conn, in RecvSnapshot snapshot)
    {
        var bytes = new List<byte>();
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                bytes.AddRange(item.AsSpan().ToArray());
                conn.ReturnBuffer(in item);
            }
        }
        return [.. bytes];
    }

    // Takes every buffer of a snapshot back to the pool and says how many bytes they held.
    private static int Drain(TcpConnection conn, in RecvSnapshot snapshot)
    {
        int bytes = 0;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                bytes += item.Len;
                conn.ReturnBuffer(in item);
            }
        }
        return bytes;
    }

    private static byte[] ReadExactly(TcpClient client, int count)
    {
        var buffer = new byte[count];
        for (int got = 0; got < count;)
        {
            int n = client.Client.Receive(buffer, got, count - got, SocketFlags.None);
            if (n == 0)
            {
                throw new IOException($"EOF after {got} of {count} bytes");
            }
            got += n;
        }
        return buffer;
    }

    private static ServerConfig Config() => new()
    {
        RecvBufferSize = 4096,
        Tcp = new TcpOptions
        {
            WriteSlabSize = 16 * 1024,
            PoolMax = 64,
            RecvQueueEntries = 64,
            ReadTimeoutMs = 0,
            SendTimeoutMs = 0,
        },
    };
}
