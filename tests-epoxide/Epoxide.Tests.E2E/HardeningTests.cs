using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// Regression tests for ioxide's hardening issues, translated to what each protects on epoll: #93
/// (healthy connections torn down when receive buffers ran short), #94 (faulted handlers leaking
/// connections), #242 (a handler released twice, so teardown closed a number it had given back),
/// #92 (a per-reactor limit reached at accept killing the reactor), and an event batch that cannot
/// hold every ready connection - plus epoxide's own: a peer that keeps a reader's buffer full.
/// </summary>
/// <remarks>
/// Not ported: "incremental recv survives per-conn ring exhaustion (#93)" and "incremental accept
/// whose buffer ring the kernel refuses sheds" - epoxide has no per-connection buffer ring and
/// charges nothing to RLIMIT_MEMLOCK at accept; the one per-accept kernel resource, the descriptor,
/// is AcceptExhaustionTests'.
/// </remarks>
internal static class HardeningTests
{
    public static void Register(Runner runner)
    {
        runner.Test("harness: Start does not return before OnStart has run", () =>
        {
            // A test of the harness, because the harness is what every other test's setup trusts.
            // Reactor.Run opens the listener BEFORE calling OnStart, and readiness is a TCP probe -
            // so Start could return while OnStart was still running.
            //
            // The delay is what makes this deterministic: without the wait, the probe wins every
            // time and the flag is still false when Start returns.
            bool ranToCompletion = false;

            TestServer.Start(
                static (_, conn) => { conn.DecRef(); return Task.CompletedTask; },
                _ =>
                {
                    Thread.Sleep(200);
                    ranToCompletion = true;
                });

            Assert.True(ranToCompletion,
                "Start returned while OnStart was still running - everything a test configures there is a race");
        });

        runner.Test("harness: a refusal thrown from OnStart reaches the caller", () =>
        {
            // The other half. A "this configuration is refused" test asserts on an exception from
            // Start, and that exception is raised on the reactor thread inside OnStart.
            Assert.Throws<Exception>(
                () => TestServer.Start(
                    static (_, conn) => { conn.DecRef(); return Task.CompletedTask; },
                    _ =>
                    {
                        // Delayed on purpose. Thrown immediately it beats the probe on any machine
                        // fast enough to notice - proving the timing rather than the behaviour.
                        Thread.Sleep(200);
                        throw new InvalidOperationException("refused-on-purpose");
                    }),
                "refused-on-purpose");
        });

        runner.Test("core: a reader holding its recv buffers while the peer floods stalls and resumes (#93)", () =>
        {
            // ioxide's "shared recv survives buffer-group exhaustion": a held buffer starved the
            // kernel's group and the connection was torn down. epoxide's pool grows instead, and only
            // a reader that asks receives - so while the reader holds its first buffer the flood stays
            // in the socket, takes no buffer of the pool, and arrives whole once the reader reads again.
            const int totalBytes = 24 * 1024;
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, _) = TestServer.StartConfigured(
                HoldFirstThenDrain(release, totalBytes),
                new ServerConfig
                {
                    RecvBufferSize = 1024,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            DriveExhaustion(port, totalBytes, release, reactor);
        });

        runner.Test("core: a burst on more connections than one epoll_wait returns still hands every peer its own bytes", () =>
        {
            // ioxide's "an incremental recv ended by a full completion queue still hands over the peer's
            // bytes": more completions in one enter than the queue holds. On epoll the same burst is more
            // ready connections than MaxEvents, so one wait returns a few and the rest wait for the next -
            // edge-triggered, so an edge that a batch left out must still be reported, and each
            // connection's bytes must still reach its own handler.
            //
            // MaxEvents 4 against 24 connections. Each round sends one message on every connection from
            // the reactor thread, so all 24 are waiting before its next epoll_wait.
            const int Connections = 24;
            const int Rounds = 8;

            var serverFds = new List<int>();
            (int port, Reactor reactor, _) = TestServer.StartConfigured(EchoRecordingFd(serverFds),
                new ServerConfig
                {
                    MaxEvents = 4,
                    RecvBufferSize = 1024,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 64, RecvQueueEntries = 64,
                    },
                });

            var clients = new Socket[Connections];
            try
            {
                // One at a time, so nothing is batched yet: the control, echoed before any burst.
                for (int i = 0; i < Connections; i++)
                {
                    clients[i] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                    {
                        NoDelay = true,
                        ReceiveTimeout = 5_000,
                    };
                    clients[i].Connect(IPAddress.Loopback, port);
                    byte[] hello = Message(i, 0);
                    clients[i].Send(hello);
                    AssertEchoed(clients[i], hello, $"before the rounds, connection {i}");
                }

                int[] fds;
                lock (serverFds)
                {
                    fds = [.. serverFds];
                }
                Assert.Equal(Connections, fds.Length);

                for (int round = 1; round <= Rounds; round++)
                {
                    var sent = new byte[Connections][];
                    for (int i = 0; i < Connections; i++)
                    {
                        sent[i] = Message(i, round);
                    }

                    bool allWaiting = false;
                    using var ran = new ManualResetEventSlim();
                    reactor.ScheduleOnReactor(_ =>
                    {
                        try
                        {
                            for (int i = 0; i < Connections; i++)
                            {
                                clients[i].Send(sent[i]);
                            }

                            // Loopback delivers inside Send, unless a loaded box defers it to ksoftirqd.
                            long deadline = Environment.TickCount64 + 2_000;
                            while (!(allWaiting = AllWaiting(fds, MessageBytes)) && Environment.TickCount64 < deadline)
                            {
                                Thread.SpinWait(64);
                            }
                        }
                        finally
                        {
                            ran.Set();
                        }
                    }, null);

                    Assert.True(ran.Wait(10_000), $"round {round}: the reactor never ran the sends");
                    Assert.True(allWaiting,
                        $"round {round}: the messages were never all waiting at once, so no epoll_wait had more ready than it could return and nothing was tested");

                    for (int i = 0; i < Connections; i++)
                    {
                        AssertEchoed(clients[i], sent[i], $"round {round}, connection {i}");
                    }
                }
            }
            finally
            {
                foreach (Socket? client in clients)
                {
                    client?.Dispose();
                }
            }
        });

        runner.Test("core: a peer that keeps a reader's buffer full cannot hold the reactor: another connection on it is still answered", () =>
        {
            // epoxide's own: a reader on its reactor receives itself while the socket has data, and a
            // full buffer says there may be more. A peer sending faster than the handler consumes
            // keeps every recv full, so without a budget the handler would never give the loop back -
            // and every other connection on the reactor, and its own parked flush, would wait for good.
            (int port, _, _) = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    while (true)
                    {
                        RecvSnapshot snap = await conn.ReadAsync();
                        bool ping = false;
                        while (conn.TryGetItem(snap, out SpscRecvRing.Item item))
                        {
                            if (item.HasBuffer)
                            {
                                ping |= item.Len == 1;
                                conn.ReturnBuffer(in item);
                            }
                        }
                        if (snap.IsClosed)
                        {
                            return;
                        }
                        if (ping)
                        {
                            conn.Write("."u8);
                            await conn.FlushAsync();
                        }
                        conn.ResetRead();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, new ServerConfig { RecvBufferSize = 4096, Tcp = new TcpOptions { ReadTimeoutMs = 0 } });

            using var pinger = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
                ReceiveTimeout = 2_000,
            };
            pinger.Connect(IPAddress.Loopback, port);
            var one = new byte[1];
            pinger.Send("p"u8);
            Assert.Equal(1, pinger.Receive(one));   // its handler is parked on the reactor now

            int flooding = 1;
            var flood = new Thread(() =>
            {
                try
                {
                    using var flooder = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { SendTimeout = 2_000 };
                    flooder.Connect(IPAddress.Loopback, port);
                    var blob = new byte[256 * 1024];
                    while (Volatile.Read(ref flooding) == 1)
                    {
                        flooder.Send(blob);
                    }
                }
                catch (SocketException)
                {
                    // The server stopped reading: the assertions below say why.
                }
            }) { IsBackground = true, Name = "flooder" };
            flood.Start();
            Thread.Sleep(200);

            const int Pings = 20;
            int answered = 0, timedOut = 0;
            for (int i = 0; i < Pings && timedOut < 2; i++)
            {
                try
                {
                    pinger.Send("p"u8);
                    answered += pinger.Receive(one);
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
                {
                    timedOut++;
                }
                Thread.Sleep(10);
            }

            Volatile.Write(ref flooding, 0);
            flood.Join(5_000);
            Assert.True(answered == Pings, $"{answered} of {Pings} pings answered while another connection flooded the reactor ({timedOut} waited 2 s for nothing)");
        });

        runner.Test("core: faulted handler releases the connection (#94)", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(
                async (_, _) =>
                {
                    await Task.Yield();   // to the reactor's own context, not the thread pool
                    throw new InvalidOperationException("boom (test)");
                },
                new ServerConfig
                {
                    RecvBufferSize = 1024,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
                    },
                });

            // Stable() already waits out WaitForListen's probe connection recycling.
            int before = FdCount.Stable();

            for (int i = 0; i < 10; i++)
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                c.GetStream().Write("x"u8.ToArray());
                Thread.Sleep(20);
            }   // dispose closes the client; the server must observe EOF and recycle

            int leaked = FdCount.Stable() - before;
            Assert.True(leaked <= 3, $"{leaked} fds leaked by 10 faulted handlers (CLOSE_WAIT sockets)");
        });

        runner.Test("core: a handler that lets go and then throws is released once, so teardown closes no number it gave back (#242)", () =>
        {
            // try { throw } finally { DecRef }: released by the handler and again by the fault path, the
            // connection would be recycled under the reactor's ref, and its table slot outlive it.
            int[] closed = NumbersClosedUnderTheirNextOwner(throwAfterLettingGo: true);
            Assert.True(closed.Length == 0,
                $"the server's teardown closed {string.Join(", ", closed)}, numbers its connections had already given back");
        });

        runner.Test("core: control: a handler that only lets go leaves a number it gave back alone at teardown", () =>
        {
            int[] closed = NumbersClosedUnderTheirNextOwner(throwAfterLettingGo: false);
            Assert.True(closed.Length == 0, $"the server's teardown closed {string.Join(", ", closed)}");
        });

        runner.Test("core: connections past PoolMax are all accepted and served, and the pool stays bounded (#92)", () =>
        {
            // ioxide's #92: an accept past a per-reactor cap (incremental mode's buffer-group ids) threw
            // and ended the reactor. epoxide's only per-reactor bound at accept is PoolMax, which caps
            // the objects kept for reuse - not the connections: twice as many live ones must all be
            // served, and once they go the pool keeps no more than PoolMax of them.
            const int PoolMax = 4;
            (int port, Reactor reactor, _) = TestServer.StartConfigured(Handlers.Raw,
                new ServerConfig
                {
                    RecvBufferSize = 1024,
                    Tcp = new TcpOptions
                    {
                        WriteSlabSize = 4096, PoolMax = PoolMax, RecvQueueEntries = 64,
                    },
                });

            var held = new List<TcpClient>();
            try
            {
                for (int i = 0; i < 2 * PoolMax; i++)
                {
                    held.Add(ConnectServing(port, TimeSpan.FromSeconds(10)));
                }

                // Every one is still served while all of them are live.
                foreach (TcpClient c in held)
                {
                    GetOk(c);
                }
            }
            finally
            {
                foreach (TcpClient c in held)
                {
                    c.Dispose();
                }
            }

            // The reactor recycles each as it sees its peer go: its own event, not a fixed interval.
            Assert.True(SpinWait.SpinUntil(() => Internals.LiveConnections(reactor) == 0, 10_000),
                $"{Internals.LiveConnections(reactor)} connections were never recycled after their peers left");
            int pooled = Internals.Pooled(reactor);
            Assert.True(pooled is > 0 and <= PoolMax, $"the pool kept {pooled} connections against a PoolMax of {PoolMax}");

            using TcpClient fresh = ConnectServing(port, TimeSpan.FromSeconds(10));
        });
    }

    /// <summary>
    /// Connect and keep trying until the server answers, up to a deadline. Capacity in these tests
    /// frees on the reactor's own schedule (a recycle, a sweep), so waiting for the observable
    /// outcome is the only synchronization that holds on a slow machine.
    /// </summary>
    private static TcpClient ConnectServing(int port, TimeSpan timeout)
    {
        long deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        Exception? last = null;

        while (Environment.TickCount64 < deadline)
        {
            var candidate = new TcpClient();
            try
            {
                candidate.Connect("127.0.0.1", port);
                candidate.ReceiveTimeout = 1000;
                GetOk(candidate);
                candidate.ReceiveTimeout = 4000;
                return candidate;
            }
            catch (Exception e)
            {
                last = e;
                candidate.Dispose();
                Thread.Sleep(50);
            }
        }

        throw new Exception($"no connection served within {timeout.TotalSeconds}s: {last?.Message}");
    }

    private static void GetOk(TcpClient c)
    {
        NetworkStream s = c.GetStream();
        s.Write(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: t\r\n\r\n"));
        byte[] buf = new byte[256];
        int n = s.Read(buf, 0, buf.Length);
        Assert.True(n > 0 && Encoding.ASCII.GetString(buf, 0, n).Contains("200"),
            "keep-alive connection stopped responding");
    }

    private const int MessageBytes = 32;

    private const ulong Fionread = 0x541B;

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request, out int value);

    [DllImport("libc", SetLastError = true)]
    private static extern int fcntl(int fd, int command);

    [DllImport("libc", SetLastError = true)]
    private static extern int dup2(int from, int to);

    [DllImport("libc", SetLastError = true, EntryPoint = "open")]
    private static extern int OpenFile(string path, int flags);

    private const int FGetFd = 1;

    private static bool IsOpen(int fd) => fcntl(fd, FGetFd) != -1;

    /// <summary>
    /// Serve one connection with a handler that lets go (and then throws, or not), wait for the server
    /// to close every connection it handled, give those numbers to someone else - /dev/null, dup2'd onto
    /// them - and stop the server. Returns the numbers its teardown closed under their new owner.
    /// </summary>
    private static int[] NumbersClosedUnderTheirNextOwner(bool throwAfterLettingGo)
    {
        // Opened before any connection, so its number cannot be one of theirs.
        int devNull = OpenFile("/dev/null", 0);

        // WaitForListen's probe connection runs the handler too, so every number it is given counts.
        var handled = new System.Collections.Concurrent.ConcurrentQueue<int>();
        int port = TestServer.Start(async (_, connection) =>
        {
            handled.Enqueue(connection.ClientFd);
            try
            {
                await Task.CompletedTask;
                if (throwAfterLettingGo)
                {
                    throw new InvalidOperationException("thrown after the handler let go (test)");
                }
            }
            finally
            {
                connection.DecRef();
            }
        });

        using (var client = new TcpClient())
        {
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            Assert.True(client.Client.Receive(new byte[1]) == 0, "the handler never let go");   // its FIN
        }

        int[] numbers = [.. handled.Distinct()];
        Assert.True(SpinWait.SpinUntil(() => numbers.All(n => !IsOpen(n)), 5_000),
            $"the server never closed {string.Join(", ", numbers.Where(IsOpen))}");

        foreach (int number in numbers)
        {
            Assert.True(dup2(devNull, number) == number, $"dup2 onto {number} failed");
        }
        Native.close(devNull);

        TestServer.StopAll();   // the teardown under test

        int[] closed = [.. numbers.Where(n => !IsOpen(n))];
        foreach (int number in numbers.Except(closed))
        {
            Native.close(number);
        }
        return closed;
    }

    // Unique per connection and round, so a stale echo names the message it came from.
    private static byte[] Message(int connection, int round)
        => Encoding.ASCII.GetBytes($"connection {connection:D2}, round {round:D2}|".PadRight(MessageBytes, '.'));

    // Every server socket holds a whole message the reactor has not received yet.
    private static bool AllWaiting(int[] fds, int bytes)
    {
        foreach (int fd in fds)
        {
            if (ioctl(fd, Fionread, out int waiting) != 0 || waiting < bytes)
            {
                return false;
            }
        }
        return true;
    }

    private static void AssertEchoed(Socket client, byte[] sent, string when)
    {
        byte[] echoed = new byte[sent.Length];
        for (int got = 0; got < echoed.Length;)
        {
            int n = client.Receive(echoed, got, echoed.Length - got, SocketFlags.None);
            if (n == 0)
            {
                throw new IOException($"{when}: EOF after {got} of {echoed.Length} echoed bytes");
            }
            got += n;
        }

        Assert.True(echoed.AsSpan().SequenceEqual(sent),
            $"{when}: echoed \"{Encoding.ASCII.GetString(echoed)}\" for \"{Encoding.ASCII.GetString(sent)}\"");
    }

    // Echoes each slice and hands its buffer straight back, as a handler that copies out does. Records
    // the server fd of every connection that sent something, which leaves out the readiness probe.
    private static Func<Reactor, TcpConnection, Task> EchoRecordingFd(List<int> fds) => async (_, conn) =>
    {
        try
        {
            bool recorded = false;
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        conn.Write(item.AsSpan());
                        conn.ReturnBuffer(in item);
                        if (!recorded)
                        {
                            recorded = true;
                            lock (fds)
                            {
                                fds.Add(conn.ClientFd);
                            }
                        }
                    }
                }
                await conn.FlushAsync();

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
    };

    // Reads once and holds the buffers until released, then drains until totalBytes arrived and
    // answers "done" - the hold-then-recover shape #93's tests share.
    private static Func<Reactor, TcpConnection, Task> HoldFirstThenDrain(TaskCompletionSource release, int totalBytes)
        => async (_, conn) =>
        {
            try
            {
                long got = 0;
                bool held = false;
                while (true)
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    UnmanagedMemoryManager[] buffers = conn.GetSnapshotMemories(snapshot);
                    foreach (UnmanagedMemoryManager m in buffers)
                    {
                        got += m.Memory.Length;
                    }

                    if (!held && buffers.Length > 0)
                    {
                        held = true;
                        await release.Task;   // hold the first buffers while the client floods
                    }
                    conn.ReturnBuffers(buffers);

                    if (got >= totalBytes)
                    {
                        conn.Write("done"u8);
                        await conn.FlushAsync();
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
        };

    private static void DriveExhaustion(int port, int totalBytes, TaskCompletionSource release, Reactor reactor)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 8000;
        NetworkStream stream = client.GetStream();

        byte[] payload = new byte[totalBytes];
        stream.Write(payload, 0, 1024);                    // handler reads this and parks holding it
        Thread.Sleep(150);
        stream.Write(payload, 1024, totalBytes - 1024);    // floods while the reader holds its buffer
        Thread.Sleep(300);

        // Only the held buffer is out: nothing received ahead of a reader that did not ask.
        int rented = Internals.RecvPool(reactor).Rented;
        Assert.True(rented == 1, $"{rented} recv buffers were out while the reader held one and read nothing more");

        release.SetResult();                               // buffers return; reading resumes

        byte[] reply = new byte[4];
        int n = stream.Read(reply, 0, 4);
        Assert.True(n == 4 && Encoding.ASCII.GetString(reply) == "done",
            "connection died while its reader held its buffers (expected it to stall and resume)");
    }
}
