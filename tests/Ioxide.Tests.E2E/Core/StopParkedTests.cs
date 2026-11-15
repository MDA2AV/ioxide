using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What a stop does to what is waiting on the reactor, and to what is called on it after.
/// </summary>
internal static class StopParkedTests
{
    // Generous against a healthy return, which takes no time at all: the assertion is that it returns.
    private const int ReturnsWithinMs = 3_000;

    public static void Register(Runner runner)
    {
        runner.Test("stop: a handler parked in a read gets to run its finally", () =>
        {
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                try
                {
                    parked.TrySetResult();
                    await conn.ReadAsync();
                }
                finally
                {
                    finished.TrySetResult();
                    conn.DecRef();
                }
            }, new ServerConfig { Tcp = new TcpOptions() });

            using Socket client = Connect(port);
            client.Send("hi"u8);
            Assert.True(parked.Task.Wait(5_000), "the handler never parked");

            StopAndJoin(reactor, thread);
            Assert.True(finished.Task.Wait(ReturnsWithinMs), "the handler is still parked, its finally not run");
        });

        runner.Test("stop: a handler parked in a RingTimer wait gets to run its finally", () =>
        {
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                try
                {
                    parked.TrySetResult();
                    await new RingTimer(r).DelayAsync(600_000);
                }
                finally
                {
                    finished.TrySetResult();
                    conn.DecRef();
                }
            }, new ServerConfig { Tcp = new TcpOptions() });

            using Socket client = Connect(port);
            client.Send("hi"u8);
            Assert.True(parked.Task.Wait(5_000), "the handler never parked");

            StopAndJoin(reactor, thread);
            Assert.True(finished.Task.Wait(ReturnsWithinMs), "the handler is still parked in its wait, its finally not run");
        });

        runner.Test("stop: a handler parked in a flush its client holds up gets to run its finally", () =>
        {
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            byte[] response = new byte[16 << 20];   // more than both sockets' buffers hold

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                try
                {
                    conn.Write(response);
                    ValueTask flush = conn.FlushAsync();
                    parked.TrySetResult();
                    await flush;
                }
                finally
                {
                    finished.TrySetResult();
                    conn.DecRef();
                }
            }, new ServerConfig { Tcp = new TcpOptions() });

            using Socket client = Connect(port);   // never reads
            client.Send("hi"u8);
            Assert.True(parked.Task.Wait(5_000), "the handler never parked");
            Thread.Sleep(200);   // the reactor hands the send to the kernel

            StopAndJoin(reactor, thread);
            Assert.True(finished.Task.Wait(ReturnsWithinMs), "the handler is still parked in its flush, its finally not run");
        });

        foreach (bool incremental in new[] { false, true })
        {
            string mode = incremental ? "incremental" : "shared ring";

            runner.Test($"stop: a connection its handler let go of has its memory freed, one a handler still holds keeps it ({mode})", () =>
            {
                var conns = new System.Collections.Concurrent.ConcurrentDictionary<char, TcpConnection>();
                using var parked = new CountdownEvent(Roles.Length);
                var held = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var heldFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                byte[] response = new byte[16 << 20];   // more than both sockets' buffers hold

                var config = new ServerConfig
                {
                    Incremental = incremental ? new IncrementalOptions { MaxConnections = 16, RecvSlots = 4 } : null,
                    Tcp = new TcpOptions(),
                };

                (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
                {
                    int role = await ReadRole(conn);
                    if (role < 0)
                    {
                        conn.DecRef();
                        return;
                    }

                    conns[(char)role] = conn;
                    try
                    {
                        switch ((char)role)
                        {
                            case 'r':
                                parked.Signal();
                                await conn.ReadAsync();
                                break;
                            case 'f':
                                conn.Write(response);
                                ValueTask flush = conn.FlushAsync();
                                parked.Signal();
                                await flush;
                                break;
                            case 't':
                                parked.Signal();
                                await new RingTimer(r).DelayAsync(600_000);
                                break;
                            case 'l':
                                parked.Signal();   // lets go at once, its client still connected
                                break;
                            case 'h':
                                parked.Signal();
                                await held.Task;   // busy outside ioxide when the stop comes
                                conn.Write("late"u8);
                                await conn.FlushAsync();
                                heldFinished.TrySetResult();
                                break;
                        }
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, config);

                var clients = new List<Socket>();
                try
                {
                    foreach (char role in Roles)
                    {
                        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        if (role == 'f')
                        {
                            client.ReceiveBufferSize = 64 * 1024;   // never reads, and takes little
                        }
                        client.Connect(IPAddress.Loopback, port);
                        client.Send([(byte)role]);
                        clients.Add(client);
                    }

                    Assert.True(parked.Wait(5_000), "the handlers never parked");
                    Thread.Sleep(200);   // the reactor hands the flush's send to the kernel

                    StopAndJoin(reactor, thread);

                    foreach (char role in "rftl")
                    {
                        Assert.True(!HasWriteBuffer(conns[role]), $"the write slab of the '{role}' connection outlived its reactor");
                        if (incremental)
                        {
                            Assert.True(!HasRing(conns[role]), $"the buffer ring of the '{role}' connection outlived its reactor");
                        }
                    }

                    Assert.True(HasWriteBuffer(conns['h']), "the write slab of a connection its handler still holds was freed under it");
                    held.TrySetResult();
                    Assert.True(heldFinished.Task.Wait(ReturnsWithinMs), "the held handler never finished");
                }
                finally
                {
                    held.TrySetResult();
                    foreach (Socket client in clients)
                    {
                        client.Dispose();
                    }
                }
            }, skip: incremental && !TestServer.KernelAtLeast(6, 12));
        }

        runner.Test("stop: a flush from another thread after the reactor stopped returns", () =>
        {
            AfterTheStop((conn, _) =>
            {
                conn.Write("x"u8);
                return conn.FlushAsync().AsTask();
            }, "FlushAsync");
        });

        runner.Test("stop: a read from another thread after the reactor stopped returns", () =>
        {
            AfterTheStop((conn, _) => conn.ReadAsync().AsTask(), "ReadAsync");
        });

        runner.Test("stop: a RingTimer wait from another thread after the reactor stopped returns", () =>
        {
            AfterTheStop((_, reactor) => new RingTimer(reactor).DelayAsync(1).AsTask(), "DelayAsync");
        });

        runner.Test("stop: control: a ReactorSwitch from another thread after the reactor stopped throws", () =>
        {
            Task? switched = null;
            AfterTheStop((_, reactor) => switched = SwitchTo(reactor), "the switch");
            Assert.True(switched!.Exception?.InnerException is ObjectDisposedException,
                $"it ended {switched.Status}: {switched.Exception?.InnerException?.GetType().Name}");
        });
    }

    // A read, a flush its client holds up, a RingTimer wait, a handler that let go, one held outside ioxide.
    private const string Roles = "rftlh";

    // The one byte a test client sends, or -1 for the harness's listen probe, which sends nothing.
    private static async Task<int> ReadRole(TcpConnection conn)
    {
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();

            int role = -1;
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    role = role < 0 ? item.AsSpan()[0] : role;
                    conn.ReturnBuffer(in item);
                }
            }

            if (role >= 0)
            {
                return role;
            }
            if (snapshot.IsClosed)
            {
                return -1;
            }
        }
    }

    private static unsafe bool HasWriteBuffer(TcpConnection connection) => WriteBufferOf(connection) != null;

    private static unsafe bool HasRing(TcpConnection connection) => BufRingOf(connection) != null && BufSlabOf(connection) != null;

    [System.Runtime.CompilerServices.UnsafeAccessor(System.Runtime.CompilerServices.UnsafeAccessorKind.Field, Name = "WriteBuffer")]
    private static extern unsafe ref byte* WriteBufferOf(TcpConnection connection);

    [System.Runtime.CompilerServices.UnsafeAccessor(System.Runtime.CompilerServices.UnsafeAccessorKind.Field, Name = "BufRing")]
    private static extern unsafe ref byte* BufRingOf(TcpConnection connection);

    [System.Runtime.CompilerServices.UnsafeAccessor(System.Runtime.CompilerServices.UnsafeAccessorKind.Field, Name = "BufSlab")]
    private static extern unsafe ref byte* BufSlabOf(TcpConnection connection);

    private static async Task SwitchTo(Reactor reactor) => await new ReactorSwitch(reactor);

    private static void AfterTheStop(Func<TcpConnection, Reactor, Task> call, string what)
    {
        var running = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
        {
            if (await IsThisTestsConnection(conn))
            {
                running.TrySetResult(conn);
                await release.Task;   // waiting on something else, and not on the connection
            }

            conn.DecRef();
        }, new ServerConfig { Tcp = new TcpOptions() });

        using Socket client = Connect(port);
        client.Send("hi"u8);
        Assert.True(running.Task.Wait(5_000), "the handler never ran");

        StopAndJoin(reactor, thread);

        Task returned = Task.Run(() => call(running.Task.Result, reactor));
        try
        {
            Assert.True(((IAsyncResult)returned).AsyncWaitHandle.WaitOne(ReturnsWithinMs),
                $"{what} on a stopped reactor never returned");
        }
        finally
        {
            release.TrySetResult();
        }
    }

    private static void StopAndJoin(Reactor reactor, Thread thread)
    {
        reactor.Stop();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");
    }

    // The harness's listen probe connects and closes without sending anything.
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
                return false;
            }
        }
    }

    private static Socket Connect(int port)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(IPAddress.Loopback, port);
        return socket;
    }
}
