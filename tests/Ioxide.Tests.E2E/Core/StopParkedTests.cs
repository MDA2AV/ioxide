using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What a stop does to what is waiting on the reactor. Teardown closes a live connection's socket and leaves the
/// object, without marking it closed, and nothing drains the handoff queues afterwards.
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
