using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
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

        runner.Test("stop: a send the last pass left queued goes to its own client, not to the socket that takes its number", () =>
        {
            using var taker = new NumberTaker();
            var resumed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                // On the reactor thread the send is queued in this pass, and the stop ends the loop before it is submitted.
                int fd = conn.ClientFd;
                conn.Write(Queued);
                ValueTask flush = conn.FlushAsync();
                r.Stop();
                await flush;

                // Resumed by the stop with the socket closed: another socket takes the number, and the ring is entered.
                taker.Take(fd);
                EnterTheRing(r);
                resumed.TrySetResult();
                conn.DecRef();
            }, new ServerConfig { Tcp = new TcpOptions(), OpSlots = 4 });

            using Socket client = Connect(port);
            client.Send("hi"u8);

            // The handler stops the reactor itself, in the pass that queued its send.
            bool stopped = thread.Join(TimeSpan.FromSeconds(10));
            if (!stopped)
            {
                StopAndJoin(reactor, thread);
            }
            Assert.True(stopped, "the handler never stopped the reactor");
            Assert.True(resumed.Task.Wait(ReturnsWithinMs), "the handler never resumed from its flush");

            taker.AssertNothingReceived();
            byte[] received = ReceiveAll(client);
            Assert.True(received.AsSpan().SequenceEqual(Queued), $"the client received '{Encoding.ASCII.GetString(received)}'");
        });

        runner.Test("stop: a send a handler woken by the stop queues on another connection goes to that client, not to the socket that takes its number", () =>
        {
            using var taker = new NumberTaker();
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var resumed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var conns = new List<TcpConnection>();   // reactor thread only

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                conns.Add(conn);
                if (conns.Count == 2)
                {
                    parked.TrySetResult();
                }

                await conn.ReadAsync();   // until the stop closes it

                // The stop goes through its connections by descriptor: the lower one wakes with the other still open.
                TcpConnection other = conns[0] == conn ? conns[1] : conns[0];
                if (conn.ClientFd < other.ClientFd)
                {
                    int fd = other.ClientFd;
                    other.Write(Queued);
                    await other.FlushAsync();

                    taker.Take(fd);
                    EnterTheRing(r);
                    resumed.TrySetResult();
                }

                conn.DecRef();
            }, new ServerConfig { Tcp = new TcpOptions(), OpSlots = 4 });

            using Socket first = Connect(port);
            first.Send("hi"u8);
            using Socket second = Connect(port);
            second.Send("hi"u8);
            Assert.True(parked.Task.Wait(5_000), "the handlers never parked");

            StopAndJoin(reactor, thread);
            Assert.True(resumed.Task.Wait(ReturnsWithinMs), "the woken handler never resumed from its flush on the other connection");

            taker.AssertNothingReceived();
            byte[] received = [.. ReceiveAll(first), .. ReceiveAll(second)];
            Assert.True(received.AsSpan().SequenceEqual(Queued), $"the clients received '{Encoding.ASCII.GetString(received)}'");
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

    private static readonly byte[] Queued = "QUEUED-FOR-THE-CLOSED-SOCKET"u8.ToArray();

    // With OpSlots = 4 the fifth wait grows the op table, which first submits whatever is queued.
    private static void EnterTheRing(Reactor reactor)
    {
        for (int i = 0; i < 8; i++)
        {
            _ = new RingTimer(reactor).DelayAsync(600_000);
        }
    }

    // Until the server's side is gone, which the ring's teardown ends.
    private static byte[] ReceiveAll(Socket socket)
    {
        socket.ReceiveTimeout = 3_000;
        var received = new List<byte>();
        byte[] buffer = new byte[256];
        try
        {
            int n;
            while ((n = socket.Receive(buffer)) > 0)
            {
                received.AddRange(buffer.AsSpan(0, n));
            }
        }
        catch (SocketException)
        {
            // a reset or the timeout: what arrived before it is the answer
        }

        return [.. received];
    }

    // A socket put on a descriptor number the stop freed, as the next accept or open anywhere in the process would
    // be: what the kernel then sends on that number reaches this socket's peer.
    private sealed class NumberTaker : IDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly Socket _peer = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly Socket _accepted;
        private int _number = -1;
        private int _dup2Result;

        public NumberTaker()
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(1);
            _peer.Connect(_listener.LocalEndPoint!);
            _accepted = _listener.Accept();
        }

        // From the handler, on the reactor thread, so it throws nothing.
        public void Take(int number)
        {
            _number = number;
            _dup2Result = dup2((int)_accepted.SafeHandle.DangerousGetHandle(), number);
        }

        public void AssertNothingReceived()
        {
            Assert.True(_dup2Result == _number, $"dup2 onto {_number} returned {_dup2Result}");

            bool readable = _peer.Poll(200_000, SelectMode.SelectRead);
            int bytes = readable ? _peer.Available : 0;
            Assert.True(bytes == 0, $"the socket that took number {_number} received {bytes} bytes queued for the one the stop closed");
        }

        public void Dispose()
        {
            if (_number >= 0 && _dup2Result == _number)
            {
                close(_number);
            }

            _accepted.Dispose();
            _peer.Dispose();
            _listener.Dispose();
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int dup2(int oldFd, int newFd);

        [DllImport("libc")]
        private static extern int close(int fd);
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
