using System.Net;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// A connection whose own ring is dry once its handler has gone, whichever came first. Nothing will read what fills
/// the ring, so no buffer comes back, and with its recv parked on -ENOBUFS there is no completion for the sweep's
/// shutdown to end, and no recv to see the peer's FIN.
/// </summary>
internal static class IncrementalDryRingTests
{
    // Many read timeouts at the 300 ms below: what "the sweep has certainly run" costs.
    private const int SweepGraceMs = 4_000;
    private const int Cap = 8;

    public static void Register(Runner runner)
    {
        bool unsupported = !TestServer.KernelAtLeast(6, 12);

        runner.Test("incremental: a connection whose ring ran dry after its handler let go is closed by the read timeout", () =>
        {
            Assert.True(ClosedAfterItsClientLeft(sent: 64 * 1024, slots: 2, bufferBytes: 1024),
                "its descriptor is still open, many read timeouts after the client left");
        }, skip: unsupported);

        runner.Test("incremental: a connection whose ring ran dry after its handler let go is closed when its client leaves, with no read timeout", () =>
        {
            Assert.True(ClosedAfterItsClientLeft(sent: 64 * 1024, slots: 2, bufferBytes: 1024, readTimeoutMs: 0),
                "its descriptor is still open, long after the client left");
        }, skip: unsupported);

        runner.Test("incremental: a connection whose handler let go holding a dry ring is closed by the read timeout", () =>
        {
            Assert.True(ClosedAfterLettingGoOfADryRing(readTimeoutMs: 300),
                "its descriptor is still open, many read timeouts after the client left");
        }, skip: unsupported);

        runner.Test("incremental: a connection whose handler let go holding a dry ring is closed when its client leaves, with no read timeout", () =>
        {
            Assert.True(ClosedAfterLettingGoOfADryRing(readTimeoutMs: 0, throughAReader: true),
                "its descriptor is still open, long after the client left");
        }, skip: unsupported);

        runner.Test("incremental: control: the same connection with room left in its ring is closed", () =>
        {
            Assert.True(ClosedAfterItsClientLeft(sent: 1024, slots: 16, bufferBytes: 4096),
                "its descriptor is still open, many read timeouts after the client left");
        }, skip: unsupported);

        runner.Test("incremental: uploads a handler refused do not use up MaxConnections", () =>
        {
            Assert.True(NextClientServedAfterUploadsOf(256 * 1024),
                $"the next client was shed, with all {Cap} group ids held by clients long gone");
        }, skip: unsupported);

        runner.Test("incremental: control: uploads that fit the ring leave MaxConnections free", () =>
        {
            Assert.True(NextClientServedAfterUploadsOf(1024),
                $"the next client was shed, with all {Cap} group ids held by clients long gone");
        }, skip: unsupported);
    }

    private static bool ClosedAfterItsClientLeft(int sent, int slots, int bufferBytes, int readTimeoutMs = 300)
    {
        var descriptor = new TaskCompletionSource<(int Fd, string? Link)>(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (_, conn) =>
        {
            try
            {
                if (await IsThisTestsConnection(conn))
                {
                    descriptor.TrySetResult((conn.ClientFd, LinkOf(conn.ClientFd)));
                }
            }
            finally
            {
                conn.DecRef();   // done, with whatever the peer sends next unread
            }
        }, new ServerConfig
        {
            Incremental = new IncrementalOptions { MaxConnections = Cap, RecvSlots = slots, RecvBufferSize = bufferBytes },
            Tcp = new TcpOptions { ReadTimeoutMs = readTimeoutMs, SendTimeoutMs = 300 },
        }).Port;

        using (Socket client = Connect(port))
        {
            client.Send("hi"u8);
            Assert.Equal(0, client.Receive(new byte[16]));   // the FIN of the handler's release
            client.Send(new byte[sent]);
        }

        Assert.True(descriptor.Task.Wait(SweepGraceMs), "the handler never saw the connection");
        (int fd, string? link) = descriptor.Task.Result;
        Assert.True(link is not null, "the descriptor was gone before the test looked");

        // By its link and not its number: the number may be some other socket's by then.
        return Eventually(() => LinkOf(fd) != link);
    }

    // A raw handler taking items and never returning them breaks TryGetItem's contract, and only the read timeout
    // ends that. Through a reader the holding is allowed, and the reactor can ask for what it holds.
    private static bool ClosedAfterLettingGoOfADryRing(int readTimeoutMs, bool throughAReader = false)
    {
        const int Slots = 2;
        const int BufferBytes = 1024;
        var descriptor = new TaskCompletionSource<(int Fd, string? Link, int Held)>(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (reactor, conn) =>
        {
            try
            {
                // Busy for as long as the peer's bytes take to fill the ring, then gone with every one of them unread.
                await new RingTimer(reactor).DelayAsync(400);

                int held = 0;
                if (throughAReader)
                {
                    held = (int)(await new TcpConnectionPipeReader(conn).ReadAsync()).Buffer.Length;
                }
                else
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            held += item.Len;
                        }
                    }
                }

                if (held > 0)
                {
                    descriptor.TrySetResult((conn.ClientFd, LinkOf(conn.ClientFd), held));
                }
            }
            finally
            {
                conn.DecRef();
            }
        }, new ServerConfig
        {
            Incremental = new IncrementalOptions { MaxConnections = Cap, RecvSlots = Slots, RecvBufferSize = BufferBytes },
            Tcp = new TcpOptions { ReadTimeoutMs = readTimeoutMs, SendTimeoutMs = 300 },
        }).Port;

        (int fd, string? link, int held) = (-1, null, 0);
        using (Socket client = Connect(port))
        {
            client.Send(new byte[64 * 1024]);

            Assert.True(descriptor.Task.Wait(SweepGraceMs), "the handler never saw the connection");
            (fd, link, held) = descriptor.Task.Result;
            Assert.True(held >= Slots * BufferBytes, $"the ring was not dry when the handler let go: it held {held} bytes");
            Assert.True(link is not null, "the descriptor was gone before the test looked");
        }

        return Eventually(() => LinkOf(fd) != link);
    }

    private static bool NextClientServedAfterUploadsOf(int upload)
    {
        byte[] refusal = Encoding.ASCII.GetBytes("HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        int handled = 0;

        int port = TestServer.StartConfigured(async (_, conn) =>
        {
            try
            {
                if (await IsThisTestsConnection(conn))
                {
                    Interlocked.Increment(ref handled);
                    conn.Write(refusal);
                    await conn.FlushAsync();
                }
            }
            finally
            {
                conn.DecRef();
            }
        }, new ServerConfig
        {
            Incremental = new IncrementalOptions { MaxConnections = Cap },   // the default 16 x 4 KiB ring
            Tcp = new TcpOptions { ReadTimeoutMs = 300, SendTimeoutMs = 300 },
        }).Port;

        for (int i = 0; i < Cap; i++)
        {
            using Socket client = Connect(port);
            client.Send(new byte[upload]);
            Assert.True(client.Receive(new byte[64]) > 0, "the refusal never came");
        }
        Assert.Equal(Cap, Volatile.Read(ref handled));

        Thread.Sleep(2_000);   // many read timeouts

        using Socket next = Connect(port);
        try
        {
            next.Send("hi"u8);
        }
        catch (SocketException)
        {
            // Already shed: the assertion below says so.
        }

        return Eventually(() => Volatile.Read(ref handled) == Cap + 1);
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
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            ReceiveTimeout = SweepGraceMs,
            SendTimeout = SweepGraceMs,
        };
        socket.Connect(IPAddress.Loopback, port);
        return socket;
    }

    private static string? LinkOf(int fd) => new FileInfo($"/proc/self/fd/{fd}").LinkTarget;

    private static bool Eventually(Func<bool> condition)
    {
        long deadlineMs = Environment.TickCount64 + SweepGraceMs;
        while (Environment.TickCount64 < deadlineMs)
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(10);
        }

        return condition();
    }
}
