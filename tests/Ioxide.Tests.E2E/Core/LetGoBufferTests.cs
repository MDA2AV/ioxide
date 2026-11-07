using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What a connection holds once its handler has let go. Nobody will read it, and its buffers come back only at
/// teardown, which takes a recv completion, which takes a buffer. So it has to give them up, and the read timeout
/// has to end it even with no recv running. On the shared ring that decides whether anyone else can receive.
/// </summary>
internal static class LetGoBufferTests
{
    private const int GraceMs = 4_000;

    private static readonly byte[] Big = new byte[8 * 1024 * 1024];   // far past what a 4 KiB window and the socket buffers hold

    private sealed record LetGo(TcpConnection Conn, int Fd, string? Link);

    // The queue is private, and how many deliveries it holds is how many buffers this connection took.
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_recv")]
    private static extern ref SpscRecvRing RecvOf(TcpConnection conn);

    public static void Register(Runner runner)
    {
        bool noIncremental = !TestServer.KernelAtLeast(6, 12);

        runner.Test("shared ring: connections whose handlers let go, holding every buffer, are closed and a new client is served", () =>
        {
            (bool served, int open, int total) = ThenLeave(sendsEach: 60);
            Assert.True(served, $"the new client was never answered, with {open} of {total} let-go connections still open");
            Assert.Equal(0, open);
        });

        runner.Test("shared ring: control: the same with room left in the ring", () =>
        {
            (bool served, int open, int total) = ThenLeave(sendsEach: 20);
            Assert.True(served, $"the new client was never answered, with {open} of {total} let-go connections still open");
            Assert.Equal(0, open);
        });

        runner.Test("shared ring: a starved recv takes back what let-go connections hold, with no read timeout and their peers still connected", () =>
        {
            const int Slots = 16;
            var letGo = new ConcurrentQueue<LetGo>();
            int port = Start(letGo, new ServerConfig { RecvBufferSize = 4096, RecvSlots = Slots }, readTimeoutMs: 0);

            var peers = new List<Socket>();
            try
            {
                DryTheRing(port, letGo, Slots, peers);

                using Socket next = Connect(port);
                Assert.True(Asked(next), "the new client was never answered: the let-go connections kept every buffer");
            }
            finally
            {
                peers.ForEach(peer => peer.Dispose());
            }
        });

        runner.Test("shared ring: a starved recv takes back what a let-go connection's reader holds", () =>
        {
            const int Slots = 16;
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    var reader = new TcpConnectionPipeReader(conn);
                    while (true)
                    {
                        ReadResult read = await reader.ReadAsync();
                        if (read.Buffer.IsEmpty || read.Buffer.FirstSpan[0] != (byte)'P')
                        {
                            return;   // with what it read still in the reader, neither advanced nor completed
                        }

                        reader.AdvanceTo(read.Buffer.End);
                        conn.Write("pong"u8);
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config(new ServerConfig { RecvBufferSize = 4096, RecvSlots = Slots }, readTimeoutMs: 0)).Port;

            var peers = new List<Socket>();
            try
            {
                for (int i = 0; i < Slots; i++)
                {
                    peers.Add(LetGoPeer(port));   // one send, so one buffer
                }

                using Socket next = Connect(port);
                Assert.True(Asked(next), "the new client was never answered: the readers kept every buffer");
            }
            finally
            {
                peers.ForEach(peer => peer.Dispose());
            }
        });

        runner.Test("shared ring: a read left parked when its handler let go strands nothing it takes later", () =>
        {
            const int Slots = 16;
            var letGo = new ConcurrentQueue<LetGo>();
            int port = Start(letGo, new ServerConfig { RecvBufferSize = 4096, RecvSlots = Slots }, readTimeoutMs: 0);

            var peers = new List<Socket>();
            var parked = new List<Socket>();
            try
            {
                for (int i = 0; i < Slots; i++)
                {
                    Socket socket = Connect(port);
                    socket.Send("W"u8);
                    Assert.Equal(0, socket.Receive(new byte[16]));
                    parked.Add(socket);
                }

                // Starved once, so the reactor asks these connections for what they hold, with their reads parked.
                DryTheRing(port, letGo, Slots, peers);
                using (Socket next = Connect(port))
                {
                    Assert.True(Asked(next), "the new client was never answered: the let-go connections kept every buffer");
                }

                // Those reads take a buffer each, which only their holders know about.
                foreach (Socket socket in parked)
                {
                    socket.Send("x"u8);
                    Thread.Sleep(1);
                }

                parked.ForEach(socket => socket.Dispose());
                parked.Clear();

                using Socket last = Connect(port);
                Assert.True(Asked(last), "the last client was never answered: the parked reads stranded their buffers");
            }
            finally
            {
                peers.ForEach(peer => peer.Dispose());
                parked.ForEach(socket => socket.Dispose());
            }
        });

        runner.Test("tcp: the read timeout closes a let-go connection parked on a ring that others hold", () =>
        {
            var letGo = new ConcurrentQueue<LetGo>();
            int port = Start(letGo, new ServerConfig { RecvBufferSize = 4096, RecvSlots = 256 }, readTimeoutMs: 500);

            using Socket parked = LetGoPeer(port);
            Assert.True(letGo.TryPeek(out LetGo? gone), "the handler never let go");

            var holders = new List<Socket>();
            try
            {
                // Their handlers are parked in a flush with no send timeout, and keep what their peers send.
                for (int i = 0; i < 5; i++)
                {
                    Socket holder = Connect(port, receiveBuffer: 4096);
                    holder.Send("B"u8);
                    holders.Add(holder);
                }
                Thread.Sleep(200);

                for (int round = 0; round < 60; round++)
                {
                    foreach (Socket holder in holders)
                    {
                        holder.Send("x"u8);
                    }

                    Thread.Sleep(1);   // apart, so each is a recv of its own
                }

                parked.Send("x"u8);   // on the dry ring: its recv parks, with nothing of its own to give back
                Assert.True(Eventually(() => LinkOf(gone!.Fd) != gone.Link), "its descriptor is still open, many read timeouts later");
            }
            finally
            {
                holders.ForEach(holder => holder.Dispose());
            }
        });

        runner.Test("incremental: a client that keeps uploading after its handler let go is read to its close, not reset", () =>
        {
            var letGo = new ConcurrentQueue<LetGo>();
            int port = Start(letGo, new ServerConfig { Incremental = new IncrementalOptions { MaxConnections = 8 } }, readTimeoutMs: 30_000);

            using (Socket client = LetGoPeer(port))
            {
                client.SendTimeout = GraceMs;

                byte[] chunk = new byte[64 * 1024];
                for (int i = 0; i < 256; i++)
                {
                    client.Send(chunk);   // 16 MiB: far past the ring, the queue and the socket buffers
                }
            }

            Assert.True(letGo.TryPeek(out LetGo? gone), "the handler never let go");
            Assert.True(Eventually(() => LinkOf(gone!.Fd) != gone.Link), "its descriptor is still open after its client left");
        }, skip: noIncremental);
    }

    private static (bool Served, int Open, int Total) ThenLeave(int sendsEach)
    {
        var letGo = new ConcurrentQueue<LetGo>();
        int port = Start(letGo, new ServerConfig { RecvBufferSize = 4096, RecvSlots = 256 }, readTimeoutMs: 300);

        var peers = new List<Socket>();
        for (int i = 0; i < 5; i++)
        {
            peers.Add(LetGoPeer(port));
        }

        for (int round = 0; round < sendsEach; round++)
        {
            foreach (Socket peer in peers)
            {
                peer.Send("x"u8);
            }

            Thread.Sleep(1);   // apart, so each is a recv of its own
        }

        peers.ForEach(peer => peer.Dispose());

        // Many read timeouts, with every peer gone.
        Thread.Sleep(2_000);

        using Socket next = Connect(port);
        bool served = Asked(next);
        Eventually(() => letGo.All(gone => LinkOf(gone.Fd) != gone.Link));
        return (served, letGo.Count(gone => LinkOf(gone.Fd) == gone.Link), letGo.Count);
    }

    private static int Start(ConcurrentQueue<LetGo> letGo, ServerConfig config, int readTimeoutMs)
        => TestServer.StartConfigured((_, conn) => Handle(conn, letGo), Config(config, readTimeoutMs)).Port;

    private static ServerConfig Config(ServerConfig config, int readTimeoutMs) => config with
    {
        Tcp = new TcpOptions { RecvQueueEntries = 64, ReadTimeoutMs = readTimeoutMs, SendTimeoutMs = 0 },
    };

    // 'R' lets go, 'W' lets go with a read left parked, 'P' answers, and 'B' parks in a flush its peer won't drain.
    private static async Task Handle(TcpConnection conn, ConcurrentQueue<LetGo> letGo)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                int marker = -1;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        marker = item.AsSpan()[0];
                        conn.ReturnBuffer(in item);
                    }
                }

                switch (marker)
                {
                    case 'R':
                        letGo.Enqueue(new LetGo(conn, conn.ClientFd, LinkOf(conn.ClientFd)));
                        return;

                    case 'W':
                        _ = new TcpConnectionPipeReader(conn).ReadAsync();
                        return;

                    case 'B':
                        conn.Write(Big);
                        await conn.FlushAsync();
                        break;

                    case 'P':
                        conn.Write("pong"u8);
                        await conn.FlushAsync();
                        break;
                }

                if (snapshot.IsClosed)
                {
                    return;
                }
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Connected, with its handler gone: the FIN of the release has arrived.
    private static Socket LetGoPeer(int port)
    {
        Socket peer = Connect(port);
        peer.Send("R"u8);
        Assert.Equal(0, peer.Receive(new byte[16]));
        return peer;
    }

    // A buffer each, each seen to arrive, so the ring ends exactly dry with no recv having noticed.
    private static void DryTheRing(int port, ConcurrentQueue<LetGo> letGo, int slots, List<Socket> peers)
    {
        for (int i = 0; i < 2; i++)
        {
            peers.Add(LetGoPeer(port));
        }

        int sent = 0;
        for (int round = 0; round < slots / peers.Count; round++)
        {
            foreach (Socket peer in peers)
            {
                peer.Send("x"u8);
                sent++;
                Assert.True(Eventually(() => Queued(letGo) == sent), $"message {sent} never reached its queue");
            }
        }
    }

    private static int Queued(ConcurrentQueue<LetGo> letGo)
    {
        int queued = 0;
        foreach (LetGo gone in letGo)
        {
            SpscRecvRing recv = RecvOf(gone.Conn);
            queued += recv.CountUntil(recv.SnapshotTail());
        }

        return queued;
    }

    private static bool Asked(Socket socket)
    {
        socket.Send("P"u8);

        var answer = new byte[4];
        try
        {
            for (int got = 0; got < answer.Length;)
            {
                int n = socket.Receive(answer, got, answer.Length - got, SocketFlags.None);
                if (n == 0)
                {
                    return false;
                }

                got += n;
            }
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
        {
            return false;
        }

        return Encoding.ASCII.GetString(answer) == "pong";
    }

    private static Socket Connect(int port, int? receiveBuffer = null)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
            ReceiveTimeout = GraceMs,
        };
        if (receiveBuffer is int bytes)
        {
            socket.ReceiveBufferSize = bytes;   // before the connect, so it is the window advertised
        }

        socket.Connect(IPAddress.Loopback, port);
        return socket;
    }

    private static string? LinkOf(int fd) => new FileInfo($"/proc/self/fd/{fd}").LinkTarget;

    private static bool Eventually(Func<bool> condition)
    {
        long deadlineMs = Environment.TickCount64 + GraceMs;
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
