using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Clients that do whatever a client can, to handlers that do whatever a handler can, over connections moved from reactor
/// to reactor all the time. Afterwards every reactor serves, holds no connection, and has every buffer it began with.
/// </summary>
internal static class MoveChaosTests
{
    private const int RunMs = 4_000;
    private const int Clients = 16;

    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            runner.Test($"move chaos: clients and handlers that end in every way, while moved all the time, leave the reactors whole ({mode})", () =>
            {
                int seed = Environment.TickCount;
                ServerConfig tight = Tight(config());
                (int port, Reactor[] reactors, Thread[] threads) = TestServer.StartFleet(3, (_, conn) => Handle(conn), tight);
                long deadline = Environment.TickCount64 + RunMs;
                using (var shuffle = new Moves.Shuffle(reactors))
                {
                    Thread[] clients = Enumerable.Range(0, Clients).Select(i => new Thread(() =>
                    {
                        var random = new Random(seed + i);
                        while (Environment.TickCount64 < deadline)
                        {
                            Misbehave(port, random);
                        }
                    }) { IsBackground = true }).ToArray();
                    foreach (Thread client in clients)
                    {
                        client.Start();
                    }
                    foreach (Thread client in clients)
                    {
                        Assert.True(client.Join(RunMs + 30_000), $"a client hung (seed {seed})");
                    }
                    Assert.True(shuffle.Made > 10, $"only {shuffle.Made} moves were made (seed {seed})");
                }

                foreach (Reactor reactor in reactors)
                {
                    Assert.True(SpinWait.SpinUntil(() => Moves.LiveOn(reactor) == 0, 15_000),
                        $"reactor {reactor.ShardIndex} still holds {Moves.LiveOn(reactor)} connections (seed {seed})");
                }
                if (tight.Incremental is { } incremental)
                {
                    foreach (Reactor reactor in reactors)
                    {
                        Assert.True(Moves.RoomOn(reactor) == incremental.MaxConnections,
                            $"reactor {reactor.ShardIndex} has room for {Moves.RoomOn(reactor)} connections, of {incremental.MaxConnections} (seed {seed})");
                    }
                }
                for (int i = 0; i < 6 * tight.RecvSlots; i++)
                {
                    Assert.True(Answers(port), $"no answer after the chaos (seed {seed})");
                }
                foreach (Reactor reactor in reactors)
                {
                    reactor.Stop();
                }
                foreach (Thread thread in threads)
                {
                    Assert.True(thread.Join(5_000), $"a stop never ended (seed {seed})");
                }
            }, skip);
        }
    }

    // What the first byte asks for: an echo that goes on, a let-go, a fault, an answer and no more reading.
    private static async Task Handle(TcpConnection conn)
    {
        bool released = false;
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                byte first = 0;
                bool any = false;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        first = any ? first : item.AsSpan()[0];
                        conn.Write(item.AsSpan());
                        conn.ReturnBuffer(in item);
                        any = true;
                    }
                }
                if (any)
                {
                    switch (first)
                    {
                        case (byte)'f':
                            throw new InvalidOperationException("a handler's own fault");
                        case (byte)'l':
                            return;
                        case (byte)'p':
                            await Task.Yield();   // and off the reactor
                            await Task.Delay(1).ConfigureAwait(false);
                            break;
                        case (byte)'w':
                            _ = conn.FlushAsync();   // not waited for
                            conn.DecRef();
                            released = true;
                            return;
                    }
                    await conn.FlushAsync();
                }
                if (snapshot.IsClosed)
                {
                    return;
                }
            }
        }
        finally
        {
            if (!released)
            {
                conn.DecRef();
            }
        }
    }

    private static void Misbehave(int port, Random random)
    {
        try
        {
            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, ReceiveTimeout = 10_000, SendTimeout = 10_000 };
            client.Connect(IPAddress.Loopback, port);
            byte[] message = new byte[random.Next(1, 4_000)];
            message.AsSpan().Fill((byte)'e');
            message[0] = (byte)"eeeelfpw"[random.Next(8)];
            switch (random.Next(7))
            {
                case 0:   // nothing at all
                    break;
                case 1:   // an exchange, or two
                    for (int i = random.Next(1, 3); i > 0; i--)
                    {
                        client.Send(message);
                        for (int got = 0, n; got < message.Length; got += n)
                        {
                            if ((n = client.Receive(new byte[4_096])) == 0)
                            {
                                return;
                            }
                        }
                    }
                    break;
                case 2:   // a reset in the middle of it
                    client.Send(message);
                    client.LingerState = new LingerOption(true, 0);
                    break;
                case 3:   // its own end first, then what is left
                    client.Send(message);
                    client.Shutdown(SocketShutdown.Send);
                    while (client.Receive(new byte[4_096]) > 0)
                    {
                    }
                    break;
                case 4:   // a byte at a time
                    foreach (byte b in message.AsSpan(0, Math.Min(message.Length, 40)))
                    {
                        client.Send([b]);
                    }
                    break;
                case 5:   // much, and reads none of it
                    client.ReceiveBufferSize = 4_096;
                    client.Blocking = false;
                    for (int i = 0; i < 30; i++)
                    {
                        client.Send(message);
                    }
                    break;
                default:   // and waits about
                    client.Send(message);
                    Thread.Sleep(random.Next(5));
                    break;
            }
        }
        catch (SocketException)
        {
            // the server's end came first, or there was no room
        }
    }

    private static bool Answers(int port)
    {
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, ReceiveTimeout = 10_000 };
        client.Connect(IPAddress.Loopback, port);
        client.Send("e"u8);
        return client.Receive(new byte[16]) == 1;
    }

    // Few buffers, so that one lost is missed. A reset that is never noticed is the read timeout's to end, moves or not (#403).
    private static ServerConfig Tight(ServerConfig config) => config with
    {
        RecvSlots = 16,
        RecvBufferSize = 512,
        Tcp = config.Tcp! with { ReadTimeoutMs = 2_000, SendTimeoutMs = 2_000 },
        Incremental = config.Incremental is { } incremental ? incremental with { MaxConnections = 32, RecvSlots = 4, RecvBufferSize = 256 } : null,
    };
}
