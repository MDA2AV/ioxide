using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>Reactors that share a port, and clients of theirs with the server's side of the connection at hand.</summary>
public sealed class MoveFleet : IDisposable
{
    private readonly BlockingCollection<TcpConnection> _accepted = new();
    private readonly List<Socket> _clients = [];

    public readonly int Port;
    public readonly Reactor[] Reactors;
    public readonly Thread[] Threads;

    /// <summary>What a handler failed with, if one did.</summary>
    public readonly ConcurrentQueue<Exception> Faults = new();

    /// <param name="moves">False for a server as it is by default, without <see cref="TcpOptions.Rebalance"/>, whose connections can't move.</param>
    public MoveFleet(int reactors, Func<TcpConnection, Task> handle, ServerConfig? config = null, Action<int, Reactor>? onStart = null,
        bool moves = true)
    {
        config ??= Shared();
        config = config with { Tcp = moves ? Movable(config.Tcp!) : config.Tcp! with { Rebalance = false } };
        (Port, Reactors, Threads) = TestServer.StartFleet(reactors, async (_, conn) =>
        {
            _accepted.Add(conn);
            try
            {
                await handle(conn);
            }
            catch (Exception e)
            {
                Faults.Enqueue(e);
                throw;
            }
        }, config, onStart);
    }

    public Reactor A => Reactors[0];
    public Reactor B => Reactors[1];

    public static ServerConfig Shared(TcpOptions? tcp = null) => new()
    {
        RecvBufferSize = 4096,
        RecvSlots = 256,
        Udp = null,
        Tcp = Movable(tcp ?? new TcpOptions { WriteSlabSize = 4096, PoolMax = 64 }),
    };

    public static ServerConfig Incremental(int room = 64, int slots = 8, int size = 1024, TcpOptions? tcp = null) => new()
    {
        Udp = null,
        Incremental = new IncrementalOptions { MaxConnections = room, RecvSlots = slots, RecvBufferSize = size },
        Tcp = Movable(tcp ?? new TcpOptions { WriteSlabSize = 4096, PoolMax = 64 }),
    };

    /// <summary>
    /// Connections that can move, which only <see cref="TcpOptions.Rebalance"/> makes them: a test that doesn't ask for its
    /// looks gets them as good as never (every 24 days by the clock), and moves the connections itself.
    /// </summary>
    public static TcpOptions Movable(TcpOptions tcp) => tcp.Rebalance ? tcp : tcp with { Rebalance = true, RebalanceIntervalMs = int.MaxValue };

    /// <summary>Both recv modes, by name; incremental needs Linux 6.12.</summary>
    public static IEnumerable<(string Mode, Func<ServerConfig> Config, bool Skip)> Modes()
    {
        yield return ("shared ring", () => Shared(), false);
        yield return ("ring per connection", () => Incremental(), !TestServer.KernelAtLeast(6, 12));
    }

    /// <summary>A client whose connection is on that reactor (the first, if none is asked for): the kernel picks, so as many tries as it takes.</summary>
    public (Socket Client, TcpConnection Conn) Connect(Reactor? on = null)
    {
        for (int attempt = 0; attempt < 500; attempt++)
        {
            Socket client = Moves.Connect(Port);
            Assert.True(_accepted.TryTake(out TcpConnection? conn, 10_000), "the connection was never accepted");
            if (ReferenceEquals(conn!.Reactor, on ?? A))
            {
                _clients.Add(client);
                return (client, conn);
            }
            client.Dispose();
        }
        throw new Exception("500 connections, and none came to the reactor asked for");
    }

    /// <summary>The next connection accepted, of a client that isn't <see cref="Connect"/>'s.</summary>
    public TcpConnection TakeAccepted()
    {
        Assert.True(_accepted.TryTake(out TcpConnection? conn, 10_000), "no connection was accepted");
        return conn!;
    }

    public void Dispose()
    {
        foreach (Socket client in _clients)
        {
            client.Dispose();
        }
        Assert.True(Faults.IsEmpty, $"a handler failed: {(Faults.TryPeek(out Exception? fault) ? fault : null)}");
    }

    /// <summary>Waits until a reactor holds so many connections.</summary>
    public static void AwaitLive(Reactor reactor, int count)
        => Assert.True(SpinWait.SpinUntil(() => Moves.LiveOn(reactor) == count, 5_000),
            $"reactor {reactor.ShardIndex} holds {Moves.LiveOn(reactor)} connections, not {count}");

    /// <summary>Sends a message and returns the answer to it, of the same length but for the digit of the reactor it came from.</summary>
    public static string Exchange(Socket client, string message)
    {
        client.Send(Encoding.ASCII.GetBytes(message));
        return Receive(client, message.Length + 1);
    }

    public static string Receive(Socket client, int length)
    {
        var buffer = new byte[length];
        int got = 0;
        while (got < length)
        {
            int n = client.Receive(buffer, got, length - got, SocketFlags.None);
            Assert.True(n > 0, $"closed after {got} of {length} bytes");
            got += n;
        }
        return Encoding.ASCII.GetString(buffer);
    }

    /// <summary>Answers each delivery with the digit of the reactor it runs on and the delivery itself.</summary>
    public static async Task Tell(TcpConnection conn)
    {
        try
        {
            while (true)
            {
                string got = await ReadText(conn);
                if (got.Length == 0)
                {
                    return;
                }
                conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    /// <summary>One delivery; empty once the peer has closed.</summary>
    public static async Task<string> ReadText(TcpConnection conn)
    {
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            var text = new StringBuilder();
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    text.Append(Encoding.ASCII.GetString(item.AsSpan()));
                    conn.ReturnBuffer(in item);
                }
            }
            if (text.Length > 0 || snapshot.IsClosed)
            {
                return text.ToString();
            }
        }
    }

    /// <summary>
    /// <c>await</c>ed from another thread, continues on the connection's reactor, whichever that is by then: the switch to
    /// its host (<see cref="TcpConnection.RingHost"/>), which throws once that reactor has stopped.
    /// </summary>
    public static ReactorSwitch Home(TcpConnection conn) => new(conn.RingHost);
}
