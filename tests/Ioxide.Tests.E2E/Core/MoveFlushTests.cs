using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// A connection that something else than its reading handler flushes, while that handler waits in a read: a broadcast from
/// another thread, a timer of the reactor it was accepted on. A flush asked for while the connection is between two
/// reactors is lost: it names the connection by its place on the reactor it has left, finds nothing there, and whoever
/// waits for it waits until the connection ends. The pending ones fail for that, and are to pass once it doesn't happen.
/// </summary>
/// <remarks>The controls next to them are the same without the move under way, and pass.</remarks>
internal static class MoveFlushTests
{
    private const string Lost = "a flush asked for off the reactor while its connection is between two of them is lost";

    // How long a flush may take that takes none.
    private const int FlushedWithinMs = 2_000;

    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            if (skip)
            {
                continue;
            }

            runner.Test($"move flush: control: one from another thread while a read waits, on a connection that has moved, is sent ({mode})", () =>
            {
                using var fleet = new MoveFleet(2, ReadOnly, config());
                (Socket client, TcpConnection conn) = fleet.Connect();
                for (int i = 0; i < 20; i++)
                {
                    Moves.To(conn, fleet.Reactors[i % 2]);
                    AssertSent(client, Task.Run(() => Say(conn, "push")));
                }
            });

            runner.Pending($"move flush: one from another thread while its connection is between two reactors is sent ({mode})", () =>
            {
                using var fleet = new MoveFleet(2, ReadOnly, config());
                (Socket client, TcpConnection conn) = fleet.Connect();
                Task said;
                using (InTransit(conn, fleet.B))
                {
                    said = Task.Run(() => Say(conn, "push"));
                    Thread.Sleep(50);   // it has been asked for by now
                }
                AssertSent(client, said);
            }, Lost);
        }

        runner.Pending("move flush: one from a timer of the old reactor, while its connection is between two, is sent", () =>
        {
            using var fleet = new MoveFleet(2, ReadOnly);
            (Socket client, TcpConnection conn) = fleet.Connect();
            Task said = Task.CompletedTask;
            using (InTransit(conn, fleet.B))
            {
                Moves.On(fleet.A, () => said = Say(conn, "push"));   // on the thread it has just left
            }
            AssertSent(client, said);
        }, Lost);

        runner.Pending("move flush: one through a pipe, from another thread while its connection is between two reactors, is sent", () =>
        {
            TcpConnectionDualPipe? pipe = null;
            using var fleet = new MoveFleet(2, async conn =>
            {
                pipe = new TcpConnectionDualPipe(conn);
                try
                {
                    while (!(await pipe.Input.ReadAsync()).IsCompleted)
                    {
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            Task said;
            using (InTransit(conn, fleet.B))
            {
                said = Task.Run(async () => await pipe!.Output.WriteAsync("push"u8.ToArray()));
                Thread.Sleep(50);
            }
            AssertSent(client, said);
        }, Lost);

        runner.Pending("move flush: one through a stream, from another thread while its connection is between two reactors, is sent", () =>
        {
            TcpConnectionStream? stream = null;
            using var fleet = new MoveFleet(2, async conn =>
            {
                stream = new TcpConnectionStream(conn);
                try
                {
                    while (await stream.ReadAsync(new byte[16]) > 0)
                    {
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            Task said;
            using (InTransit(conn, fleet.B))
            {
                said = Task.Run(async () => await stream!.WriteAsync("push"u8.ToArray()));
                Thread.Sleep(50);
            }
            AssertSent(client, said);
        }, Lost);

        runner.Pending("move flush: after one from another thread while its connection is between two reactors, it can be flushed again", () =>
        {
            using var fleet = new MoveFleet(2, ReadOnly);
            (Socket client, TcpConnection conn) = fleet.Connect();
            Task first;
            using (InTransit(conn, fleet.B))
            {
                first = Task.Run(() => Say(conn, "first"));
                Thread.Sleep(50);
            }
            Moves.WaitFor(conn, Moves.None);
            Thread.Sleep(50);
            Task second = Task.Run(() => Say(conn, "push"));   // refused: the one before never ends
            Assert.True(Task.WaitAll([first, second], FlushedWithinMs), "a flush never completed");
            Assert.Equal("firstpush", MoveFleet.Receive(client, 9));
        }, Lost);

        runner.Test("move flush: control: whoever waits for one from another thread, while its connection is between two reactors, is told once the connection ends", () =>
        {
            using var fleet = new MoveFleet(2, ReadOnly);
            (Socket client, TcpConnection conn) = fleet.Connect();
            Task said;
            using (InTransit(conn, fleet.B))
            {
                said = Task.Run(() => Say(conn, "push"));
                Thread.Sleep(50);
            }
            Moves.WaitFor(conn, Moves.None);
            client.Dispose();
            Assert.True(said.Wait(5_000), "whoever waits for the flush was never told");
            MoveFleet.AwaitLive(fleet.B, 0);
        });

        runner.Test("move flush: control: pushed to from other threads while moved all the time, pinned connections get everything", () =>
        {
            using var fleet = new MoveFleet(3, conn =>
            {
                conn.Pinned = true;
                return ReadOnly(conn);
            });
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 16).Select(_ => fleet.Connect(fleet.Reactors[Random.Shared.Next(3)])).ToArray();
            using var shuffle = new Moves.Shuffle(fleet.Reactors);
            Task[] pushing = all.Select(pair => Task.Run(async () =>
            {
                for (int i = 0; i < 500; i++)
                {
                    await Say(pair.Conn, "push").WaitAsync(TimeSpan.FromMilliseconds(FlushedWithinMs));
                    Assert.Equal("push", MoveFleet.Receive(pair.Client, 4));
                }
            })).ToArray();
            Assert.True(Task.WaitAll(pushing, 60_000), "a push was never sent");
            Assert.Equal(0L, shuffle.Made);
        });

        runner.Test("move flush: control: pushed to while moved all the time, from its own reactor each time, connections get everything", () =>
        {
            using var fleet = new MoveFleet(3, ReadOnly);
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 16).Select(_ => fleet.Connect(fleet.Reactors[Random.Shared.Next(3)])).ToArray();
            using var shuffle = new Moves.Shuffle(fleet.Reactors);
            Task[] pushing = all.Select(pair => Task.Run(async () =>
            {
                for (int i = 0; i < 300; i++)
                {
                    await Task.Run(async () =>
                    {
                        await MoveFleet.Home(pair.Conn);
                        await Say(pair.Conn, "push");
                    }).WaitAsync(TimeSpan.FromMilliseconds(FlushedWithinMs));
                    Assert.Equal("push", MoveFleet.Receive(pair.Client, 4));
                }
            })).ToArray();
            Assert.True(Task.WaitAll(pushing, 60_000), "a push was never sent");
            Assert.True(shuffle.Made > 20, $"only {shuffle.Made} moves were made");
        });
    }

    // The connection given to a reactor that is held, until disposed.
    private static Moves.Held InTransit(TcpConnection conn, Reactor target)
    {
        Moves.Held held = Moves.Hold(target);
        Assert.True(SpinWait.SpinUntil(() => Moves.ReadParkedOf(conn), 5_000), "the handler never got to wait");
        Assert.True(Moves.Begin(conn, target), "the move was refused");
        Moves.WaitFor(conn, Moves.Given);
        return held;
    }

    private static void AssertSent(Socket client, Task said)
    {
        Assert.True(said.Wait(FlushedWithinMs), "the flush never completed");
        Assert.Equal("push", MoveFleet.Receive(client, 4));
    }

    private static async Task Say(TcpConnection conn, string text)
    {
        conn.Write(Encoding.ASCII.GetBytes(text));
        await conn.FlushAsync();
    }

    // Waits in reads, and leaves the writing to others.
    private static async Task ReadOnly(TcpConnection conn)
    {
        try
        {
            while ((await MoveFleet.ReadText(conn)).Length > 0)
            {
            }
        }
        finally
        {
            conn.DecRef();
        }
    }
}
