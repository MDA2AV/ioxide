using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// A connection that ends while it moves, or after: by its peer, its handler, a timeout. Whichever reactor has it by then
/// ends it, once, and neither keeps anything of it.
/// </summary>
internal static class MoveEndTests
{
    private enum Stage { Waiting, Given, Moved }

    private enum By { Close, Reset, HalfClose }

    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            foreach (Stage stage in Enum.GetValues<Stage>())
            {
                foreach (By by in Enum.GetValues<By>())
                {
                    RegisterPeer(runner, mode, config, skip, stage, by);
                }
            }
            RegisterHandler(runner, mode, config, skip);
        }
        RegisterClocks(runner);
        RegisterShutdown(runner);
        RegisterNoRoom(runner);
        RegisterBatch(runner);
    }

    // A connection that ends in the batch of completions that ends its recv.
    private static void RegisterBatch(Runner runner)
    {
        // Its recv's cancel and its send's failure come back in one batch. A recv armed at the first would only be submitted
        // after the second has closed the descriptor, whose number may be another socket's by then.
        runner.Test("move end: a connection that ends as its recv is cancelled leaves no recv for whatever takes its descriptor's number", () =>
        {
            const int Rounds = 8, Big = 8 * 1024 * 1024;
            int reused = 0;
            for (int round = 0; round < Rounds; round++)
            {
                var flushing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var opened = new TaskCompletionSource<(int Was, int Fd, int Peer)>(TaskCreationOptions.RunContinuationsAsynchronously);
                using (var fleet = new MoveFleet(2, async conn =>
                {
                    try
                    {
                        if (await MoveFleet.ReadText(conn) != "go")
                        {
                            return;
                        }
                        ValueTask<RecvSnapshot> read = conn.ReadAsync();
                        conn.Write(new byte[Big]);
                        ValueTask flush = conn.FlushAsync();
                        flushing.SetResult();
                        await flush;   // which fails
                        int was = conn.ClientFd;

                        // The next pass, before the reactor submits: a socket opened then takes the number this one leaves.
                        Reactor.Current!.ScheduleOnReactor(_ => opened.SetResult(OpenSocketPair(was)), null);
                        await read;
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, MoveFleet.Shared(new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, SendWaitAll = false })))
                {
                    (Socket client, TcpConnection conn) = fleet.Connect();
                    client.Send("go"u8);
                    Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");

                    // A move given up has its recv armed again, behind the send that stalls.
                    Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
                    Moves.WaitFor(conn, Moves.Waiting);
                    Moves.GiveUp(conn);
                    Moves.WaitFor(conn, Moves.None);
                    Thread.Sleep(20);

                    Moves.OnItsReactor(conn, reactor =>
                    {
                        Assert.True(Moves.StartMove(reactor, conn, fleet.B), "the move was refused");
                        TcpSweepClose(reactor, conn);   // as a send timeout does
                    });
                    Assert.True(opened.Task.Wait(5_000), "the connection never ended");
                    (int was, int fd, int peer) = opened.Task.Result;
                    Thread.Sleep(50);
                    try
                    {
                        if (fd == was)
                        {
                            reused++;
                            Assert.Equal(6L, Peek(fd));
                        }
                    }
                    finally
                    {
                        Native.close(fd);
                        Native.close(peer);
                    }
                }
                TestServer.StopAll();
            }
            Assert.True(reused > 0, "the number was never taken again, so this proves nothing");
        });
    }

    // A pair of sockets, one end of which takes the lowest number free (which was ought to be), with 6 bytes in it.
    private static unsafe (int Was, int Fd, int Peer) OpenSocketPair(int was)
    {
        int* pair = stackalloc int[2];
        Assert.Equal(0, socketpair(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0, pair));
        (int fd, int peer) = pair[0] == was ? (pair[0], pair[1]) : (pair[1], pair[0]);
        fixed (byte* bytes = "secret"u8)
        {
            Native.write(peer, bytes, 6);
        }
        return (was, fd, peer);
    }

    private static unsafe long Peek(int fd)
    {
        byte* buffer = stackalloc byte[64];
        return recv(fd, buffer, 64, 0x42 /* MSG_PEEK | MSG_DONTWAIT */);
    }

    [DllImport("libc")]
    private static extern unsafe int socketpair(int domain, int type, int protocol, int* pair);

    [DllImport("libc")]
    private static extern unsafe long recv(int fd, void* buffer, nuint length, int flags);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "TcpSweepClose")]
    private static extern void TcpSweepClose(Reactor reactor, TcpConnection conn);

    // Incremental mode: a connection's ring is registered in its new reactor's io_uring, which can be refused.
    private static void RegisterNoRoom(Runner runner)
    {
        bool skip = !TestServer.KernelAtLeast(6, 12);

        runner.Test("move end: a reactor at its MaxConnections is given no connection, and the one that was to go is served on", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, MoveFleet.Incremental(room: 2));
            (Socket client, TcpConnection conn) = fleet.Connect();
            (Socket Client, TcpConnection Conn) first = fleet.Connect(fleet.B);
            fleet.Connect(fleet.B);
            MoveFleet.AwaitLive(fleet.B, 2);
            Assert.Equal(0, Moves.RoomOn(fleet.B));

            Assert.True(!Moves.Begin(conn, fleet.B), "a move to a reactor without room began");
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));

            first.Client.Dispose();
            MoveFleet.AwaitLive(fleet.B, 1);
            Moves.To(conn, fleet.B);   // into the room it left
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
            Assert.Equal(0, Moves.RoomOn(fleet.B));
            Assert.Equal(2, Moves.RoomOn(fleet.A));
        }, skip);

        runner.Test("move end: what a move had reserved is free again once it is given up", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        atWork.TrySetResult();
                        await gate.Task.ConfigureAwait(false);
                        await MoveFleet.Home(conn);
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, MoveFleet.Incremental(room: 4));
            (Socket client, TcpConnection conn) = fleet.Connect();
            MoveFleet.AwaitLive(fleet.B, 0);
            client.Send("work"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            Assert.Equal(3, Moves.RoomOn(fleet.B));
            Moves.GiveUp(conn);
            Moves.WaitFor(conn, Moves.None);
            Assert.Equal(4, Moves.RoomOn(fleet.B));
            gate.SetResult();
        }, skip);

        runner.Test("move end: what a move had reserved is free again once its connection ends, though its handler holds on to that", () =>
        {
            var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                if ((await MoveFleet.ReadText(conn)).Length > 0)
                {
                    holding.SetResult();
                    await release.Task;
                }
                conn.DecRef();
            }, MoveFleet.Incremental(room: 4));
            (Socket client, TcpConnection conn) = fleet.Connect();
            MoveFleet.AwaitLive(fleet.B, 0);
            client.Send("hold"u8);
            Assert.True(holding.Task.Wait(5_000), "the handler never got to hold it");
            try
            {
                Moves.OnItsReactor(conn, reactor =>
                {
                    Assert.True(Moves.StartMove(reactor, conn, fleet.B), "the move was refused");
                    Assert.Equal(3, Moves.RoomOn(fleet.B));
                    CloseFromRecv(reactor, conn);   // as a recv that ends before its cancel does
                    Assert.Equal(Moves.None, Moves.StateOf(conn));
                    Assert.Equal(4, Moves.RoomOn(fleet.B));
                });
            }
            finally
            {
                release.SetResult();
            }
            MoveFleet.AwaitLive(fleet.A, 0);
            Assert.Equal(4, Moves.RoomOn(fleet.B));
        }, skip);

        runner.Test("move end: what a move had reserved is free again as soon as its connection's send fails, though its handler holds on to that", () =>
        {
            const int Big = 8 * 1024 * 1024;
            var flushing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    if (await MoveFleet.ReadText(conn) != "go")
                    {
                        return;
                    }
                    conn.Write(new byte[Big]);
                    ValueTask flush = conn.FlushAsync();
                    flushing.SetResult();
                    await flush;
                    failed.SetResult();
                    await release.Task;
                }
                finally
                {
                    conn.DecRef();
                }
            }, MoveFleet.Incremental(room: 4));
            (Socket client, TcpConnection conn) = fleet.Connect();
            MoveFleet.AwaitLive(fleet.B, 0);
            client.Send("go"u8);
            Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            Assert.Equal(3, Moves.RoomOn(fleet.B));
            try
            {
                client.LingerState = new LingerOption(true, 0);
                client.Close();   // a reset, which fails the send
                Assert.True(failed.Task.Wait(5_000), "the flush never ended");
                Assert.True(SpinWait.SpinUntil(() => Moves.RoomOn(fleet.B) == 4, 2_000), $"{Moves.RoomOn(fleet.B)} of 4 are free while the handler holds on");
            }
            finally
            {
                release.SetResult();
            }
            MoveFleet.AwaitLive(fleet.A, 0);
        }, skip);

        bool cannotRunOut = skip || !LockedMemory.CanRunOut;

        foreach (bool roomAtHome in new[] { true, false })
        {
            string how = roomAtHome ? "is told where it comes back to" : "is told as it is closed";
            runner.Test($"move end: whoever waits for the flush of a connection that its new reactor can't register {how}", () =>
            {
                const int Big = 8 * 1024 * 1024;
                var flushing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var flushed = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
                var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var fleet = new MoveFleet(2, async conn =>
                {
                    try
                    {
                        if (await MoveFleet.ReadText(conn) != "go")
                        {
                            return;
                        }
                        Task<string> read = MoveFleet.ReadText(conn);
                        conn.Write(new byte[Big]);
                        ValueTask flush = conn.FlushAsync();
                        flushing.SetResult();
                        await flush;
                        flushed.SetResult(Reactor.Current!.ShardIndex);
                        if (await read == "more")
                        {
                            conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}more"));
                            await conn.FlushAsync();
                            await MoveFleet.ReadText(conn);
                        }
                        ended.SetResult();
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, MoveFleet.Incremental(room: 4));
                (Socket client, TcpConnection conn) = fleet.Connect();
                MoveFleet.AwaitLive(fleet.B, 0);
                client.Send("go"u8);
                Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");
                Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
                Moves.WaitFor(conn, Moves.Waiting);
                Moves.Held b = Moves.Hold(fleet.B);
                Receive(client, Big);   // the send completes, and the connection goes with it
                Moves.WaitFor(conn, Moves.Given);
                if (roomAtHome)
                {
                    Moves.Held a = Moves.Hold(fleet.A);
                    using (LockedMemory.None())
                    {
                        b.Dispose();
                        Moves.On(fleet.B, static () => { });
                    }
                    a.Dispose();
                    Assert.True(flushed.Task.Wait(5_000), "whoever waits for the flush was never told");
                    Assert.Equal(0, flushed.Task.Result);
                    client.Send("more"u8);
                    Assert.Equal("0more", MoveFleet.Receive(client, 5));
                    client.Dispose();
                }
                else
                {
                    using (LockedMemory.None())
                    {
                        b.Dispose();
                        Assert.Equal(0, client.Receive(new byte[16]));
                    }
                    Assert.True(flushed.Task.Wait(5_000), "whoever waits for the flush was never told");
                }
                Assert.True(ended.Task.Wait(5_000), "the handler never ended");
                MoveFleet.AwaitLive(fleet.A, 0);
                MoveFleet.AwaitLive(fleet.B, 0);
                foreach (Reactor reactor in fleet.Reactors)
                {
                    Assert.Equal(4, Moves.RoomOn(reactor));
                    Assert.Equal(0, ArrivingAt(reactor));
                    Assert.Equal(0, GivenAwayBy(reactor));
                }
            }, cannotRunOut);
        }

        runner.Test("move end: a connection its new reactor can't register, whose home has stopped, is closed, and nothing of it is left", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, MoveFleet.Incremental(room: 4));
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            MoveFleet.AwaitLive(fleet.B, 0);
            Moves.Held b = Moves.Hold(fleet.B);
            try
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                fleet.A.Stop();
            }
            finally
            {
                using (LockedMemory.None())
                {
                    b.Dispose();
                    Assert.Equal(0, client.Receive(new byte[16]));
                }
            }
            Assert.True(fleet.Threads[0].Join(5_000), "the stop never ended");
            MoveFleet.AwaitLive(fleet.B, 0);
            foreach (Reactor reactor in fleet.Reactors)
            {
                Assert.Equal(4, Moves.RoomOn(reactor));
                Assert.Equal(0, ArrivingAt(reactor));
                Assert.Equal(0, GivenAwayBy(reactor));
            }
        }, cannotRunOut);

        runner.Test("move end: a connection whose ring its new reactor can't register goes home, and is served there", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, MoveFleet.Incremental(room: 4));
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            MoveFleet.AwaitLive(fleet.B, 0);

            Moves.Held b = Moves.Hold(fleet.B);
            Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
            Moves.WaitFor(conn, Moves.Given);
            client.Send("between"u8);
            Moves.Held a = Moves.Hold(fleet.A);   // has it back only once there is locked memory again
            using (LockedMemory.None())
            {
                b.Dispose();
                Moves.On(fleet.B, static () => { });
            }
            Assert.Equal(Moves.Given, Moves.StateOf(conn));
            a.Dispose();

            Assert.Equal("0between", MoveFleet.Receive(client, 8));
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            Assert.Equal(0L, fleet.B.ConnectionsTaken);
            Assert.Equal(1L, fleet.A.ConnectionsTaken);
            MoveFleet.AwaitLive(fleet.A, 1);
            MoveFleet.AwaitLive(fleet.B, 0);
            Assert.Equal(3, Moves.RoomOn(fleet.A));
            Assert.Equal(4, Moves.RoomOn(fleet.B));

            Moves.To(conn, fleet.B);   // and goes another time
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        }, cannotRunOut);

        runner.Test("move end: a connection whose ring neither reactor can register is closed, and both go on", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, MoveFleet.Incremental(room: 4));
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            MoveFleet.AwaitLive(fleet.B, 0);

            Moves.Held b = Moves.Hold(fleet.B);
            Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
            Moves.WaitFor(conn, Moves.Given);
            using (LockedMemory.None())
            {
                b.Dispose();
                Assert.Equal(0, client.Receive(new byte[16]));
            }
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
            foreach (Reactor reactor in fleet.Reactors)
            {
                Assert.Equal(4, Moves.RoomOn(reactor));
                (Socket next, TcpConnection _) = fleet.Connect(reactor);
                Assert.Equal($"{reactor.ShardIndex}next", MoveFleet.Exchange(next, "next"));
            }
        }, cannotRunOut);
    }

    private static void RegisterPeer(Runner runner, string mode, Func<ServerConfig> config, bool skip, Stage stage, By by)
    {
        string when = stage switch
        {
            Stage.Waiting => "while its handler keeps the move waiting",
            Stage.Given => "while between two reactors",
            _ => "after a move",
        };
        string what = by switch
        {
            By.Close => "closed by its peer",
            By.Reset => "reset by its peer",
            _ => "half-closed by its peer",
        };

        runner.Test($"move end: a connection {what} {when} ends, and nothing of it is left ({mode})", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var ended = new System.Collections.Concurrent.ConcurrentDictionary<TcpConnection, int>();
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        if (got == "wait")
                        {
                            atWork.TrySetResult();
                            await gate.Task.ConfigureAwait(false);
                            await MoveFleet.Home(conn);
                        }
                        conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                        await conn.FlushAsync();
                    }
                    ended[conn] = conn.Reactor.ShardIndex;
                }
                finally
                {
                    conn.DecRef();
                }
            }, config());

            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            string socket = SocketOf(conn.ClientFd);
            int fd = conn.ClientFd;
            ended.Clear();   // of the ones that came to the other reactor

            switch (stage)
            {
                case Stage.Waiting:
                    client.Send("wait"u8);
                    Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
                    Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
                    Moves.WaitFor(conn, Moves.Waiting);
                    End(client, by);
                    gate.SetResult();
                    break;

                case Stage.Given:
                    using (Moves.Hold(fleet.B))
                    {
                        Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                        Moves.WaitFor(conn, Moves.Given);
                        End(client, by);
                        Thread.Sleep(20);
                    }
                    break;

                default:
                    Moves.To(conn, fleet.B);
                    Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
                    End(client, by);
                    break;
            }

            Assert.True(SpinWait.SpinUntil(() => ended.ContainsKey(conn), 5_000), $"the handler never saw the end: {Moves.Describe(conn)}");
            if (by == By.HalfClose)
            {
                int expected = stage == Stage.Waiting ? "0wait".Length : 0;
                if (expected > 0)
                {
                    Assert.Equal("0wait", MoveFleet.Receive(client, expected));
                }
                Assert.Equal(0, client.Receive(new byte[16]));   // what was being answered, and then the server's own end
            }
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
            Assert.True(SpinWait.SpinUntil(() => SocketOf(fd) != socket, 5_000), "the connection's descriptor was never closed");
            if (config().Incremental is { } incremental)
            {
                Assert.Equal(incremental.MaxConnections, Moves.RoomOn(fleet.A));
                Assert.Equal(incremental.MaxConnections, Moves.RoomOn(fleet.B));
            }

            // Both reactors go on.
            foreach (Reactor reactor in fleet.Reactors)
            {
                (Socket next, TcpConnection _) = fleet.Connect(reactor);
                Assert.Equal($"{reactor.ShardIndex}next", MoveFleet.Exchange(next, "next"));
            }
        }, skip);
    }

    private static void RegisterHandler(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move end: a handler that lets go while its move waits: its peer hears of it, and it ends where it was ({mode})", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                if ((await MoveFleet.ReadText(conn)).Length > 0)
                {
                    atWork.TrySetResult();
                    await gate.Task.ConfigureAwait(false);
                }
                conn.DecRef();
            }, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("work"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            gate.SetResult();
            Assert.Equal(0, client.Receive(new byte[1]));
            Moves.WaitFor(conn, Moves.None);
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            Assert.Equal(0L, fleet.A.ConnectionsGiven);
        }, skip);

        runner.Test($"move end: a handler let go of from another thread while between two reactors ends on the second ({mode})", () =>
        {
            var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                if ((await MoveFleet.ReadText(conn)).Length == 0)
                {
                    conn.DecRef();   // not this test's
                    return;
                }
                Task<string> read = MoveFleet.ReadText(conn);   // another thread lets go of it here, and the read ends with the connection
                waiting.SetResult();
                await read;
            }, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("hello"u8);
            Assert.True(waiting.Task.Wait(5_000), "the handler never got to wait");
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                conn.DecRef();
                Assert.Equal(0, client.Receive(new byte[1]));   // the half-close is this thread's, at once
            }
            Assert.True(SpinWait.SpinUntil(() => fleet.B.ConnectionsTaken == 1, 5_000), "the second reactor never took it");
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        }, skip);

        runner.Test($"move end: a handler that fails after a move lets go of its connection where it is ({mode})", () =>
        {
            (int port, Reactor[] reactors, _) = TestServer.StartFleet(2, async (_, conn) =>
            {
                Accepted.Enqueue(conn);
                await MoveFleet.ReadText(conn);
                throw new InvalidOperationException("a handler's own fault");
            }, config());

            (Socket client, TcpConnection conn) = Take(port, reactors[0]);
            Moves.To(conn, reactors[1]);
            client.Send("fail"u8);
            Assert.Equal(0, client.Receive(new byte[1]));
            client.Dispose();
            MoveFleet.AwaitLive(reactors[0], 0);
            MoveFleet.AwaitLive(reactors[1], 0);
        }, skip);

        runner.Test($"move end: connections that moved are pooled and reused where they end ({mode})", () =>
        {
            var seen = new System.Collections.Concurrent.ConcurrentBag<TcpConnection>();
            using var fleet = new MoveFleet(2, conn =>
            {
                seen.Add(conn);
                return MoveFleet.Tell(conn);
            }, config());
            (Socket first, TcpConnection conn) = fleet.Connect();
            Moves.To(conn, fleet.B);
            first.Dispose();
            MoveFleet.AwaitLive(fleet.B, 0);

            (Socket second, TcpConnection again) = fleet.Connect(fleet.B);
            Assert.True(ReferenceEquals(conn, again), "the connection was not taken from the pool of the reactor it ended on");
            Assert.Equal("1hello", MoveFleet.Exchange(second, "hello"));
            Assert.True(!again.Pinned && ReferenceEquals(again.Reactor, fleet.B), "it is not as new");

            Moves.To(again, fleet.A);   // and moves like any other
            Assert.Equal("0hello", MoveFleet.Exchange(second, "hello"));
        }, skip);

        runner.Test($"move end: a handler that lets go of a connection that moved, holding buffers, gives them back where it is ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, async conn =>
            {
                var pipe = new TcpConnectionDualPipe(conn);
                await pipe.Input.ReadAsync();   // and keeps what it got
                conn.DecRef();
            }, config() with { RecvSlots = 4, RecvBufferSize = 256 });
            for (int i = 0; i < 20; i++)   // five times as many as the buffers there are
            {
                (Socket client, TcpConnection conn) = fleet.Connect();
                Moves.To(conn, fleet.B);
                client.Send("x"u8);
                Assert.Equal(0, client.Receive(new byte[4]));
                client.Dispose();
                MoveFleet.AwaitLive(fleet.B, 0);
            }
        }, skip);

        runner.Test($"move end: a pin ends with the connection's life ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket first, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(first, "hello"));
            conn.Pinned = true;
            first.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            (Socket _, TcpConnection again) = fleet.Connect();
            Assert.True(ReferenceEquals(conn, again), "the connection was not reused, so this proved nothing");
            Moves.To(again, fleet.B);
        }, skip);
    }

    private static void RegisterClocks(Runner runner)
    {
        runner.Test("move end: a read timeout runs on through moves, and ends the connection on the reactor it is on by then", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, MoveFleet.Shared(new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, ReadTimeoutMs = 1_000 }));
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            long parked = Environment.TickCount64;
            for (int i = 1; i <= 5; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 2]);
            }
            Assert.Equal(0, client.Receive(new byte[1]));
            Assert.True(Environment.TickCount64 - parked < 5_000, "a move started the read's clock again and again");
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        });

        runner.Test("move end: a read timeout due while the move waits ends the connection", () =>
        {
            // Its handler is at work with a read of its own parked beside it, so the clock runs, and a file read keeps the move waiting.
            using var pipe = new System.IO.Pipes.AnonymousPipeServerStream(System.IO.Pipes.PipeDirection.Out, HandleInheritability.None);
            var reading = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    if (await MoveFleet.ReadText(conn) != "go")
                    {
                        return;
                    }
                    ValueTask<RecvSnapshot> read = conn.ReadAsync();
                    ValueTask<int> file = conn.ReadFileAsync((int)pipe.ClientSafePipeHandle.DangerousGetHandle(), 16, 0);
                    reading.SetResult();
                    Assert.True((await read).IsClosed, "the read ended with the connection open");
                    ended.SetResult();
                    await file;
                }
                finally
                {
                    conn.DecRef();
                }
            }, MoveFleet.Shared(new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, ReadTimeoutMs = 500 }));
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("go"u8);
            Assert.True(reading.Task.Wait(5_000), "the handler never got to read");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);

            Assert.Equal(0, client.Receive(new byte[1]));
            Assert.True(ended.Task.Wait(5_000), "the handler never heard of it");
            pipe.Write("x"u8);
            MoveFleet.AwaitLive(fleet.A, 0);
        });

        runner.Test("move end: a send timeout ends a connection that moved", () =>
        {
            var sent = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    if ((await MoveFleet.ReadText(conn)).Length == 0)
                    {
                        return;
                    }
                    conn.Write(new byte[8 * 1024 * 1024]);
                    await conn.FlushAsync();
                    sent.TrySetResult(Reactor.Current!.ShardIndex);
                }
                finally
                {
                    conn.DecRef();
                }
            }, MoveFleet.Shared(new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, SendTimeoutMs = 700 }));
            (Socket client, TcpConnection conn) = fleet.Connect();
            Moves.To(conn, fleet.B);
            client.Send("go"u8);   // and reads nothing
            Assert.True(sent.Task.Wait(10_000), "the flush never ended");
            Assert.Equal(1, sent.Task.Result);
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        });
    }

    private static void RegisterShutdown(Runner runner)
    {
        // The let-go finds a flush in flight, so the half-close waits for it in the queue of the reactor the connection
        // was on, where it is not found any more once it has moved.
        runner.Test("move end: a half-close that waits for a flush is made, though the connection moves from under it", () =>
        {
            const int Big = 8 * 1024 * 1024;
            var flushing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var flushed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                if ((await MoveFleet.ReadText(conn)).Length == 0)
                {
                    conn.DecRef();   // not this test's
                    return;
                }
                _ = conn.ReadAsync().AsTask();   // parked to the end
                conn.Write(new byte[Big]);
                ValueTask flush = conn.FlushAsync();
                flushing.SetResult();
                await flush;
                flushed.SetResult();
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("go"u8);
            Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);

            using (Moves.Hold(fleet.B))
            {
                MoveFleetDrain(client, Big);   // the send ends, and it is handed over before its waiter is told
                Moves.WaitFor(conn, Moves.Given);
                Assert.True(Moves.FlushOutstandingOf(conn), "the flush was over, so nothing is deferred and this proves nothing");
                conn.DecRef();
            }

            Assert.True(flushed.Task.Wait(5_000), "the flush's waiter was never told");
            Assert.Equal(0, client.Receive(new byte[1]));   // within its receive timeout, and the read timeout is a minute
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 0);
        });

        runner.Test("move end: a half-close of the handler's own, after a move, reaches the peer", () =>
        {
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    if ((await MoveFleet.ReadText(conn)).Length == 0)
                    {
                        return;
                    }
                    conn.Write("bye"u8);
                    await conn.FlushAsync();
                    conn.ShutdownWrite();
                    await MoveFleet.ReadText(conn);
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            Moves.To(conn, fleet.B);
            client.Send("go"u8);
            Assert.Equal("bye", MoveFleet.Receive(client, 3));
            Assert.Equal(0, client.Receive(new byte[1]));
            client.Dispose();
            MoveFleet.AwaitLive(fleet.B, 0);
        });
    }

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "CloseFromRecv")]
    private static extern void CloseFromRecv(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_arriving")]
    private static extern ref int ArrivingField(Reactor reactor);

    private static int ArrivingAt(Reactor reactor) => Volatile.Read(ref ArrivingField(reactor));

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_givenAway")]
    private static extern ref int GivenAwayField(Reactor reactor);

    private static int GivenAwayBy(Reactor reactor) => Volatile.Read(ref GivenAwayField(reactor));

    private static void Receive(Socket client, int length)
    {
        var buffer = new byte[64 * 1024];
        for (int got = 0; got < length;)
        {
            int n = client.Receive(buffer, 0, Math.Min(buffer.Length, length - got), SocketFlags.None);
            Assert.True(n > 0, $"closed after {got} of {length} bytes");
            got += n;
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentQueue<TcpConnection> Accepted = new();

    private static (Socket Client, TcpConnection Conn) Take(int port, Reactor on)
    {
        for (int attempt = 0; attempt < 500; attempt++)
        {
            Accepted.Clear();
            Socket client = Moves.Connect(port);
            TcpConnection? conn = null;
            Assert.True(SpinWait.SpinUntil(() => Accepted.TryDequeue(out conn), 10_000), "the connection was never accepted");
            if (ReferenceEquals(conn!.Reactor, on))
            {
                return (client, conn);
            }
            client.Dispose();
        }
        throw new Exception("500 connections, and none came to the reactor asked for");
    }

    private static void End(Socket client, By by)
    {
        switch (by)
        {
            case By.HalfClose:
                client.Shutdown(SocketShutdown.Send);
                break;
            case By.Reset:
                client.LingerState = new LingerOption(true, 0);
                client.Close();
                break;
            default:
                client.Close();
                break;
        }
    }

    private static void MoveFleetDrain(Socket client, int length)
    {
        var buffer = new byte[64 * 1024];
        for (int got = 0; got < length;)
        {
            int n = client.Receive(buffer, 0, Math.Min(buffer.Length, length - got), SocketFlags.None);
            Assert.True(n > 0, $"closed after {got} of {length} bytes");
            got += n;
        }
    }

    // The socket a descriptor is, by its inode; empty once it is none.
    private static string SocketOf(int fd)
    {
        try
        {
            return File.ResolveLinkTarget($"/proc/self/fd/{fd}", false)?.Name ?? "";
        }
        catch (IOException)
        {
            return "";
        }
    }
}
