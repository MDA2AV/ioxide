using System.IO.Pipelines;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// A connection changing reactors (<see cref="TcpOptions.Rebalance"/>), one move at a time: when it goes and when it stays,
/// where its handler runs, what becomes of the bytes on their way, and the reactors' books.
/// </summary>
internal static class MoveTests
{
    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            RegisterMove(runner, mode, config, skip);
            RegisterWhen(runner, mode, config, skip);
        }
        RegisterHolds(runner);
        RegisterSends(runner);
        RegisterAdapters(runner);
        RegisterThreads(runner);
    }

    private static void RegisterMove(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move: a connection waiting in a read goes on where it was moved to, with its handler ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0here", MoveFleet.Exchange(client, "here"));

            Moves.To(conn, fleet.B);

            Assert.Equal("1there", MoveFleet.Exchange(client, "there"));
            Assert.Equal("1still", MoveFleet.Exchange(client, "still"));
            Assert.Equal(1L, fleet.A.ConnectionsGiven);
            Assert.Equal(1L, fleet.B.ConnectionsTaken);
            MoveFleet.AwaitLive(fleet.A, 0);
            MoveFleet.AwaitLive(fleet.B, 1);
            Moves.On(fleet.B, () => Assert.True(ReferenceEquals(conn, Moves.ConnectionsOf(fleet.B).Single()), "it is not in its new reactor's table"));
            Moves.On(fleet.A, () => Assert.True(Moves.ConnectionsOf(fleet.A).Length == 0, "it is still in its old reactor's table"));
        }, skip);

        runner.Test($"move: what the peer sends while the connection is between two reactors reaches its handler on the second ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));

            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                client.Send("between"u8);
                Thread.Sleep(50);
                Assert.Equal(0, client.Available);
            }

            Assert.Equal("1between", MoveFleet.Receive(client, 8));
            Assert.Equal("1after", MoveFleet.Exchange(client, "after"));
        }, skip);

        runner.Test($"move: what had arrived is handled where it arrived, and what comes after it on the next reactor, in order ({mode})", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        if (got.StartsWith('!'))
                        {
                            atWork.TrySetResult();
                            await gate.Task.ConfigureAwait(false);
                            await MoveFleet.Home(conn);
                        }
                        conn.Write(Encoding.ASCII.GetBytes(string.Concat(got.Select(c => $"{Reactor.Current!.ShardIndex}{c}"))));
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, config());

            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("!"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            client.Send("abc"u8);
            Assert.True(SpinWait.SpinUntil(() => Queued(conn) > 0, 5_000), "what the client sent was never received");

            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            client.Send("xyz"u8);
            gate.SetResult();

            Assert.Equal("0!0a0b0c1x1y1z", MoveFleet.Receive(client, 14));
            Assert.True(Moves.IsOn(conn, fleet.B), Moves.Describe(conn));
        }, skip);

        runner.Test($"move: round and round, 300 times, and neither slots, buffers nor group ids are lost or handed out twice ({mode})", () =>
        {
            ServerConfig small = Small(config());
            using var fleet = new MoveFleet(3, MoveFleet.Tell, small);
            (Socket client, TcpConnection conn) = fleet.Connect();

            for (int i = 1; i <= 300; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 3]);
                Assert.Equal($"{i % 3}message {i}", MoveFleet.Exchange(client, $"message {i}"));
            }

            MoveFleet.AwaitLive(fleet.Reactors[0], 1);
            foreach (Reactor reactor in fleet.Reactors)
            {
                Moves.On(reactor, () =>
                {
                    int held = Moves.ConnectionsOf(reactor).Length;
                    Assert.Equal(ReferenceEquals(reactor, conn.Reactor) ? 1 : 0, held);
                    Assert.True(Moves.SlotsOn(reactor) < 16, $"one connection has used {Moves.SlotsOn(reactor)} slots of reactor {reactor.ShardIndex}");
                    if (small.Incremental is { } incremental)
                    {
                        Assert.Equal(incremental.MaxConnections - held, Moves.RoomOn(reactor));
                    }
                });
            }
        }, skip);

        runner.Test($"move: many connections at once, from one reactor to another and back, and each keeps its own bytes ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket Client, TcpConnection Conn)[] all = Enumerable.Range(0, 40).Select(_ => fleet.Connect()).ToArray();

            for (int round = 0; round < 6; round++)
            {
                Reactor target = round % 2 == 0 ? fleet.B : fleet.A;
                foreach ((Socket _, TcpConnection conn) in all)
                {
                    Moves.Begin(conn, target);
                }
                for (int i = 0; i < all.Length; i++)
                {
                    all[i].Client.Send(Encoding.ASCII.GetBytes($"message {i:D2}"));
                }
                for (int i = 0; i < all.Length; i++)
                {
                    Assert.Equal($"message {i:D2}", MoveFleet.Receive(all[i].Client, 11)[1..]);
                    Moves.To(all[i].Conn, target);
                }
            }
            MoveFleet.AwaitLive(fleet.A, all.Length);
            MoveFleet.AwaitLive(fleet.B, 0);
        }, skip);
    }

    private static void RegisterWhen(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move: a connection whose handler is at work goes when the handler next waits ({mode})", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, conn => WorkOnce(conn, atWork, gate.Task), config());
            (Socket client, TcpConnection conn) = fleet.Connect();

            client.Send("work"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            Thread.Sleep(50);
            Assert.True(ReferenceEquals(conn.Reactor, fleet.A) && Moves.StateOf(conn) == Moves.Waiting, $"it went with its handler at work: {Moves.Describe(conn)}");

            gate.SetResult();
            Assert.Equal("0work", MoveFleet.Receive(client, 5));
            Assert.True(SpinWait.SpinUntil(() => Moves.IsOn(conn, fleet.B), 5_000), $"it never went: {Moves.Describe(conn)}");
            Assert.Equal("1next", MoveFleet.Exchange(client, "next"));
        }, skip);

        runner.Test($"move: a connection that isn't idle in time stays, with its recv armed again ({mode})", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, conn => WorkOnce(conn, atWork, gate.Task), config());
            (Socket client, TcpConnection conn) = fleet.Connect();

            client.Send("work"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            Moves.GiveUp(conn);
            Moves.WaitFor(conn, Moves.None);

            client.Send("behind"u8);
            Assert.True(SpinWait.SpinUntil(() => Queued(conn) > 0, 5_000), "nothing was received after the move was given up: its recv was never armed again");
            gate.SetResult();
            Assert.Equal("0work0behind", MoveFleet.Receive(client, 12));
            Assert.Equal(0L, fleet.A.ConnectionsGiven);
            Assert.True(Moves.IsOn(conn, fleet.A), Moves.Describe(conn));

            Moves.To(conn, fleet.B);   // and can be moved another time
            Assert.Equal("1later", MoveFleet.Exchange(client, "later"));
        }, skip);

        runner.Test($"move: without help, one whose handler stays at work stays too, and is served ({mode})", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, conn => WorkOnce(conn, atWork, gate.Task), config());
            (Socket client, TcpConnection conn) = fleet.Connect();

            client.Send("work"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
            Moves.WaitFor(conn, Moves.None);   // by its reactor's own clock
            gate.SetResult();
            Assert.Equal("0work", MoveFleet.Receive(client, 5));
            Assert.Equal("0next", MoveFleet.Exchange(client, "next"));
        }, skip);

        runner.Test($"move: to its own reactor, or while moving already, is refused ({mode})", () =>
        {
            using var fleet = new MoveFleet(3, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.True(!Moves.Begin(conn, fleet.A), "a move to its own reactor began");
            Moves.OnItsReactor(conn, reactor =>
            {
                Assert.True(Moves.StartMove(reactor, conn, fleet.B), "the move was refused");
                Assert.True(!Moves.StartMove(reactor, conn, fleet.Reactors[2]), "a second move began within the first");
            });
            Assert.True(SpinWait.SpinUntil(() => Moves.IsOn(conn, fleet.B), 5_000), Moves.Describe(conn));
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        }, skip);
    }

    private static void RegisterHolds(Runner runner)
    {
        // Two ways a recv can end ahead of its cancel, in the same batch of completions: each ends the wait for the cancel.
        foreach ((string how, Action<Reactor, TcpConnection> end) in new (string, Action<Reactor, TcpConnection>)[]
        {
            ("for want of a buffer", (reactor, conn) => OnTcpRecvCompletionShared(reactor, Moves.SlotOf(conn), (ushort)Moves.TagGenOf(conn), -ENOBUFS, 0)),
            ("by itself", (reactor, conn) => OnRecvEnded(reactor, conn, (ushort)Moves.TagGenOf(conn), 1)),
        })
        {
            runner.Test($"move: a connection whose recv ends {how} before its cancel goes without it", () =>
            {
                using var fleet = new MoveFleet(2, MoveFleet.Tell);
                (Socket client, TcpConnection conn) = fleet.Connect();
                Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
                Moves.OnItsReactor(conn, reactor =>
                {
                    Assert.True(Moves.StartMove(reactor, conn, fleet.B), "the move was refused");
                    end(reactor, conn);
                    Assert.True(Moves.StateOf(conn) != Moves.Cancelling, "it still waits for the cancel");
                });
                Assert.True(SpinWait.SpinUntil(() => Moves.IsOn(conn, fleet.B), 5_000), Moves.Describe(conn));
                Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
            });
        }

        runner.Test("move: a connection whose recv waits for a buffer stays until it has one", () =>
        {
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                var held = new List<SpscRecvRing.Item>();
                byte first = 0;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    first = item.AsSpan()[0];
                    held.Add(item);
                }
                if (first == (byte)'h')
                {
                    holding.SetResult();
                    await release.Task.ConfigureAwait(false);
                }
                foreach (SpscRecvRing.Item item in held)
                {
                    conn.ReturnBuffer(in item);
                }
                await MoveFleet.Home(conn);
                if (first is not (0 or (byte)'h'))
                {
                    conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{(char)first}"));
                    await conn.FlushAsync();
                }
                await MoveFleet.Tell(conn);
            }, MoveFleet.Shared() with { RecvSlots = 1 });

            (Socket holder, TcpConnection _) = fleet.Connect();
            (Socket client, TcpConnection conn) = fleet.Connect();
            holder.Send("hold"u8);   // the only buffer reactor A has
            Assert.True(holding.Task.Wait(5_000), "the buffer was never held");
            client.Send("x"u8);
            bool starved = false;
            for (int i = 0; i < 500 && !starved; i++)
            {
                Moves.On(fleet.A, () => starved = StarvedOn(fleet.A).Count == 1);
            }
            Assert.True(starved, "its recv never went without a buffer, so this proved nothing");
            Assert.True(!Moves.Begin(conn, fleet.B) && Moves.StateOf(conn) == Moves.None, "the move of a connection without a recv began");

            release.SetResult();
            Assert.Equal("0x", MoveFleet.Receive(client, 2));
            Moves.To(conn, fleet.B);
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        });

        runner.Test("move: a connection that holds a part of a message in its reactor's buffers stays", () =>
        {
            using var fleet = new MoveFleet(2, TellTens);
            (Socket client, TcpConnection conn) = fleet.Connect();

            client.Send("01234"u8);
            Assert.True(SpinWait.SpinUntil(() => Moves.ReadParkedOf(conn) && !Moves.HoldsNothingOf(conn), 5_000), "the handler never got to wait for the rest");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.None);   // at once: the rest of it can only come where its first part is

            client.Send("56789"u8);
            Assert.Equal("00123456789", MoveFleet.Receive(client, 11));
            Assert.Equal(0L, fleet.A.ConnectionsGiven);

            Moves.To(conn, fleet.B);   // whole messages only: it holds nothing now
            Assert.Equal("1abcdefghij", MoveFleet.Exchange(client, "abcdefghij"));
        });

        runner.Test("move: buffers handed back from another thread count as handed back", () =>
        {
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    while (true)
                    {
                        RecvSnapshot snapshot = await conn.ReadAsync();
                        UnmanagedMemoryManager[] memories = conn.GetSnapshotMemories(snapshot);
                        string got = string.Concat(memories.Select(m => Encoding.ASCII.GetString(m.GetSpan())));
                        await Task.Run(() => conn.ReturnBuffers(memories)).ConfigureAwait(false);
                        await MoveFleet.Home(conn);
                        if (got.Length > 0)
                        {
                            conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
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
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            for (int i = 0; i < 50; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 2]);
                Assert.Equal($"{i % 2}hello", MoveFleet.Exchange(client, "hello"));
            }
        });

        runner.Test("move: a pinned connection stays, and goes once it is unpinned", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell);
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));

            conn.Pinned = true;
            Assert.True(!Moves.Begin(conn, fleet.B), "a pinned connection began to move");
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));

            conn.Pinned = false;
            Moves.To(conn, fleet.B);
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        });

        runner.Test("move: a connection pinned by its handler while it moves stays", () =>
        {
            var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        if (got == "pin")
                        {
                            atWork.TrySetResult();
                            await gate.Task.ConfigureAwait(false);
                            await MoveFleet.Home(conn);
                            conn.Pinned = true;
                        }
                        conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("pin"u8);
            Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            gate.SetResult();
            Assert.Equal("0pin", MoveFleet.Receive(client, 4));
            Assert.Equal("0next", MoveFleet.Exchange(client, "next"));
            Assert.True(Moves.IsOn(conn, fleet.A), Moves.Describe(conn));
        });

        runner.Test("move: a connection with a file read in flight waits for it", () =>
        {
            using var pipe = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None);
            var reading = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    if (await MoveFleet.ReadText(conn) != "go")
                    {
                        return;
                    }
                    ValueTask<RecvSnapshot> read = conn.ReadAsync();   // the connection's, waiting as the file's does
                    ValueTask<int> file = conn.ReadFileAsync((int)pipe.ClientSafePipeHandle.DangerousGetHandle(), 16, 0);
                    reading.SetResult();
                    conn.AdvanceWrite(await file);
                    conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}"));
                    await conn.FlushAsync();
                    await read;
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("go"u8);
            Assert.True(reading.Task.Wait(5_000), "the handler never got to read");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            Thread.Sleep(50);
            Assert.True(Moves.StateOf(conn) == Moves.Waiting, $"it went with a file read in flight: {Moves.Describe(conn)}");

            pipe.Write("file"u8);
            Assert.Equal("file0", MoveFleet.Receive(client, 5));
            Assert.True(SpinWait.SpinUntil(() => Moves.IsOn(conn, fleet.B), 5_000), $"it never went: {Moves.Describe(conn)}");
            client.Send("bye"u8);
            MoveFleet.AwaitLive(fleet.A, 0);
        });

        runner.Test("move: a connection that is over stays to end", () =>
        {
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var fleet = new MoveFleet(2, async conn =>
            {
                string got = await MoveFleet.ReadText(conn);
                conn.DecRef();   // with the peer still there
                if (got.Length > 0)
                {
                    await release.Task;
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("bye"u8);
            Assert.Equal(0, client.Receive(new byte[1]));
            Assert.True(!Moves.Begin(conn, fleet.B), "a connection its handler had let go of began to move");
            client.Dispose();
            MoveFleet.AwaitLive(fleet.A, 0);
            release.SetResult();
        });
    }

    private static void RegisterSends(Runner runner)
    {
        foreach ((string name, TcpOptions tcp) in new[]
        {
            ("one slab", new TcpOptions { WriteSlabSize = 4096, PoolMax = 64 }),
            ("segments", new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, WriteOverflow = WriteOverflowStrategy.Segmented }),
            ("zero-copy", new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, ZeroCopySend = true }),
            ("short sends", new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, SendWaitAll = false }),
        })
        {
            runner.Test($"move: a connection with a send in flight waits for it, and whoever waits for the flush resumes on the next reactor ({name})", () =>
            {
                const int Big = 8 * 1024 * 1024;   // more than both sockets hold
                var flushing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var fleet = new MoveFleet(2, async conn =>
                {
                    try
                    {
                        if (await MoveFleet.ReadText(conn) != "go")
                        {
                            return;
                        }
                        ValueTask<RecvSnapshot> read = conn.ReadAsync();   // waits beside the flush
                        conn.Write(Pattern(Big));
                        ValueTask flush = conn.FlushAsync();
                        flushing.SetResult();
                        await flush;
                        int flushed = Reactor.Current!.ShardIndex;
                        RecvSnapshot snapshot = await read;
                        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                        {
                            conn.ReturnBuffer(in item);
                        }
                        conn.Write(Encoding.ASCII.GetBytes($"{flushed}{Reactor.Current!.ShardIndex}"));
                        await conn.FlushAsync();
                        await MoveFleet.ReadText(conn);
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, MoveFleet.Shared(tcp));

                (Socket client, TcpConnection conn) = fleet.Connect();
                client.Send("go"u8);
                Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");
                Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
                Moves.WaitFor(conn, Moves.Waiting);
                Thread.Sleep(50);
                Assert.True(Moves.StateOf(conn) == Moves.Waiting && Moves.FlushOutstandingOf(conn), $"it went, or the send ended, with the client not reading: {Moves.Describe(conn)}");

                AssertPattern(client, Big);
                client.Send("read"u8);
                Assert.Equal("11", MoveFleet.Receive(client, 2));
                Assert.Equal(1L, fleet.B.ConnectionsTaken);
            }, skip: tcp.ZeroCopySend && !TestServer.KernelAtLeast(6, 0));
        }

        runner.Test("move: a flush that is never waited for doesn't hold its connection, and is whole", () =>
        {
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                        _ = conn.FlushAsync();   // and back to the read
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            for (int i = 0; i < 100; i++)
            {
                client.Send("hello"u8);
                Moves.Begin(conn, fleet.Reactors[i % 2]);
                Assert.Equal("hello", MoveFleet.Receive(client, 6)[1..]);
            }
            Assert.True(fleet.A.ConnectionsGiven + fleet.B.ConnectionsGiven > 0, "it never moved");
        });
    }

    private static void RegisterAdapters(Runner runner)
    {
        foreach ((string name, Func<TcpConnection, Task> handle) in new (string, Func<TcpConnection, Task>)[]
        {
            ("pipes", TellTens),
            ("a stream", TellTensStream),
        })
        {
            runner.Test($"move: a handler reading and writing through {name} goes along", () =>
            {
                using var fleet = new MoveFleet(2, handle);
                (Socket client, TcpConnection conn) = fleet.Connect();
                for (int i = 0; i < 40; i++)
                {
                    Moves.To(conn, fleet.Reactors[i % 2]);
                    Assert.Equal($"{i % 2}message {i:D2}", MoveFleet.Exchange(client, $"message {i:D2}"));
                }
            });
        }

        runner.Test("move: a pipe made before the move is the connection's after it, and not its next life's", () =>
        {
            var pipes = new System.Collections.Concurrent.ConcurrentQueue<(TcpConnection Conn, TcpConnectionDualPipe Pipe)>();
            using var fleet = new MoveFleet(2, async conn =>
            {
                pipes.Enqueue((conn, new TcpConnectionDualPipe(conn)));
                await MoveFleet.Tell(conn);
            }, MoveFleet.Shared(new TcpOptions { WriteSlabSize = 4096, PoolMax = 64 }));

            (Socket first, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(first, "hello"));
            TcpConnectionDualPipe pipe = pipes.Last(p => ReferenceEquals(p.Conn, conn)).Pipe;
            Assert.True(ReferenceEquals(conn, pipe.Connection), "a pipe's Connection is not the one it was made over");
            Moves.To(conn, fleet.B);
            Assert.Equal("1hello", MoveFleet.Exchange(first, "hello"));
            Assert.True(pipe.IsValid(), "a pipe was invalidated by a move");

            // Over, on the reactor it moved to, and back from that one's pool for a client of its own. Both reactors count
            // their connections from the same number, so a life numbered by its reactor could come out like the last one.
            first.Dispose();
            MoveFleet.AwaitLive(fleet.B, 0);
            Assert.True(!pipe.IsValid(), "a pipe outlived its connection");
            for (int i = 0; i < 20; i++)
            {
                (Socket next, TcpConnection again) = fleet.Connect(fleet.B);
                Assert.Equal("1again", MoveFleet.Exchange(next, "again"));
                Assert.True(!pipe.IsValid(), "a pipe of the life before was the next one's");
                next.Dispose();
                MoveFleet.AwaitLive(fleet.B, 0);
            }
            Assert.True(pipes.Count(p => ReferenceEquals(p.Conn, conn)) > 1, "the connection was never reused, so this proved nothing");
        });
    }

    private static void RegisterThreads(Runner runner)
    {
        runner.Test("move: a switch to the connection's reactor lands where the connection is by then", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell);
            (Socket client, TcpConnection conn) = fleet.Connect();

            Task<Reactor?> landed;
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                landed = Task.Run(async () =>
                {
                    await MoveFleet.Home(conn);
                    return Reactor.Current;
                });
                Assert.True(!landed.Wait(100), "a switch landed with the connection between two reactors");
            }
            Assert.True(landed.Wait(5_000) && ReferenceEquals(landed.Result, fleet.B), "it landed elsewhere");
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        });

        runner.Test("move: on its old reactor, a connection given away is off the reactor, at once", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell);
            (Socket _, TcpConnection conn) = fleet.Connect();
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                Moves.On(fleet.A, () => Assert.True(ReferenceEquals(conn.Reactor, fleet.B) && !conn.Reactor.OnReactorThread,
                    "the reactor it left still took it for its own"));
            }
        });

        runner.Test("move: a handler that goes on from its old reactor's timer is off the reactor, and its flush is sent", () =>
        {
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    Reactor accepted = Reactor.Current!;
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        await new RingTimer(accepted).DelayAsync(1);   // resumes there
                        conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            Moves.To(conn, fleet.B);
            for (int i = 0; i < 20; i++)
            {
                Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            }
            Assert.True(Moves.IsOn(conn, fleet.B), Moves.Describe(conn));
        });

        runner.Test("move: a handler that works on the thread pool goes along with its connection", () =>
        {
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
                    {
                        int index = conn.Reactor.ShardIndex;
                        await Task.Yield();
                        await Task.Delay(1).ConfigureAwait(false);
                        conn.Write(Encoding.ASCII.GetBytes($"{index}{got}"));
                        await conn.FlushAsync().ConfigureAwait(false);
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            for (int i = 0; i < 30; i++)
            {
                Moves.To(conn, fleet.Reactors[i % 2]);
                Assert.Equal($"{i % 2}hello", MoveFleet.Exchange(client, "hello"));
            }
        });
    }

    // Answers as MoveFleet.Tell does, but works for as long as the gate is shut on the first delivery.
    private static async Task WorkOnce(TcpConnection conn, TaskCompletionSource atWork, Task gate)
    {
        try
        {
            for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
            {
                atWork.TrySetResult();
                await gate.ConfigureAwait(false);
                await MoveFleet.Home(conn);
                conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Messages of ten bytes, read whole from a pipe, which holds what it has of one.
    private static async Task TellTens(TcpConnection conn)
    {
        var pipe = new TcpConnectionDualPipe(conn);
        try
        {
            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();
                System.Buffers.ReadOnlySequence<byte> buffer = read.Buffer;
                while (buffer.Length >= 10)
                {
                    System.Buffers.BuffersExtensions.Write(pipe.Output, Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{Encoding.ASCII.GetString(buffer.Slice(0, 10))}"));
                    buffer = buffer.Slice(10);
                }
                pipe.Input.AdvanceTo(buffer.Start, buffer.End);
                await pipe.Output.FlushAsync();
                if (read.IsCompleted)
                {
                    return;
                }
            }
        }
        finally
        {
            pipe.Input.Complete();
            conn.DecRef();
        }
    }

    private static async Task TellTensStream(TcpConnection conn)
    {
        var stream = new TcpConnectionStream(conn);
        var message = new byte[10];
        try
        {
            while (true)
            {
                int got = 0;
                while (got < message.Length)
                {
                    int n = await stream.ReadAsync(message.AsMemory(got));
                    if (n == 0)
                    {
                        return;
                    }
                    got += n;
                }
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{Encoding.ASCII.GetString(message)}"));
            }
        }
        finally
        {
            stream.Dispose();
            conn.DecRef();
        }
    }

    // A handful of buffers: one lost per move, and the reactor would soon have none.
    private static ServerConfig Small(ServerConfig config) => config with
    {
        RecvSlots = 4,
        RecvBufferSize = 256,
        Incremental = config.Incremental is { } incremental ? incremental with { MaxConnections = 8, RecvSlots = 2, RecvBufferSize = 64 } : null,
    };

    private static byte[] Pattern(int length)
    {
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(i * 31 + (i >> 11));
        }
        return bytes;
    }

    private static void AssertPattern(Socket client, int length)
    {
        byte[] expected = Pattern(length);
        var buffer = new byte[64 * 1024];
        for (int got = 0; got < length;)
        {
            int n = client.Receive(buffer, 0, Math.Min(buffer.Length, length - got), SocketFlags.None);
            Assert.True(n > 0, $"closed after {got} of {length} bytes");
            Assert.True(buffer.AsSpan(0, n).SequenceEqual(expected.AsSpan(got, n)), $"wrong bytes between {got} and {got + n}");
            got += n;
        }
    }

    private const int ENOBUFS = 105;

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "OnTcpRecvCompletionShared")]
    private static extern void OnTcpRecvCompletionShared(Reactor reactor, int slot, ushort gen, int res, uint flags);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "OnRecvEnded")]
    private static extern void OnRecvEnded(Reactor reactor, TcpConnection conn, ushort gen, ushort bgid);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_recvStarved")]
    private static extern ref List<ulong> StarvedOn(Reactor reactor);

    private static long Queued(TcpConnection conn) => QueueOf(conn).SnapshotTail() - TakenOf(QueueOf(conn));

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_recv")]
    private static extern ref SpscRecvRing QueueOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_TakenCount")]
    private static extern long TakenOf(SpscRecvRing ring);
}
