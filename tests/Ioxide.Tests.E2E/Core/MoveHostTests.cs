using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.timer;
using ioxide.utils;
using Microsoft.Win32.SafeHandles;

namespace Ioxide.Tests;

/// <summary>
/// A connection's host (<see cref="TcpConnection.RingHost"/>): what is switched to, posted or submitted through it goes to
/// the reactor serving the connection then, wherever it was moved: while it is between two, from the reactor that gave
/// it away, across two hand-overs, one sent back home, and past a reactor that stopped while the connection was on its
/// way from it. Once the connection's reactor has stopped, a switch or a yield throws and a post is dropped, as they do
/// to that reactor. Without Rebalance it is the reactor itself.
/// </summary>
internal static class MoveHostTests
{
    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            RegisterAfterAMove(runner, mode, config, skip);
            RegisterOnTheWay(runner, mode, config, skip);
            RegisterOrder(runner, mode, config, skip);
            RegisterStops(runner, mode, config, skip);
            RegisterWithoutRebalance(runner, mode, config, skip);
            RegisterShuffled(runner, mode, config, skip);
        }
        RegisterSentBack(runner);
    }

    private static void RegisterAfterAMove(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move host: a switch to it from the thread pool lands on the reactor the connection was moved to ({mode})", () =>
        {
            Assert.Equal("1", OnceMoved(config, async host =>
            {
                await new ReactorSwitch(host);
                return $"{Reactor.Current?.ShardIndex}";
            }));
        }, skip);

        runner.Test($"move host: a timer through it fires on the reactor the connection was moved to ({mode})", () =>
        {
            Assert.Equal("1", OnceMoved(config, async host =>
            {
                await new RingTimer(host).DelayAsync(1);
                return $"{Reactor.Current?.ShardIndex}";
            }));
        }, skip);

        runner.Test($"move host: each kind of operation submitted through it completes on the reactor the connection was moved to ({mode})", () =>
        {
            Assert.Equal("timeout 1, write 9 1, read 1 hostwrite, connect 0 1, send 5 1 there, recv 1 back", OnceMoved(config, SubmitAll));
        }, skip);
    }

    private static void RegisterOnTheWay(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move host: what is posted through it while the connection is between two reactors runs on the second, once that has it ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            AwaitParked(conn);

            string ranOn = "nowhere";
            using var ran = new ManualResetEventSlim();
            using (Moves.Hold(fleet.B))   // what is given to B stays in transit
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                conn.RingHost.ScheduleOnReactor(_ =>
                {
                    ranOn = $"reactor {Reactor.Current?.ShardIndex}, taken {fleet.B.ConnectionsTaken}, the connection's {ReferenceEquals(conn.Reactor, fleet.B)}";
                    ran.Set();
                }, null);
                Assert.True(!ran.Wait(200), $"it ran while the connection was between two: on {ranOn}");
            }

            Assert.True(ran.Wait(5_000), "it never ran");
            Assert.Equal("reactor 1, taken 1, the connection's True", ranOn);
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        }, skip);

        runner.Test($"move host: to the reactor that gave the connection away it is the other one, and a switch made there lands there once that one has it ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            (Socket other, _) = fleet.Connect();   // another of A's
            AwaitParked(conn);

            bool here = true;
            Task<string>? landed = null;
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                Moves.On(fleet.A, () =>   // returns: the switch made there doesn't keep the giver
                {
                    here = conn.RingHost.OnReactorThread;
                    landed = SwitchedTo(conn.RingHost, conn);
                });
                Assert.True(!here, "to the reactor that gave it away, the connection is still its own");
                Assert.Equal("0hi", MoveFleet.Exchange(other, "hi"));   // A goes on serving, the switch made there waiting
                Assert.True(!landed!.Wait(200), "the switch landed before the other reactor had the connection");
            }

            Assert.True(landed!.Wait(5_000), "the switch never landed");
            Assert.Equal("1 True", landed.Result);
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        }, skip);

        runner.Test($"move host: what is posted through it before two hand-overs runs on the reactor that has the connection after them ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            AwaitParked(conn);

            string ranOn = "nowhere";
            using var ran = new ManualResetEventSlim();
            Moves.Held a;
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                a = Moves.Hold(fleet.A);   // what this thread posts goes to A, which gave the connection away, and waits there
                conn.RingHost.ScheduleOnReactor(_ =>
                {
                    ranOn = $"reactor {Reactor.Current?.ShardIndex}, taken back {fleet.A.ConnectionsTaken}";
                    ran.Set();
                }, null);
            }

            using (a)
            {
                Assert.True(SpinWait.SpinUntil(() => Moves.IsOn(conn, fleet.B), 5_000), Moves.Describe(conn));
                AwaitParked(conn);
                Assert.True(Moves.Begin(conn, fleet.A), "the move back was refused");
                Moves.WaitFor(conn, Moves.Given);
                Assert.True(!ran.IsSet, $"it ran before the connection was back: on {ranOn}");
            }

            Assert.True(ran.Wait(5_000), "it never ran");
            Assert.Equal("reactor 0, taken back 1", ranOn);
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
        }, skip);

        runner.Test($"move host: what is posted through it as the connection leaves one reactor runs on the third it gets to ({mode})", () =>
        {
            using var fleet = new MoveFleet(3, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            AwaitParked(conn);

            string ranOn = "nowhere";
            using var ran = new ManualResetEventSlim();
            Moves.Held a;
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                a = Moves.Hold(fleet.A);
                conn.RingHost.ScheduleOnReactor(_ =>
                {
                    ranOn = $"reactor {Reactor.Current?.ShardIndex}, the connection's {ReferenceEquals(conn.Reactor, Reactor.Current)}";
                    ran.Set();
                }, null);
            }

            using (a)
            {
                Assert.True(SpinWait.SpinUntil(() => Moves.IsOn(conn, fleet.B), 5_000), Moves.Describe(conn));
                AwaitParked(conn);
                Moves.To(conn, fleet.Reactors[2]);
                Assert.True(!ran.IsSet, $"it ran before the giver had looked at it: on {ranOn}");
            }

            Assert.True(ran.Wait(5_000), "it never ran");
            Assert.Equal("reactor 2, the connection's True", ranOn);
            Assert.Equal("2hello", MoveFleet.Exchange(client, "hello"));
        }, skip);

        runner.Test($"move host: what goes through it while the connection is on its way from a reactor that stops to one that doesn't gets to the second ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (Socket client, TcpConnection conn) = fleet.Connect();
            AwaitParked(conn);

            Task<string> switched;
            string posted = "nowhere";
            using var ran = new ManualResetEventSlim();
            using (Moves.Hold(fleet.B))
            {
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                fleet.A.Stop();
                Assert.True(fleet.Threads[0].Join(10_000), "the stop never ended");   // past its wait for what it gave away

                switched = Task.Run(() => SwitchedTo(conn.RingHost, conn));
                conn.RingHost.ScheduleOnReactor(_ =>
                {
                    posted = $"{Reactor.Current?.ShardIndex}";
                    ran.Set();
                }, null);
                Assert.True(!ran.Wait(200) && !switched.Wait(200), "it ran before the second reactor had the connection");
            }

            Assert.True(switched.Wait(5_000) && ran.Wait(5_000), "it never got to the second reactor");
            Assert.Equal("1 True 1", $"{switched.Result} {posted}");
            Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
        }, skip);
    }

    // Posting through it never runs what is posted at once, not even on the connection's own reactor, and a yield
    // through it comes back behind what was posted before it.
    private static void RegisterOrder(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        foreach (bool moves in new[] { true, false })
        {
            runner.Test($"move host: a yield through it comes back after the turn it was made in, behind what was posted before it ({mode}, {Rebalance(moves)})", () =>
            {
                using var fleet = new MoveFleet(2, MoveFleet.Tell, config(), moves: moves);
                (_, TcpConnection conn) = fleet.Connect();
                var order = new ConcurrentQueue<string>();
                Task? yielding = null;
                Moves.On(fleet.A, () =>
                {
                    conn.RingHost.ScheduleOnReactor(_ => order.Enqueue("posted"), null);
                    yielding = YieldThenSay(conn.RingHost, order);
                    order.Enqueue("returned");
                });
                Assert.True(yielding!.Wait(5_000), "the yield never came back");
                Assert.Equal("returned, posted, yielded", string.Join(", ", order));
            }, skip);
        }
    }

    private static void RegisterStops(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        foreach (bool moves in new[] { true, false })
        {
            runner.Test($"move host: a switch to it once the connection's reactor has stopped throws rather than waits ({mode}, {Rebalance(moves)})", () =>
            {
                var outcomes = new ConcurrentDictionary<TcpConnection, Task<string>>();   // the kernel's other picks too
                using var stopped = new ManualResetEventSlim();
                using var fleet = new MoveFleet(2, async conn =>
                {
                    try
                    {
                        IRingHost host = conn.RingHost;
                        outcomes[conn] = Task.Run(async () =>
                        {
                            stopped.Wait(10_000);
                            try
                            {
                                await new ReactorSwitch(host);
                                return "landed";
                            }
                            catch (ObjectDisposedException)
                            {
                                return "stopped";
                            }
                        });
                        await MoveFleet.ReadText(conn);
                    }
                    finally
                    {
                        conn.DecRef();
                    }
                }, config(), moves: moves);

                (_, TcpConnection conn) = fleet.Connect();
                Task<string>? outcome = null;
                Assert.True(SpinWait.SpinUntil(() => outcomes.TryGetValue(conn, out outcome), 5_000), "the handler never began");
                fleet.A.Stop();
                Assert.True(fleet.Threads[0].Join(10_000), "the stop never ended");
                stopped.Set();

                Assert.True(outcome!.Wait(5_000), "the switch is still waiting on a reactor that stopped");
                Assert.Equal("stopped", outcome.Result);
            }, skip);

            runner.Test($"move host: a yield through it once the connection's reactor has stopped throws rather than waits ({mode}, {Rebalance(moves)})", () =>
            {
                using var fleet = new MoveFleet(2, MoveFleet.Tell, config(), moves: moves);
                (_, TcpConnection conn) = fleet.Connect();
                fleet.A.Stop();
                Assert.True(fleet.Threads[0].Join(10_000), "the stop never ended");

                Task<string> outcome = Task.Run(async () =>
                {
                    try
                    {
                        await ReactorSwitch.Yield(conn.RingHost);
                        return "came back";
                    }
                    catch (ObjectDisposedException)
                    {
                        return "stopped";
                    }
                });
                Assert.True(outcome.Wait(5_000), "the yield is still waiting on a reactor that stopped");
                Assert.Equal("stopped", outcome.Result);
            }, skip);

            runner.Test($"move host: a post through it once the connection's reactor has stopped is dropped, and let go of, as one to that reactor is ({mode}, {Rebalance(moves)})", () =>
            {
                using var fleet = new MoveFleet(2, MoveFleet.Tell, config(), moves: moves);
                (_, TcpConnection conn) = fleet.Connect();
                fleet.A.Stop();
                Assert.True(fleet.Threads[0].Join(10_000), "the stop never ended");

                using var ran = new ManualResetEventSlim();
                WeakReference posted = PostHolding(conn.RingHost, ran);
                Assert.True(!ran.Wait(300), "a post to a reactor that stopped ran");
                Assert.True(Collected(posted), "a post to a reactor that stopped is still held, as one that goes on and on would be");
            }, skip);
        }

        runner.Test($"move host: a switch through it that isn't on the connection's reactor when it ends throws ({mode})", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
            (_, TcpConnection conn) = fleet.Connect();
            Assert.Throws<ObjectDisposedException>(() => new ReactorSwitch(conn.RingHost).GetResult(), "stopped");   // a switch that never landed
            Assert.Throws<ObjectDisposedException>(() => ReactorSwitch.Yield(conn.RingHost).GetResult(), "stopped");   // a yield that never came back
        }, skip);
    }

    private static void RegisterWithoutRebalance(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move host: without Rebalance it is the reactor the connection was accepted on itself ({mode})", () =>
        {
            var outcomes = new ConcurrentDictionary<TcpConnection, Task<string>>();
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    IRingHost host = conn.RingHost;
                    outcomes[conn] = Task.Run(async () =>
                    {
                        await new ReactorSwitch(host);
                        int switched = Reactor.Current?.ShardIndex ?? -1;
                        var posted = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
                        host.ScheduleOnReactor(_ => posted.SetResult(Reactor.Current?.ShardIndex ?? -1), null);
                        return $"{switched} {await posted.Task} {host.OnReactorThread}";
                    });
                    await MoveFleet.ReadText(conn);
                }
                finally
                {
                    conn.DecRef();
                }
            }, config(), moves: false);

            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.True(ReferenceEquals(conn.RingHost, fleet.A), "the host of a connection that can't move isn't its reactor");
            Task<string>? outcome = null;
            Assert.True(SpinWait.SpinUntil(() => outcomes.TryGetValue(conn, out outcome), 5_000), "the handler never began");
            Assert.True(outcome!.Wait(5_000), "the switch never landed");
            Assert.Equal("0 0 False", outcome.Result);   // its reactor's, from the thread pool where the last is asked
            client.Dispose();
        }, skip);
    }

    // Connections moved all the time (Moves.Shuffle) while their handlers, with a read waiting, switch to the host from the
    // thread pool and post through it: each switch lands on the connection's reactor, each post runs there, once.
    private static void RegisterShuffled(Runner runner, string mode, Func<ServerConfig> config, bool skip)
    {
        runner.Test($"move host: connections moved all the time: what is switched and posted through it gets to each one's reactor, every post once ({mode})", () =>
        {
            const int Clients = 6, Rounds = 150;
            long posted = 0, ran = 0, wrong = 0;
            using var fleet = new MoveFleet(3, async conn =>
            {
                try
                {
                    IRingHost host = conn.RingHost;
                    ValueTask<RecvSnapshot> reading = conn.ReadAsync();
                    while (true)
                    {
                        RecvSnapshot snapshot = await reading;
                        string got = Take(conn, snapshot);
                        if (snapshot.IsClosed)
                        {
                            return;
                        }
                        reading = conn.ReadAsync();   // waits beside what follows, so the connection can move meanwhile
                        if (got.Length == 0)
                        {
                            continue;
                        }

                        await Task.Run(async () =>
                        {
                            for (int k = 0; k < 3; k++)
                            {
                                await new ReactorSwitch(host);
                                if (!conn.Reactor.OnReactorThread)
                                {
                                    Interlocked.Increment(ref wrong);
                                }
                                Interlocked.Increment(ref posted);
                                host.ScheduleOnReactor(_ =>
                                {
                                    if (!conn.Reactor.OnReactorThread)
                                    {
                                        Interlocked.Increment(ref wrong);
                                    }
                                    Interlocked.Increment(ref ran);
                                }, null);
                                await Task.Yield();
                            }
                        });

                        await new ReactorSwitch(host);
                        conn.Write(Encoding.ASCII.GetBytes(got));
                        await conn.FlushAsync();
                    }
                }
                catch (ObjectDisposedException)
                {
                    // the fleet's stop, past the test
                }
                finally
                {
                    conn.DecRef();
                }
            }, config());

            var clients = new Thread[Clients];
            var failures = new ConcurrentQueue<string>();
            using (new Moves.Shuffle(fleet.Reactors))
            {
                for (int c = 0; c < Clients; c++)
                {
                    int index = c;
                    clients[c] = new Thread(() =>
                    {
                        try
                        {
                            using Socket client = Moves.Connect(fleet.Port);
                            for (int r = 0; r < Rounds; r++)
                            {
                                string message = $"{index:D2}-{r:D4}";
                                client.Send(Encoding.ASCII.GetBytes(message));
                                string echoed = MoveFleet.Receive(client, message.Length);
                                if (echoed != message)
                                {
                                    failures.Enqueue($"client {index} round {r}: {echoed}");
                                    return;
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            failures.Enqueue($"client {index}: {e.Message}");
                        }
                    }) { IsBackground = true };
                    clients[c].Start();
                }
                foreach (Thread client in clients)
                {
                    Assert.True(client.Join(60_000), "a client never finished");
                }
            }

            Assert.True(failures.IsEmpty, string.Join("; ", failures));
            Assert.True(SpinWait.SpinUntil(() => Interlocked.Read(ref ran) == Interlocked.Read(ref posted), 5_000),
                $"{Interlocked.Read(ref ran)} of {Interlocked.Read(ref posted)} posts ran");
            Assert.Equal(0L, Interlocked.Read(ref wrong));
            Assert.True(fleet.Reactors.Sum(r => r.ConnectionsGiven) > Clients, "the connections were hardly moved, so this proves little");
        }, skip);
    }

    // Incremental mode, the taker without locked memory for the connection's ring: it goes home. What was posted and
    // switched through its host and queued at home ahead of its return runs at home once it is back, whether the taker
    // goes on or stops meanwhile.
    private static void RegisterSentBack(Runner runner)
    {
        bool cannot = !TestServer.KernelAtLeast(6, 12) || !LockedMemory.CanRunOut;
        foreach (bool stops in new[] { false, true })
        {
            runner.Test($"move host: what went through it ahead of the connection's return home runs at home once it is back ({(stops ? "the reactor that sent it back stops" : "the reactor that sent it back goes on")})", () =>
            {
                using var fleet = new MoveFleet(2, MoveFleet.Tell, MoveFleet.Incremental(room: 4));
                (Socket client, TcpConnection conn) = fleet.Connect();
                Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
                MoveFleet.AwaitLive(fleet.B, 0);

                string ranOn = "nowhere", landed = "nowhere";
                using var ran = new ManualResetEventSlim();
                using var switched = new ManualResetEventSlim();
                Moves.Held b = Moves.Hold(fleet.B);
                Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                Moves.WaitFor(conn, Moves.Given);
                Moves.Held a = Moves.Hold(fleet.A);   // what this thread sends goes to A, and waits there ahead of the return
                conn.RingHost.ScheduleOnReactor(_ =>
                {
                    ranOn = $"reactor {Reactor.Current?.ShardIndex}, taken back {fleet.A.ConnectionsTaken}";
                    ran.Set();
                }, null);
                var awaiter = new ReactorSwitch(conn.RingHost);
                awaiter.UnsafeOnCompleted(() =>
                {
                    try
                    {
                        awaiter.GetResult();
                        landed = $"reactor {Reactor.Current?.ShardIndex}";
                    }
                    catch (ObjectDisposedException)
                    {
                        landed = "threw";
                    }
                    switched.Set();
                });

                using (LockedMemory.None())
                {
                    b.Dispose();
                    Moves.On(fleet.B, static () => { });   // past its arrival there: sent home
                }
                if (stops)
                {
                    fleet.B.Stop();
                    Assert.True(fleet.Threads[1].Join(10_000), "the stop never ended");
                }
                Assert.True(!ran.IsSet && !switched.IsSet, "it ran before the connection was back home");
                a.Dispose();

                Assert.True(ran.Wait(5_000) && switched.Wait(5_000), $"it never ran: {Moves.Describe(conn)}");
                Assert.Equal("reactor 0, taken back 1 / reactor 0", $"{ranOn} / {landed}");
                Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            }, cannot);
        }
    }

    // A connection whose handler waits in a read, and meanwhile, on the thread pool, does what it is given with the
    // connection's host once the connection has been moved to the second reactor: what that returns.
    private static string OnceMoved(Func<ServerConfig> config, Func<IRingHost, Task<string>> body)
    {
        using var moved = new ManualResetEventSlim();
        Task<string>? outcome = null;
        using var fleet = new MoveFleet(2, async conn =>
        {
            try
            {
                if (await MoveFleet.ReadText(conn) != "go")
                {
                    return;
                }
                ValueTask<RecvSnapshot> read = conn.ReadAsync();   // the connection can move while this waits
                IRingHost host = conn.RingHost;
                outcome = Task.Run(async () =>
                {
                    moved.Wait(10_000);
                    return await body(host);
                });
                RecvSnapshot snapshot = await read;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    conn.ReturnBuffer(in item);
                }
                await MoveFleet.ReadText(conn);
            }
            finally
            {
                conn.DecRef();
            }
        }, config());

        (Socket client, TcpConnection conn) = fleet.Connect();
        client.Send("go"u8);
        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref outcome) is not null && Moves.ReadParkedOf(conn), 5_000), "the handler never waited in a read");
        Moves.To(conn, fleet.B);
        moved.Set();
        Assert.True(outcome!.Wait(5_000), "what was done through the host never finished");
        client.Send("x"u8);
        return outcome.Result;
    }

    // Each kind of operation through the host, on descriptors of its own (a file, a socket to a listener here): what it
    // came back with, and the reactor it came back on.
    private static async Task<string> SubmitAll(IRingHost host)
    {
        var said = new List<string>();
        var timeout = new Op();
        host.SubmitTimeout(1_000_000, timeout);
        said.Add($"timeout {(await timeout.Done).On}");

        string path = Path.GetTempFileName();
        nint buffer = Marshal.AllocHGlobal(64);
        nint sockaddr = Marshal.AllocHGlobal(16);
        try
        {
            using (SafeFileHandle file = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite))
            {
                int fd = (int)file.DangerousGetHandle();
                Marshal.Copy("hostwrite"u8.ToArray(), 0, buffer, 9);
                var write = new Op();
                host.SubmitWrite(fd, buffer, 9, 0, write);
                (int wrote, int wroteOn) = await write.Done;
                said.Add($"write {wrote} {wroteOn}");
                var read = new Op();
                host.SubmitRead(fd, buffer + 16, 9, 0, read);
                (int got, int readOn) = await read.Done;
                said.Add($"read {readOn} {Text(buffer + 16, got)}");
            }

            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            int sfd = (int)socket.Handle;
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Marshal.Copy(new byte[] { 2, 0, (byte)(port >> 8), (byte)port, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 }, 0, sockaddr, 16);
            Task<Socket> accepting = listener.AcceptSocketAsync();
            var connect = new Op();
            host.SubmitConnect(sfd, sockaddr, 16, connect);
            (int connected, int connectedOn) = await connect.Done;
            said.Add($"connect {connected} {connectedOn}");
            using Socket peer = await accepting;
            peer.ReceiveTimeout = 5_000;

            Marshal.Copy("there"u8.ToArray(), 0, buffer, 5);
            var send = new Op();
            host.SubmitSend(sfd, buffer, 5, send);
            (int sent, int sentOn) = await send.Done;
            said.Add($"send {sent} {sentOn} {MoveFleet.Receive(peer, 5)}");

            var recv = new Op();
            host.SubmitRecv(sfd, buffer, 64, recv);
            peer.Send("back"u8);
            (int n, int recvOn) = await recv.Done;
            said.Add($"recv {recvOn} {Text(buffer, n)}");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(sockaddr);
            File.Delete(path);
        }
        return string.Join(", ", said);
    }

    private static string Text(nint at, int length)
    {
        var bytes = new byte[Math.Max(0, length)];
        Marshal.Copy(at, bytes, 0, bytes.Length);
        return Encoding.ASCII.GetString(bytes);
    }

    // An operation's end: its result, and the reactor it came on.
    private sealed class Op : IRingCompletion
    {
        private readonly TaskCompletionSource<(int Result, int On)> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<(int Result, int On)> Done => _done.Task;

        public void Complete(int result) => _done.TrySetResult((result, Reactor.Current?.ShardIndex ?? -1));
    }

    private static async Task<string> SwitchedTo(IRingHost host, TcpConnection conn)
    {
        await new ReactorSwitch(host);
        return $"{Reactor.Current?.ShardIndex} {conn.Reactor.OnReactorThread}";
    }

    private static async Task YieldThenSay(IRingHost host, ConcurrentQueue<string> order)
    {
        await ReactorSwitch.Yield(host);
        order.Enqueue("yielded");
    }

    // Posts through the host what only the post holds: the reference to it says whether the post is still held later.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference PostHolding(IRingHost host, ManualResetEventSlim ran)
    {
        var held = new object();
        host.ScheduleOnReactor(_ => ran.Set(), held);
        return new WeakReference(held);
    }

    private static bool Collected(WeakReference weak)
    {
        for (int i = 0; i < 20 && weak.IsAlive; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            Thread.Sleep(20);
        }
        return !weak.IsAlive;
    }

    // What a snapshot holds, its buffers handed back.
    private static string Take(TcpConnection conn, RecvSnapshot snapshot)
    {
        var text = new StringBuilder();
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                text.Append(Encoding.ASCII.GetString(item.AsSpan()));
                conn.ReturnBuffer(in item);
            }
        }
        return text.ToString();
    }

    private static void AwaitParked(TcpConnection conn)
        => Assert.True(SpinWait.SpinUntil(() => Moves.ReadParkedOf(conn), 5_000), "the handler never waited in a read");

    private static string Rebalance(bool on) => on ? "Rebalance" : "no Rebalance";
}
