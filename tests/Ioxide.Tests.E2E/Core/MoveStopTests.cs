using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Reactors that stop while connections move between them: a connection is always somebody's, so a stop closes it or
/// another reactor serves it, its handler ends or goes on, and no stop waits for what will never come.
/// </summary>
internal static class MoveStopTests
{
    // Generous against a healthy end, which takes no time at all.
    private const int EndsWithinMs = 5_000;

    public static void Register(Runner runner)
    {
        foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
        {
            runner.Test($"move stop: a connection on its way to a reactor that stops is taken by it and closed ({mode})", () =>
            {
                var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var fleet = new MoveFleet(2, conn => TellAndEnd(conn, ended), config());
                (Socket client, TcpConnection conn) = fleet.Connect();
                Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));

                using (Moves.Hold(fleet.B))
                {
                    Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                    Moves.WaitFor(conn, Moves.Given);
                    fleet.B.Stop();
                }

                Assert.True(ended.Task.Wait(EndsWithinMs), $"the handler never heard of the stop: {Moves.Describe(conn)}");
                AssertClosed(client);
                Assert.True(fleet.Threads[1].Join(EndsWithinMs), "the stop never ended");
                Assert.Equal(0, Moves.LiveOn(fleet.B));
                Assert.Equal(0, ArrivingAt(fleet.B));
                AssertServes(fleet, fleet.A);
            }, skip);

            runner.Test($"move stop: a connection is not given to a reactor that is stopping, and is served on where it is ({mode})", () =>
            {
                var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var fleet = new MoveFleet(2, conn => WorkOnce(conn, atWork, gate.Task), config());
                (Socket client, TcpConnection conn) = fleet.Connect();
                client.Send("work"u8);
                Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
                Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
                Moves.WaitFor(conn, Moves.Waiting);

                fleet.B.Stop();
                Assert.True(fleet.Threads[1].Join(EndsWithinMs), "the stop never ended, with nothing on its way");
                gate.SetResult();
                Assert.Equal("0work", MoveFleet.Receive(client, 5));
                Assert.Equal("0next", MoveFleet.Exchange(client, "next"));
                Assert.Equal(0L, fleet.A.ConnectionsGiven);
                Assert.True(!Moves.Begin(conn, fleet.B), "a move to a stopped reactor began");
                Assert.Equal("0still", MoveFleet.Exchange(client, "still"));
            }, skip);

            runner.Test($"move stop: a connection whose move waits ends with its reactor's stop ({mode})", () =>
            {
                var atWork = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var fleet = new MoveFleet(2, conn => WorkOnce(conn, atWork, gate.Task), config());
                (Socket client, TcpConnection conn) = fleet.Connect();
                client.Send("work"u8);
                Assert.True(atWork.Task.Wait(5_000), "the handler never got to work");
                Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
                Moves.WaitFor(conn, Moves.Waiting);

                fleet.A.Stop();
                AssertClosed(client);
                gate.SetResult();
                Assert.True(fleet.Threads[0].Join(EndsWithinMs), "the stop never ended");
                Assert.Equal(0, Moves.LiveOn(fleet.A));
                if (config().Incremental is { } incremental)
                {
                    Assert.Equal(incremental.MaxConnections, Moves.RoomOn(fleet.B));   // what was reserved there is back
                }
                AssertServes(fleet, fleet.B);
            }, skip);

            runner.Test($"move stop: a connection given away before its old reactor stopped is served on ({mode})", () =>
            {
                using var fleet = new MoveFleet(2, MoveFleet.Tell, config());
                (Socket client, TcpConnection conn) = fleet.Connect();
                using (Moves.Hold(fleet.B))
                {
                    Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
                    Moves.WaitFor(conn, Moves.Given);
                    fleet.A.Stop();
                    Assert.True(fleet.Threads[0].Join(EndsWithinMs), "the stop waited for a connection that had left");
                }
                Assert.Equal("1hello", MoveFleet.Exchange(client, "hello"));
                client.Dispose();
                MoveFleet.AwaitLive(fleet.B, 0);
            }, skip);

            runner.Test($"move stop: reactors that stop while their connections are moved about all end, and so do all handlers ({mode})", () =>
            {
                int handlers = 0;
                using var fleet = new MoveFleet(3, async conn =>
                {
                    Interlocked.Increment(ref handlers);
                    try
                    {
                        await MoveFleet.Tell(conn);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref handlers);
                    }
                }, config());
                Socket[] clients = Enumerable.Range(0, 30).Select(_ => fleet.Connect(fleet.Reactors[Random.Shared.Next(3)]).Client).ToArray();

                using var over = new CancellationTokenSource();
                Task[] talking = clients.Select(client => Task.Run(() =>
                {
                    try
                    {
                        while (!over.IsCancellationRequested)
                        {
                            string answer = MoveFleet.Exchange(client, "8 bytes.");   // which no buffer's end splits
                            Assert.Equal("8 bytes.", answer[1..]);
                        }
                    }
                    catch (SocketException)
                    {
                        // reset by the stop
                    }
                    catch (Exception e) when (e.Message.StartsWith("closed after", StringComparison.Ordinal))
                    {
                        // closed by it
                    }
                })).ToArray();

                using (var shuffle = new Moves.Shuffle(fleet.Reactors))
                {
                    Assert.True(SpinWait.SpinUntil(() => shuffle.Made > 100, 20_000), $"only {shuffle.Made} moves were made");
                    foreach (Reactor reactor in fleet.Reactors)
                    {
                        reactor.Stop();
                        Thread.Sleep(5);
                    }
                    foreach (Thread thread in fleet.Threads)
                    {
                        Assert.True(thread.Join(EndsWithinMs), "a stop never ended");
                    }
                }
                over.Cancel();
                Assert.True(Task.WaitAll(talking, 15_000), "a client was left without an answer or an end");
                Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref handlers) == 0, 5_000), $"{handlers} handlers never ended");
                foreach (Reactor reactor in fleet.Reactors)
                {
                    Assert.Equal(0, Moves.LiveOn(reactor));
                    Assert.Equal(0, ArrivingAt(reactor));
                }
            }, skip);
        }

        // Its giver has been told that the reactor isn't stopping, and is about to post it.
        runner.Test("move stop: a stop waits for a connection that is on its way and not posted yet", () =>
        {
            using var fleet = new MoveFleet(2, MoveFleet.Tell);
            Interlocked.Increment(ref ArrivingField(fleet.B));
            fleet.B.Stop();
            Assert.True(!fleet.Threads[1].Join(300), "the stop ended with a connection on its way");   // it has a second
            Interlocked.Decrement(ref ArrivingField(fleet.B));
            Assert.True(fleet.Threads[1].Join(EndsWithinMs), "the stop never ended");
        });

        // Posted while the stop was closing the others: the giver had asked in time.
        runner.Test("move stop: a connection that arrives once a stop has closed the others is closed too, and let go of", () =>
        {
            var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var closing = new ManualResetEventSlim();
            using var given = new ManualResetEventSlim();
            using var fleet = new MoveFleet(2, conn => TellAndEnd(conn, ended), null, (i, reactor) =>
            {
                if (i == 1)
                {
                    reactor.AddStopper(() =>   // first of all a stop does
                    {
                        StopRequestedOf(reactor) = false;   // as it was when the giver asked
                        closing.Set();
                        given.Wait(10_000);
                        StopRequestedOf(reactor) = true;
                    });
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            fleet.B.Stop();
            Assert.True(closing.Wait(5_000), "the stop never began");
            Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
            Moves.WaitFor(conn, Moves.Given);
            given.Set();

            Assert.True(ended.Task.Wait(EndsWithinMs), "the handler never heard of the stop");
            AssertClosed(client);
            Assert.True(fleet.Threads[1].Join(EndsWithinMs), "the stop never ended");
            Assert.Equal(0, Moves.LiveOn(fleet.B));
            AssertServes(fleet, fleet.A);
        });

        // The loop is over and the reactor has not said so yet: a connection given to it then is never taken.
        runner.Test("move stop: a connection given to a reactor that has just ended by a fault is closed, and its handler ends", () =>
        {
            var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var faulted = new ManualResetEventSlim();
            using var goOn = new ManualResetEventSlim();
            using var fleet = new MoveFleet(2, conn => TellAndEnd(conn, ended));
            (Socket client, TcpConnection conn) = fleet.Connect();
            Assert.Equal("0hello", MoveFleet.Exchange(client, "hello"));
            Fault(fleet.B, faulted, goOn);

            Assert.True(faulted.Wait(5_000), "the reactor never faulted");
            Assert.True(Moves.Begin(conn, fleet.B), "the move was refused");
            Moves.WaitFor(conn, Moves.Given);
            goOn.Set();

            Assert.True(fleet.Threads[1].Join(EndsWithinMs), "the reactor outlived its fault");
            Assert.True(ended.Task.Wait(EndsWithinMs), "the handler never heard of it");
            AssertClosed(client);
            AssertServes(fleet, fleet.A);
        });

        runner.Test("move stop: so is one with a flush nobody has been told of yet, and its waiter is", () =>
        {
            const int Big = 8 * 1024 * 1024;
            var flushing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var flushed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var faulted = new ManualResetEventSlim();
            using var goOn = new ManualResetEventSlim();
            using var fleet = new MoveFleet(2, async conn =>
            {
                try
                {
                    if (await MoveFleet.ReadText(conn) != "go")
                    {
                        return;
                    }
                    ValueTask<ioxide.RecvSnapshot> read = conn.ReadAsync();
                    conn.Write(new byte[Big]);
                    ValueTask flush = conn.FlushAsync();
                    flushing.SetResult();
                    await flush;
                    flushed.SetResult();
                    Assert.True((await read).IsClosed, "the read found the connection open");
                    ended.SetResult();
                }
                finally
                {
                    conn.DecRef();
                }
            });
            (Socket client, TcpConnection conn) = fleet.Connect();
            client.Send("go"u8);
            Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");
            Assert.True(Moves.Begin(conn, fleet.B, patient: true), "the move was refused");
            Moves.WaitFor(conn, Moves.Waiting);
            Fault(fleet.B, faulted, goOn);
            Assert.True(faulted.Wait(5_000), "the reactor never faulted");

            var buffer = new byte[64 * 1024];
            for (int got = 0; got < Big;)
            {
                got += client.Receive(buffer);
            }
            Moves.WaitFor(conn, Moves.Given);
            Assert.True(Moves.FlushOutstandingOf(conn), "the flush was over, so this proves nothing");
            goOn.Set();

            Assert.True(fleet.Threads[1].Join(EndsWithinMs), "the reactor outlived its fault");
            Assert.True(flushed.Task.Wait(EndsWithinMs), "the flush's waiter was never told");
            Assert.True(ended.Task.Wait(EndsWithinMs), "the handler never heard of the end");
            AssertClosed(client);
        });
    }

    // Faults the reactor's loop in its next pass, and holds it there, before its teardown, until goOn.
    private static void Fault(Reactor reactor, ManualResetEventSlim faulted, ManualResetEventSlim goOn)
    {
        TcpConnection?[] slots = SlotsOf(reactor);
        reactor.OnFault = (_, _) =>
        {
            SlotsOf(reactor) = slots;
            LeavingOf(reactor).Clear();
            faulted.Set();
            goOn.Wait(10_000);
        };
        reactor.ScheduleOnReactor(_ =>
        {
            LeavingOf(reactor).Add(0);   // has the pass look into the table
            SlotsOf(reactor) = null!;
        }, null);
    }

    private static void AssertServes(MoveFleet fleet, Reactor reactor)
    {
        (Socket client, TcpConnection _) = fleet.Connect(reactor);
        Assert.Equal($"{reactor.ShardIndex}alive", MoveFleet.Exchange(client, "alive"));
    }

    private static void AssertClosed(Socket client)
    {
        try
        {
            Assert.Equal(0, client.Receive(new byte[16]));
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
        {
            // a stop resets
        }
    }

    // MoveFleet.Tell, which says when it ends - of a connection that has said something, not of those that came to the
    // other reactor.
    private static async Task TellAndEnd(TcpConnection conn, TaskCompletionSource ended)
    {
        bool said = false;
        try
        {
            for (string got; (got = await MoveFleet.ReadText(conn)).Length > 0;)
            {
                said = true;
                conn.Write(Encoding.ASCII.GetBytes($"{Reactor.Current!.ShardIndex}{got}"));
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
            if (said)
            {
                ended.TrySetResult();
            }
        }
    }

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
        catch (ObjectDisposedException)
        {
            // its reactor has stopped
        }
        finally
        {
            conn.DecRef();
        }
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_arriving")]
    private static extern ref int ArrivingField(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_stopRequested")]
    private static extern ref bool StopRequestedOf(Reactor reactor);

    private static int ArrivingAt(Reactor reactor) => Volatile.Read(ref ArrivingField(reactor));

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_leaving")]
    private static extern ref List<ulong> LeavingOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_slots")]
    private static extern ref TcpConnection?[] SlotsOf(Reactor reactor);
}
