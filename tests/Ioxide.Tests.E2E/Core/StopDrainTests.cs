using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// The stop as one path: it closes every listener and connection and cancels every ring op, runs on until every
/// connection has been let go and every op has completed, or its deadline passes, and only then frees what the
/// reactor owns. What a handler still holds after the deadline stays allocated.
/// </summary>
internal static class StopDrainTests
{
    // Generous against a healthy return, which takes no time at all: the assertion is that it returns.
    private const int ReturnsWithinMs = 3_000;

    // The stop's deadline (Reactor.StopDrainMs).
    private const int DrainMs = 1_000;

    private const int ECANCELED = 125;

    public static void Register(Runner runner)
    {
        foreach (bool incremental in new[] { false, true })
        {
            string mode = incremental ? "incremental" : "shared ring";

            runner.Test($"stop: a handler holding its connection on another thread is waited for, and only then is everything freed ({mode})", () =>
            {
                ServerConfig config = Config(incremental);
                var holding = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var letGo = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        conn.DecRef();
                        return;
                    }

                    holding.TrySetResult(conn);
                    await release.Task.ConfigureAwait(false);   // on the thread pool, busy elsewhere when the stop comes
                    bool closed = (await conn.ReadAsync()).IsClosed;
                    conn.DecRef();
                    letGo.TrySetResult(closed);
                }, config);

                try
                {
                    using Socket client = Connect(port);
                    client.Send("hi"u8);
                    Assert.True(holding.Task.Wait(5_000), "the handler never ran");
                    TcpConnection conn = holding.Task.Result;

                    reactor.Stop();
                    Assert.True(!thread.Join(200), "the stop ended while a handler still held its connection");
                    Assert.True(HasWriteBuffer(conn) && HasReceiveMemory(reactor, conn, incremental),
                        "the stop freed a connection while its handler still held it");

                    release.TrySetResult();
                    Assert.True(thread.Join(ReturnsWithinMs), "the stop never ended once its last handler let go");
                    Assert.True(letGo.Task.Result, "the handler's read during the stop found its connection open");
                    Assert.True(!HasWriteBuffer(conn), "the write slab of the connection let go of during the stop outlived it");
                    Assert.True(!HasReceiveMemory(reactor, conn, incremental), "the receive memory outlived a stop whose handlers all let go");
                }
                finally
                {
                    release.TrySetResult();
                }
            }, skip: incremental && !TestServer.KernelAtLeast(6, 12));

            runner.Test($"stop: a handler that never lets go ends the stop at its deadline, with its connection and the receive memory it can reach left allocated, and what it calls after fails fast ({mode})", () =>
            {
                ServerConfig config = Config(incremental);
                var holding = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

                (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        conn.DecRef();
                        return;
                    }

                    holding.TrySetResult(conn);
                    await release.Task.ConfigureAwait(false);
                    conn.DecRef();
                }, config);

                try
                {
                    using Socket client = Connect(port);
                    client.Send("hi"u8);
                    Assert.True(holding.Task.Wait(5_000), "the handler never ran");
                    TcpConnection conn = holding.Task.Result;
                    client.Send(Payload);
                    Assert.True(SpinWait.SpinUntil(() => !RecvOf(conn).IsEmpty(), 5_000), "the client's bytes were never queued");
                    string socket = SocketOf(conn.ClientFd);

                    var watch = Stopwatch.StartNew();
                    reactor.Stop();
                    Assert.True(SpinWait.SpinUntil(() => conn.IsClosed, 5_000), "the stop never closed the connection");
                    Assert.Throws<ObjectDisposedException>(() => _ = new RingTimer(reactor).DelayAsync(600_000), nameof(Reactor));   // during the drain too
                    Assert.True(thread.Join(5 * DrainMs), "the stop never ended, with a handler that never lets go");
                    Assert.True(watch.ElapsedMilliseconds >= DrainMs - 100, $"the stop ended after {watch.ElapsedMilliseconds} ms, before its deadline");
                    Assert.True(SocketOf(conn.ClientFd) == socket, $"after the stop fd {conn.ClientFd} names {SocketOf(conn.ClientFd)}, not the {socket} its handler still holds");
                    Assert.True(HasWriteBuffer(conn), "the stop freed the write slab of a connection its handler still holds");
                    Assert.True(HasReceiveMemory(reactor, conn, incremental), "the stop freed the receive memory a connection its handler still holds points into");

                    Task calls = Task.Run(() =>
                    {
                        conn.Write("late"u8);
                        Assert.True(conn.FlushAsync().IsCompleted, "a flush after the stop waited");

                        ValueTask<RecvSnapshot> read = conn.ReadAsync();
                        Assert.True(read.IsCompleted && read.Result.IsClosed, "a read after the stop waited, or found the connection open");
                        int returned = 0;
                        while (conn.TryGetItem(read.Result, out SpscRecvRing.Item item))
                        {
                            if (item.HasBuffer)
                            {
                                conn.ReturnBuffer(in item);
                                returned++;
                            }
                        }
                        Assert.True(returned > 0, "nothing queued before the stop was left to give back");

                        Assert.Throws<ObjectDisposedException>(() => _ = new RingTimer(reactor).DelayAsync(600_000), nameof(Reactor));
                        Assert.Throws<ObjectDisposedException>(() => SwitchTo(reactor).GetAwaiter().GetResult(), nameof(Reactor));

                        conn.DecRef();
                    });
                    Assert.True(((IAsyncResult)calls).AsyncWaitHandle.WaitOne(ReturnsWithinMs), "a call into the stopped reactor never returned");
                    calls.GetAwaiter().GetResult();
                }
                finally
                {
                    release.TrySetResult();
                }
            }, skip: incremental && !TestServer.KernelAtLeast(6, 12));
        }

        foreach (bool peerClosed in new[] { false, true })
        {
            string state = peerClosed ? "its client closed before the stop" : "open at the stop";

            runner.Test($"stop: reads from another thread during the stop and after it get the bytes queued before it, intact, from receive memory still allocated ({state})", () =>
            {
                ServerConfig config = SmallBuffers;
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
                }, config);

                try
                {
                    using Socket client = Connect(port);
                    client.Send("hi"u8);
                    Assert.True(running.Task.Wait(5_000), "the handler never ran");
                    TcpConnection conn = running.Task.Result;

                    client.Send(Payload);
                    if (peerClosed)
                    {
                        client.Shutdown(SocketShutdown.Send);   // the reactor lets go of it itself, before the stop
                    }
                    Assert.True(SpinWait.SpinUntil(() => peerClosed ? conn.IsClosed : CountOf(conn) * config.RecvBufferSize >= Payload.Length, 5_000),
                        peerClosed ? "the reactor never saw its client close" : "the client's bytes were never queued");
                    Thread.Sleep(50);   // a segment still on its way is queued too

                    reactor.Stop();
                    Assert.True(SpinWait.SpinUntil(() => conn.IsClosed, 5_000), "the stop never closed the connection");
                    Assert.True(thread.IsAlive, "the stop ended with a handler still holding its connection");

                    var received = new List<byte>();
                    ValueTask<RecvSnapshot> read = conn.ReadAsync();
                    Assert.True(read.IsCompleted, "a read during the stop of what was queued before it waited");
                    RecvSnapshot snapshot = read.Result;
                    TakeFromAllocated(reactor, conn, config, snapshot, Payload.Length / 2, received);

                    Assert.True(thread.Join(5 * DrainMs), "the reactor did not stop");
                    TakeFromAllocated(reactor, conn, config, snapshot, int.MaxValue, received);

                    Assert.True(received.ToArray().AsSpan().SequenceEqual(Payload),
                        $"the reads across the stop got {received.Count} bytes, not the {Payload.Length} queued before it");
                }
                finally
                {
                    release.TrySetResult();
                }
            });
        }

        runner.Test("stop: what a pipe reader took before the stop and still holds stays intact, in receive memory still allocated", () =>
        {
            var holding = new TaskCompletionSource<(TcpConnection, ReadOnlySequence<byte>)>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                try
                {
                    while (true)
                    {
                        ReadResult result = await reader.ReadAsync();
                        if (result.Buffer.Length >= Payload.Length)
                        {
                            holding.TrySetResult((conn, result.Buffer));   // neither consumed nor completed
                            await release.Task;
                            return;
                        }
                        if (result.IsCompleted)
                        {
                            return;   // the harness's listen probe
                        }
                        reader.AdvanceTo(result.Buffer.Start, result.Buffer.End);
                    }
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            }, SmallBuffers);

            try
            {
                using Socket client = Connect(port);
                client.Send(Payload);
                Assert.True(holding.Task.Wait(5_000), "the handler never read what its client sent");

                reactor.Stop();
                Assert.True(thread.Join(5 * DrainMs), "the reactor did not stop");

                (TcpConnection conn, ReadOnlySequence<byte> held) = holding.Task.Result;
                foreach (ReadOnlyMemory<byte> segment in held)
                {
                    AssertInAllocated(reactor, conn, SmallBuffers, segment);
                }
                Assert.True(held.ToArray().AsSpan().SequenceEqual(Payload), "what the reader held changed across the stop");
            }
            finally
            {
                release.TrySetResult();
            }
        });

        runner.Test("stop: a ring op parked at the stop ends at once, and one its completion submits again throws ObjectDisposedException", () =>
        {
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var handler = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var background = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var stopNow = new ManualResetEventSlim();
            long stoppedAt = 0, firstEndedAt = 0;

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (r, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                try
                {
                    var timer = new RingTimer(r);
                    ValueTask<int> first = timer.DelayAsync(600_000);
                    parked.TrySetResult();
                    int a = await first;
                    Volatile.Write(ref firstEndedAt, Stopwatch.GetTimestamp());

                    // Inline in the completion the stop gives, as a retry would.
                    handler.TrySetResult($"{a}, then {await WaitAgain(timer)}");
                }
                finally
                {
                    conn.DecRef();
                }
            }, new ServerConfig { Tcp = new TcpOptions() }, r =>
            {
                _ = WaitTwice(new RingTimer(r), background);   // a wait no connection holds

                // Stopped from a tick, so a cancel left to a later tick would be a whole tick away.
                r.AddTicker(() =>
                {
                    if (stopNow.IsSet && Volatile.Read(ref stoppedAt) == 0)
                    {
                        Volatile.Write(ref stoppedAt, Stopwatch.GetTimestamp());
                        r.Stop();
                    }
                });
            });

            using Socket client = Connect(port);
            client.Send("hi"u8);
            Assert.True(parked.Task.Wait(5_000), "the handler never parked");

            stopNow.Set();
            Assert.True(handler.Task.Wait(ReturnsWithinMs), "the handler's wait parked at the stop, or the one after it, never ended");
            Assert.True(background.Task.Wait(ReturnsWithinMs), "the wait no connection holds, or the one after it, never ended");
            Assert.True(thread.Join(ReturnsWithinMs), "the reactor did not stop");
            Assert.Equal($"{-ECANCELED}, then ObjectDisposedException", handler.Task.Result);
            Assert.Equal($"{-ECANCELED}, then ObjectDisposedException", background.Task.Result);

            double ms = Stopwatch.GetElapsedTime(Volatile.Read(ref stoppedAt), Volatile.Read(ref firstEndedAt)).TotalMilliseconds;
            Assert.True(ms < Reactor.TickMs / 2, $"the wait parked at the stop ended {ms:F0} ms after it, at a tick rather than at the stop");
        });

        runner.Test("stop: a RingTimer loop that waits again after each cancelled wait ends at the stop, and the stop returns at once", () =>
        {
            var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task loop = null!;
            (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(
                (_, conn) => { conn.DecRef(); return Task.CompletedTask; },
                new ServerConfig { Tcp = new TcpOptions() },
                r => loop = Feed(new RingTimer(r), waiting));
            Assert.True(waiting.Task.Wait(5_000), "the loop never waited");

            var watch = Stopwatch.StartNew();
            reactor.Stop();
            bool stopped = thread.Join(5 * DrainMs);
            long ms = watch.ElapsedMilliseconds;
            Assert.True(stopped, "the reactor did not stop");
            Assert.True(ms < Reactor.TickMs / 2, $"the stop took {ms} ms, held by a loop that waits again after each cancelled wait");
            Assert.True(loop.Exception?.InnerException is ObjectDisposedException, $"the loop ended {loop.Status}: {loop.Exception?.InnerException?.GetType().Name}");
        });

        runner.Test("stop: a ring op handed over from another thread before the stop, and taken after its cancel, ends cancelled", () =>
        {
            var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                holding.TrySetResult();
                await release.Task.ConfigureAwait(false);   // held, so the stop runs on past its first pass
                conn.DecRef();
            }, new ServerConfig { Tcp = new TcpOptions() });

            using var paused = new ManualResetEventSlim();
            using var resume = new ManualResetEventSlim();
            try
            {
                using Socket client = Connect(port);
                client.Send("hi"u8);
                Assert.True(holding.Task.Wait(5_000), "the handler never ran");

                // Held in this pass's posts, past its ops: what is handed over now is taken in the next pass.
                reactor.ScheduleOnReactor(_ =>
                {
                    paused.Set();
                    resume.Wait(5_000);
                }, null);
                Assert.True(paused.Wait(5_000), "the reactor never ran the post");
                Task<int> wait = new RingTimer(reactor).DelayAsync(600_000).AsTask();
                reactor.Stop();
                resume.Set();

                Assert.True(wait.Wait(ReturnsWithinMs), "a wait handed over before the stop, and taken after its cancel, never ended");
                Assert.Equal(-ECANCELED, wait.Result);
            }
            finally
            {
                resume.Set();
                release.TrySetResult();
            }
            Assert.True(thread.Join(ReturnsWithinMs), "the reactor did not stop");
        });

        runner.Test("stop: buffers a handler gives back from another thread during the stop are taken", () =>
        {
            const int Held = 32;
            var holding = new TaskCompletionSource<(TcpConnection, int)>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                var held = new List<SpscRecvRing.Item>();
                try
                {
                    while (held.Count < Held)
                    {
                        RecvSnapshot snapshot = await conn.ReadAsync();
                        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                        {
                            if (item.HasBuffer)
                            {
                                held.Add(item);
                            }
                        }
                        if (snapshot.IsClosed)
                        {
                            return;   // the harness's listen probe
                        }
                    }

                    holding.TrySetResult((conn, held.Count));
                    await release.Task.ConfigureAwait(false);   // on the thread pool, during the stop
                    foreach (SpscRecvRing.Item item in held)
                    {
                        conn.ReturnBuffer(in item);
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, SmallBuffers);

            try
            {
                using Socket client = Connect(port);
                client.Send(new byte[Held * SmallBuffers.RecvBufferSize]);
                Assert.True(holding.Task.Wait(5_000), "the handler never came to hold its buffers");
                (TcpConnection conn, int held) = holding.Task.Result;

                reactor.Stop();
                Assert.True(SpinWait.SpinUntil(() => conn.IsClosed, 5_000), "the stop never closed the connection");
                ushort before = TailOf(reactor);
                release.TrySetResult();
                Assert.True(thread.Join(ReturnsWithinMs), "the reactor did not stop");

                int taken = (ushort)(TailOf(reactor) - before);
                Assert.True(taken >= held, $"{taken} of the {held} buffers given back during the stop were taken");
            }
            finally
            {
                release.TrySetResult();
            }
        });

        runner.Test("stop: a zero-copy response its client never reads ends at the stop: the flush returns, the handler lets go, the stop ends at once and the write slab is freed", () =>
        {
            var flushing = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            byte[] response = new byte[8 << 20];   // more than both sockets' buffers hold

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
                    flushing.TrySetResult(conn);
                    await flush;
                }
                finally
                {
                    finished.TrySetResult();
                    conn.DecRef();
                }
            }, new ServerConfig { Tcp = new TcpOptions { ZeroCopySend = true } });

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.ReceiveBufferSize = 4096;   // takes little, and never reads
            client.Connect(IPAddress.Loopback, port);
            client.Send("hi"u8);
            Assert.True(flushing.Task.Wait(5_000), "the handler never flushed");
            TcpConnection conn = flushing.Task.Result;
            Thread.Sleep(200);   // the kernel has the send, parked on the client's closed window
            Assert.True(!finished.Task.IsCompleted, "the flush ended before the stop, so nothing held it");

            var watch = Stopwatch.StartNew();
            reactor.Stop();
            bool stopped = thread.Join(5 * DrainMs);
            long ms = watch.ElapsedMilliseconds;
            Assert.True(stopped, "the reactor did not stop");
            Assert.True(finished.Task.IsCompleted, "the handler's flush never returned");
            Assert.True(ms < Reactor.TickMs / 2, $"the stop took {ms} ms, held by a send its client never reads");
            Assert.True(!HasWriteBuffer(conn), "the write slab of the connection outlived the stop");
        });

        runner.Test("stop: the stoppers run on the reactor thread before its connections close, and one that throws leaves the rest to run", () =>
        {
            var parked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            bool closed = false;
            var ran = new List<string>();

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
                    closed = true;
                }
                finally
                {
                    conn.DecRef();
                }
            }, new ServerConfig { Tcp = new TcpOptions() }, r =>
            {
                r.AddStopper(() => ran.Add($"on the reactor {Reactor.Current == r}, its connection closed {closed}"));
                r.AddStopper(() => throw new InvalidOperationException("a stopper that throws"));
                r.AddStopper(() => ran.Add("the next one"));
            });

            using Socket client = Connect(port);
            client.Send("hi"u8);
            Assert.True(parked.Task.Wait(5_000), "the handler never parked");

            reactor.Stop();
            Assert.True(thread.Join(ReturnsWithinMs), "the reactor did not stop");
            Assert.Equal("on the reactor True, its connection closed False; the next one", string.Join("; ", ran));
            Assert.True(closed, "the stop never closed the connection to its handler");
        });

        runner.Test("stop: from the stop on its listener refuses connections, while a handler still holds one", () =>
        {
            var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int handlers = 0;

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                Interlocked.Increment(ref handlers);
                holding.TrySetResult();
                await release.Task.ConfigureAwait(false);
                conn.DecRef();
            }, new ServerConfig { Tcp = new TcpOptions() });

            try
            {
                using Socket client = Connect(port);
                client.Send("hi"u8);
                Assert.True(holding.Task.Wait(5_000), "the handler never ran");

                reactor.Stop();
                bool refused = SpinWait.SpinUntil(() => Refuses(port), DrainMs / 2);
                Assert.True(thread.IsAlive, "the stop ended with a handler still holding its connection");
                Assert.True(refused, "a connect during the stop was taken");
                Assert.Equal(1, Volatile.Read(ref handlers));
            }
            finally
            {
                release.TrySetResult();
            }
        });

        foreach (bool paused in new[] { false, true })
        {
            string how = paused ? "by the sweep, as an accept paused before the stop" : "by its accept's last completion";

            runner.Test($"stop: no accept is armed again on the number of a listener the stop closed ({how})", () =>
            {
                using var listenerClosed = new ManualResetEventSlim();
                using var numberTaken = new ManualResetEventSlim();
                var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

                (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        conn.DecRef();
                        return;
                    }

                    holding.TrySetResult();
                    await conn.ReadAsync();   // ends inside the stop's close, on the reactor, after its listeners closed

                    // Holds the reactor until the test has put a socket of its own on the listener's number.
                    listenerClosed.Set();
                    numberTaken.Wait(5_000);
                    await release.Task;   // held, so the stop runs on
                    conn.DecRef();
                }, new ServerConfig { Tcp = new TcpOptions() });

                using var own = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                int number = -1;
                try
                {
                    using Socket client = Connect(port);
                    client.Send("hi"u8);
                    Assert.True(holding.Task.Wait(5_000), "the handler never ran");

                    int listenFd = ListenFdsOf(reactor)[0];
                    Action stop = paused
                        ? () => { PausedOf(reactor).Add(listenFd); reactor.Stop(); }   // in one pass, before a sweep can take it
                        : reactor.Stop;
                    reactor.ScheduleOnReactor(static s => ((Action)s!)(), stop);
                    Assert.True(listenerClosed.Wait(5_000), "the stop never closed the connection");

                    own.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                    own.Listen(8);
                    Assert.True(!IsOpen(listenFd), $"fd {listenFd} was taken before the test could take it");
                    Assert.Equal(listenFd, dup2((int)own.Handle, listenFd));
                    number = listenFd;
                    numberTaken.Set();

                    Thread.Sleep(paused ? 2 * Reactor.TickMs : 50);   // a sweep, or the accept's last completion

                    // An accept armed on the number takes the connection out of the backlog first, given the time.
                    using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    probe.Connect(own.LocalEndPoint!);
                    Thread.Sleep(200);
                    Assert.True(own.Poll(0, SelectMode.SelectRead),
                        "the stopped reactor armed an accept on its closed listener's number and took the connection of the socket that took it");
                }
                finally
                {
                    numberTaken.Set();
                    release.TrySetResult();
                    if (number >= 0)
                    {
                        close(number);
                    }
                }
            });
        }

        runner.Test("stop: a datagram that reaches a socket the stop closed is dropped, not handed to OnDatagram", () =>
        {
            int udpPort = TestServer.NextPort();
            int datagrams = 0;
            var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(async (_, conn) =>
            {
                if (!await IsThisTestsConnection(conn))
                {
                    conn.DecRef();
                    return;
                }

                holding.TrySetResult();
                await release.Task.ConfigureAwait(false);   // held, so the stop runs on
                conn.DecRef();
            },
            new ServerConfig { Tcp = new TcpOptions(), Udp = new UdpOptions { Ports = [(ushort)udpPort] } },
            r => r.OnDatagram = (Reactor _, in UdpDatagram _) => Interlocked.Increment(ref datagrams));

            try
            {
                using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                var target = new IPEndPoint(IPAddress.Loopback, udpPort);
                udp.SendTo("before"u8, target);
                Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref datagrams) == 1, 5_000), "the datagram before the stop never reached OnDatagram");

                using Socket client = Connect(port);
                client.Send("hi"u8);
                Assert.True(holding.Task.Wait(5_000), "the handler never ran");

                reactor.Stop();
                Assert.True(SpinWait.SpinUntil(() => Refuses(port), DrainMs / 2), "the stop never closed its sockets");
                for (int i = 0; i < 8; i++)
                {
                    udp.SendTo("after"u8, target);
                }
                Thread.Sleep(200);

                Assert.True(thread.IsAlive, "the stop ended with a handler still holding its connection");
                Assert.True(Volatile.Read(ref datagrams) == 1, $"{Volatile.Read(ref datagrams) - 1} datagrams reached OnDatagram after the stop closed their socket");
            }
            finally
            {
                release.TrySetResult();
            }
        });
    }

    private static readonly byte[] Payload = [.. Enumerable.Range(0, 1000).Select(i => (byte)('a' + i % 26))];

    // 64-byte buffers, so the payload spans many items.
    private static readonly ServerConfig SmallBuffers = new() { RecvBufferSize = 64, RecvSlots = 256, Tcp = new TcpOptions() };

    private static ServerConfig Config(bool incremental) => incremental
        ? new ServerConfig { Incremental = new IncrementalOptions { MaxConnections = 16 }, Tcp = new TcpOptions() }
        : new ServerConfig { RecvBufferSize = 4096, RecvSlots = 256, Tcp = new TcpOptions() };

    private static async Task WaitTwice(RingTimer timer, TaskCompletionSource<string> results)
    {
        int a = await timer.DelayAsync(600_000);
        results.TrySetResult($"{a}, then {await WaitAgain(timer)}");
    }

    // What a second wait came to: its result, or the type of what it threw.
    private static async Task<string> WaitAgain(RingTimer timer)
    {
        try
        {
            return (await timer.DelayAsync(600_000)).ToString();
        }
        catch (Exception e)
        {
            return e.GetType().Name;
        }
    }

    // Playground/Tcp/Feed's shape: it waits again whatever the last wait came to.
    private static async Task Feed(RingTimer timer, TaskCompletionSource waiting)
    {
        while (true)
        {
            ValueTask<int> wait = timer.DelayAsync(1_000);
            waiting.TrySetResult();
            await wait;
        }
    }

    // Each item checked to lie in receive memory still allocated before a byte of it is read: freed, it can fault.
    private static void TakeFromAllocated(Reactor reactor, TcpConnection conn, ServerConfig config, RecvSnapshot snapshot, int bytes, List<byte> into)
    {
        int taken = 0;
        while (taken < bytes && conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                AssertInAllocated(reactor, conn, config, in item);
                into.AddRange(item.AsSpan());
                taken += item.Len;
                conn.ReturnBuffer(in item);
            }
        }
    }

    private static unsafe void AssertInAllocated(Reactor reactor, TcpConnection conn, ServerConfig config, in SpscRecvRing.Item item)
        => AssertInAllocated(reactor, conn, config, item.Ptr, item.Len);

    private static unsafe void AssertInAllocated(Reactor reactor, TcpConnection conn, ServerConfig config, ReadOnlyMemory<byte> segment)
    {
        fixed (byte* ptr = segment.Span)
        {
            AssertInAllocated(reactor, conn, config, ptr, segment.Length);
        }
    }

    private static unsafe void AssertInAllocated(Reactor reactor, TcpConnection conn, ServerConfig config, byte* ptr, int length)
    {
        byte* slab;
        nuint size;
        if (config.Incremental is { } incremental)
        {
            slab = BufSlabOf(conn);
            size = (nuint)incremental.RecvSlots * (nuint)incremental.RecvBufferSize;
        }
        else
        {
            slab = SlabOf(reactor);
            size = (nuint)config.RecvSlots * (nuint)config.RecvBufferSize;
        }

        Assert.True(slab != null, "the receive memory the read points into was freed at the stop, under a connection its handler still holds");
        Assert.True(ptr >= slab && ptr + length <= slab + size, "the read handed out bytes from outside the receive memory");
    }

    private static unsafe bool HasWriteBuffer(TcpConnection connection) => WriteBufferOf(connection) != null;

    private static unsafe bool HasReceiveMemory(Reactor reactor, TcpConnection connection, bool incremental) => incremental
        ? BufRingOf(connection) != null && BufSlabOf(connection) != null
        : SlabOf(reactor) != null;

    private static int CountOf(TcpConnection connection) => RecvOf(connection).CountUntil(RecvOf(connection).SnapshotTail());

    private static async Task SwitchTo(Reactor reactor) => await new ReactorSwitch(reactor);

    // A connect completes into a listener's backlog without anyone accepting, so it succeeds exactly while the
    // listening socket is open; one that landed there as the listener closed is reset instead.
    private static bool Refuses(int port)
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            probe.Connect(IPAddress.Loopback, port);
            return false;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
        {
            return false;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return true;
        }
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

    private const int FGetFd = 1;

    private static bool IsOpen(int fd) => fcntl(fd, FGetFd) != -1;

    // What a descriptor number names, as socket:[inode], or "nothing" once it is closed.
    private static string SocketOf(int fd) => new FileInfo($"/proc/self/fd/{fd}").LinkTarget ?? "nothing";

    [DllImport("libc", SetLastError = true)]
    private static extern int fcntl(int fd, int command);

    [DllImport("libc", SetLastError = true)]
    private static extern int dup2(int oldFd, int newFd);

    [DllImport("libc")]
    private static extern int close(int fd);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "WriteBuffer")]
    private static extern unsafe ref byte* WriteBufferOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "BufRing")]
    private static extern unsafe ref byte* BufRingOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "BufSlab")]
    private static extern unsafe ref byte* BufSlabOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_recv")]
    private static extern ref SpscRecvRing RecvOf(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_bufSlab")]
    private static extern unsafe ref byte* SlabOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_bufRingTail")]
    private static extern ref ushort TailOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_listenFds")]
    private static extern ref int[] ListenFdsOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_acceptPaused")]
    private static extern ref List<int> PausedOf(Reactor reactor);
}
