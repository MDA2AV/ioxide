using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// DrainPostQ runs until the queue is empty, so what is posted during the drain runs in that same drain, and
/// while it keeps coming the loop never reaches io_uring_enter. These leave the posting going until an echo on
/// another connection is answered, or is not.
/// </summary>
internal static class PostStarvationTests
{
    public static void Register(Runner runner)
    {
        runner.Test("post: a callback that keeps re-posting itself leaves the ring running", () =>
        {
            bool stop = false;

            AnsweredWhile(start: reactor =>
            {
                void Again(object? _)
                {
                    if (!Volatile.Read(ref stop))
                    {
                        reactor.ScheduleOnReactor(Again, null);
                    }
                }

                reactor.ScheduleOnReactor(Again, null);
            }, finish: () => Volatile.Write(ref stop, true));
        });

        runner.Test("post: a handler looping on ReactorSwitch.Yield leaves the ring running", () =>
        {
            bool stop = false;

            AnsweredWhile(start: reactor =>
            {
                async Task YieldLoop()
                {
                    while (!Volatile.Read(ref stop))
                    {
                        await ReactorSwitch.Yield(reactor);
                    }
                }

                reactor.ScheduleOnReactor(_ => _ = YieldLoop(), null);
            }, finish: () => Volatile.Write(ref stop, true));
        });

        runner.Test("post: callbacks one pass leaves over run in the next, not at the next tick", () =>
        {
            // A post from the reactor's own thread writes no eventfd, so on an idle ring a pass that leaves
            // callbacks queued must not block in its wait. Passes on a drain without a bound, too.
            const int Posts = 20_000;
            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            (_, Reactor reactor, _) = TestServer.StartConfigured(Echo, new ServerConfig
            {
                RecvBufferSize = 4096,
                RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            });

            int left = Posts;   // reactor thread only
            void Again(object? _)
            {
                if (--left > 0)
                {
                    reactor.ScheduleOnReactor(Again, null);
                }
                else
                {
                    done.TrySetResult();
                }
            }

            var watch = Stopwatch.StartNew();
            reactor.ScheduleOnReactor(Again, null);
            Assert.True(done.Task.Wait(30_000), "the posts never finished");
            Assert.True(watch.ElapsedMilliseconds < 2_000,
                $"{Posts} posts took {watch.ElapsedMilliseconds} ms: what a pass left over waited for a tick");
        });

        runner.Test("post: control: a callback posted once leaves the ring running", () =>
        {
            AnsweredWhile(start: reactor => reactor.ScheduleOnReactor(_ => { }, null), finish: () => { });
        });
    }

    private static void AnsweredWhile(Action<Reactor> start, Action finish)
    {
        (int port, Reactor reactor, _) = TestServer.StartConfigured(Echo, new ServerConfig
        {
            RecvBufferSize = 4096,
            RecvSlots = 64,
            Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
        });

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
            ReceiveTimeout = 3_000,
        };
        client.Connect(IPAddress.Loopback, port);
        Assert.True(Echoed(client), "the echo was not answered even before the posting began");

        start(reactor);
        try
        {
            Thread.Sleep(100);
            Assert.True(Echoed(client), "the echo was never answered: the loop did not get back to the ring");
        }
        finally
        {
            finish();
        }
    }

    private static bool Echoed(Socket client)
    {
        client.Send("y"u8);
        try
        {
            return client.Receive(new byte[1]) == 1;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
        {
            return false;
        }
    }

    private static async Task Echo(Reactor reactor, TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        conn.Write(item.AsSpan());
                        conn.ReturnBuffer(in item);
                    }
                }

                await conn.FlushAsync();
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
}
