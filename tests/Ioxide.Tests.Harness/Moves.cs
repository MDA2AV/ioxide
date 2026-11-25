using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Moves connections between reactors on request: what a busy reactor does under <see cref="TcpOptions.Rebalance"/>,
/// without one having to be busy. A move needs no more than two reactors and a connection, so it works with the option off.
/// </summary>
public static class Moves
{
    /// <summary>
    /// Has the connection's reactor begin moving it, and returns what it answered: false, and it stays. A patient move
    /// isn't given up for taking its time.
    /// </summary>
    public static bool Begin(TcpConnection conn, Reactor target, bool patient = false)
    {
        bool began = false;
        OnItsReactor(conn, reactor =>
        {
            began = StartMove(reactor, conn, target);
            if (began && patient)
            {
                SinceField(conn) = long.MaxValue / 2;
            }
        });
        return began;
    }

    /// <summary>Moves the connection to a reactor and waits until it is there.</summary>
    public static void To(TcpConnection conn, Reactor target, int timeoutMs = 5_000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (!IsOn(conn, target))
        {
            Assert.True(Environment.TickCount64 < deadline, $"the connection never got to reactor {target.ShardIndex}: {Describe(conn)}");
            Begin(conn, target);
            SpinWait.SpinUntil(() => IsOn(conn, target), 5);
        }
    }

    /// <summary>Whether the connection is on that reactor, for good until another move begins.</summary>
    public static bool IsOn(TcpConnection conn, Reactor reactor) => ReferenceEquals(conn.Reactor, reactor) && StateOf(conn) == 0;

    /// <summary>Waits until the connection's move is at <paramref name="state"/>.</summary>
    public static void WaitFor(TcpConnection conn, int state, int timeoutMs = 5_000)
        => Assert.True(SpinWait.SpinUntil(() => StateOf(conn) == state, timeoutMs), $"the move never got to state {state}: {Describe(conn)}");

    /// <summary>TcpConnection.MoveNone and the states after it.</summary>
    public const int None = 0, Cancelling = 1, Waiting = 2, Given = 3;

    /// <summary>A move at <see cref="Waiting"/> is given up by its reactor's next pass, if the connection isn't idle by then.</summary>
    public static void GiveUp(TcpConnection conn) => OnItsReactor(conn, _ => SinceField(conn) = 0);

    /// <summary>Runs on the connection's reactor, whichever it is by then, and waits for it.</summary>
    public static void OnItsReactor(TcpConnection conn, Action<Reactor> body)
    {
        using var done = new ManualResetEventSlim();
        while (true)
        {
            Reactor reactor = conn.Reactor;
            bool ran = false;
            Exception? failure = null;
            done.Reset();
            reactor.ScheduleOnReactor(_ =>
            {
                try
                {
                    ran = ReferenceEquals(conn.Reactor, reactor);   // or it has moved on
                    if (ran)
                    {
                        body(reactor);
                    }
                }
                catch (Exception e)
                {
                    failure = e;
                }
                done.Set();
            }, null);
            Assert.True(done.Wait(10_000), $"reactor {reactor.ShardIndex} never ran what was posted to it");
            if (failure is not null)
            {
                throw failure;
            }
            if (ran)
            {
                return;
            }
        }
    }

    /// <summary>Runs on a reactor, in one of its passes, and waits for it.</summary>
    public static void On(Reactor reactor, Action body)
    {
        using var done = new ManualResetEventSlim();
        Exception? failure = null;
        reactor.ScheduleOnReactor(_ =>
        {
            try
            {
                body();
            }
            catch (Exception e)
            {
                failure = e;
            }
            done.Set();
        }, null);
        Assert.True(done.Wait(10_000), $"reactor {reactor.ShardIndex} never ran what was posted to it");
        if (failure is not null)
        {
            throw failure;
        }
    }

    /// <summary>
    /// Holds a reactor inside a callback until disposed: what is posted to it stays posted, a connection given to it
    /// stays in transit.
    /// </summary>
    public static Held Hold(Reactor reactor)
    {
        var held = new Held();
        reactor.ScheduleOnReactor(_ =>
        {
            held.Holding.Set();
            held.Released.Wait();
        }, null);
        Assert.True(held.Holding.Wait(5_000), $"reactor {reactor.ShardIndex} never got to being held");
        return held;
    }

    public sealed class Held : IDisposable
    {
        internal readonly ManualResetEventSlim Holding = new();
        internal readonly ManualResetEventSlim Released = new();

        public void Dispose() => Released.Set();
    }

    /// <summary>
    /// Begins a move to another reactor, picked at random, for every connection of every reactor, over and over until
    /// disposed.
    /// </summary>
    public sealed class Shuffle : IDisposable
    {
        private readonly Reactor[] _reactors;
        private readonly Thread _thread;
        private volatile bool _over;

        public Shuffle(Reactor[] reactors, int everyMs = 1)
        {
            _reactors = reactors;
            _thread = new Thread(() =>
            {
                while (!_over)
                {
                    foreach (Reactor reactor in reactors)
                    {
                        reactor.ScheduleOnReactor(static state =>
                        {
                            var (from, all) = ((Reactor, Reactor[]))state!;
                            foreach (TcpConnection conn in ConnectionsOf(from))
                            {
                                StartMove(from, conn, all[Random.Shared.Next(all.Length)]);
                            }
                        }, (reactor, reactors));
                    }
                    Thread.Sleep(everyMs);
                }
            }) { IsBackground = true, Name = "test-shuffle" };
            _thread.Start();
        }

        /// <summary>The moves that have been made so far.</summary>
        public long Made => _reactors.Sum(reactor => reactor.ConnectionsTaken);

        public void Dispose()
        {
            _over = true;
            _thread.Join();
        }
    }

    /// <summary>A client whose connection that reactor took: which one takes it is up to the kernel, so as many as it takes.</summary>
    public static Socket ConnectTo(int port, Reactor wanted, Func<Socket, Reactor> whose)
    {
        for (int attempt = 0; attempt < 500; attempt++)
        {
            Socket client = Connect(port);
            if (ReferenceEquals(whose(client), wanted))
            {
                return client;
            }
            client.Dispose();
        }
        throw new Exception($"500 connections, and none came to reactor {wanted.ShardIndex}");
    }

    public static Socket Connect(int port, int receiveTimeoutMs = 10_000)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, ReceiveTimeout = receiveTimeoutMs };
        client.Connect(IPAddress.Loopback, port);
        return client;
    }

    /// <summary>The connections in a reactor's table. On its thread, or while nothing can change it.</summary>
    public static TcpConnection[] ConnectionsOf(Reactor reactor)
        => SlotsOf(reactor).Take(SlotsUsedOf(reactor)).Where(conn => conn is not null).ToArray()!;

    /// <summary>Accepted by a reactor or given to it, and not recycled or given away yet.</summary>
    public static int LiveOn(Reactor reactor) => TcpLiveOf(reactor);

    /// <summary>Group ids a reactor has left (incremental mode).</summary>
    public static int RoomOn(Reactor reactor) => FreeGidCountOf(reactor);

    /// <summary>The slots a reactor has handed out at some time.</summary>
    public static int SlotsOn(Reactor reactor) => SlotsUsedOf(reactor);

    public static string Describe(TcpConnection conn)
        => $"on reactor {conn.Reactor.ShardIndex}, state {StateOf(conn)}, read parked {ReadParkedOf(conn)}, holds nothing {HoldsNothingOf(conn)}, closed {conn.IsClosed}";

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "StartMove")]
    public static extern bool StartMove(Reactor reactor, TcpConnection conn, Reactor target);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "MoveState")]
    private static extern ref int StateField(TcpConnection conn);

    public static int StateOf(TcpConnection conn) => Volatile.Read(ref StateField(conn));

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "MoveSinceMs")]
    private static extern ref long SinceField(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "Slot")]
    public static extern ref int SlotOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "TagGen")]
    public static extern ref int TagGenOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_HoldsNothing")]
    public static extern bool HoldsNothingOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_ReadParked")]
    public static extern bool ReadParkedOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_FlushOutstanding")]
    public static extern bool FlushOutstandingOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_slots")]
    private static extern ref TcpConnection?[] SlotsOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_slotsUsed")]
    private static extern ref int SlotsUsedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_TcpLive")]
    private static extern int TcpLiveOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_freeGidCount")]
    private static extern ref int FreeGidCountOf(Reactor reactor);
}
