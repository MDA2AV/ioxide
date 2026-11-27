using System.Runtime.CompilerServices;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What a connection that can change reactors keeps of itself: whether it is idle, whose it is, seen from whichever thread
/// asks, and which of its numbers are its life's and which its reactor's.
/// </summary>
internal static class ConnectionMoveTests
{
    public static void Register(Runner runner)
    {
        runner.Test("move: a connection is idle with a read waiting, and nothing held, sent or read beside it", () =>
        {
            TcpConnection conn = Connection();
            Assert.True(!conn.ReadParked && !conn.Idle, "a connection nobody reads is idle");

            ValueTask<RecvSnapshot> read = conn.ReadAsync();
            Assert.True(conn.ReadParked && conn.Idle, "one whose read waits is not");

            InProgressOf(conn) = 1;
            Assert.True(conn.IdleButForTheSend && !conn.Idle, "one with a flush in progress is idle");
            InProgressOf(conn) = 0;

            conn.Pinned = true;
            Assert.True(!conn.Idle && !conn.IdleButForTheSend, "a pinned one is idle");
            conn.Pinned = false;

            RefsOf(conn) = 1;
            Assert.True(!conn.Idle && !conn.IdleButForTheSend, "one its handler has let go of is idle");
            RefsOf(conn) = 2;
            Assert.True(conn.Idle, "what made it busy was not all of it");

            conn.MarkClosed();
            Assert.True(read.IsCompleted && !conn.Idle && !conn.IdleButForTheSend, "one that is closed is idle");
        });

        runner.Test("move: what was received and not taken, or taken and not given back, is held", () =>
        {
            TcpConnection conn = Connection();
            Assert.True(conn.HoldsNothing, "a new connection holds something");

            for (ushort i = 0; i < 3; i++)
            {
                Deliver(conn, i);
            }
            Assert.True(!conn.HoldsNothing, "what is queued is not held");

            var taken = new List<SpscRecvRing.Item>();
            RecvSnapshot snapshot = Snapshot(conn);
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                taken.Add(item);
            }
            Assert.Equal(3, taken.Count);
            foreach (SpscRecvRing.Item item in taken)
            {
                Assert.True(!conn.HoldsNothing, "what was taken is not held");
                conn.ReturnBuffer(in item);
            }
            Assert.True(conn.HoldsNothing, "everything was given back and something is held");

            // The same through the memories, and from another thread.
            for (ushort i = 0; i < 4; i++)
            {
                Deliver(conn, i);
            }
            UnmanagedMemoryManager[] memories = conn.GetSnapshotMemories(Snapshot(conn));
            Assert.Equal(4, memories.Length);
            Assert.True(!conn.HoldsNothing, "what was taken as memories is not held");
            var giving = new Thread(() => conn.ReturnBuffers(memories));
            giving.Start();
            giving.Join();
            Assert.True(conn.HoldsNothing, "memories given back from another thread are held");
        });

        runner.Test("move: holding is counted afresh in the connection's next life, whatever is given back of the last one", () =>
        {
            TcpConnection conn = Connection();
            Deliver(conn, 0);
            Deliver(conn, 1);
            RecvSnapshot snapshot = Snapshot(conn);
            Assert.True(conn.TryGetItem(snapshot, out SpscRecvRing.Item first), "nothing was delivered");
            Assert.True(conn.TryGetItem(snapshot, out SpscRecvRing.Item second), "one was delivered");
            conn.Clear();   // with neither given back
            Assert.True(conn.HoldsNothing, "a new life holds what the last one did");

            conn.ReturnBuffer(in first);   // too late, both
            conn.ReturnBuffers([second.AsMemoryManager()]);
            Assert.True(conn.HoldsNothing, "what is given back of the life before counts in this one");
            Deliver(conn, 3);
            Assert.True(conn.TryGetItem(Snapshot(conn), out SpscRecvRing.Item held), "nothing was delivered");
            Assert.True(!conn.HoldsNothing, "what was given back of the life before made up for what this one holds");
            conn.ReturnBuffer(in held);
            Assert.True(conn.HoldsNothing, "everything was given back and something is held");
        });

        runner.Test("move: every life has a number of its own, whichever reactors it was on, and tags one per place", () =>
        {
            Reactor a = NeverRunning(0), b = NeverRunning(1);
            var conn = new TcpConnection(a, -1, 64, 8);
            var lives = new HashSet<int>();
            for (int life = 0; life < 50; life++)
            {
                Reactor reactor = life % 2 == 0 ? a : b;
                Track(reactor, conn);
                int tag = conn.TagGen;
                Assert.True(lives.Add(conn.Generation), $"life {life} has the number of an earlier one");
                Untrack(reactor, conn);
                FreeSlotsOf(reactor).Push(conn.Slot);

                // Away, within the life: its tags change, its life doesn't.
                Reactor other = life % 2 == 0 ? b : a;
                int generation = conn.Generation;
                conn.LeaveFor(other);
                Track(other, conn);
                conn.ArriveOn(other);
                Assert.Equal(generation, conn.Generation);
                Assert.True(ConnAt(other, conn.Slot, (ushort)conn.TagGen) == conn, "it is not found by its tag where it arrived");
                Untrack(other, conn);
                FreeSlotsOf(other).Push(conn.Slot);
                conn.Clear();
            }
        });

        runner.Test("move: a connection outside a fleet hands back as before connections moved: its receives carry its tag, and nothing is counted", () =>
        {
            Reactor a = NeverRunning(0);
            var conn = new TcpConnection(a, -1, 64, 8);
            conn.Clear();   // its second life: its number is not its tag's
            conn.InitRefs();
            Track(a, conn);
            Assert.True(conn.TagGen != conn.Generation, "its tag is its life's number");
            Assert.True(!conn.Movable, "a connection without Rebalance can move");
            Receive(conn, 7);
            Assert.True(conn.TryGetItem(Snapshot(conn), out SpscRecvRing.Item item), "nothing was received");
            Assert.Equal((ushort)conn.TagGen, item.Gen);
            conn.ReturnBuffer(in item);
            conn.ReturnBuffers([item.AsMemoryManager()]);
            Assert.Equal(0L, ReturnedOf(conn));
        });

        runner.Test("move: a fleet's connection carries its life in its receives, wherever it goes, and counts what it hands back", () =>
        {
            var config = new ServerConfig { ReactorCount = 2, Udp = null, Tcp = new TcpOptions { Rebalance = true } };
            Reactor a = new(0, config), b = new(1, config);
            JoinFleet(a);
            JoinFleet(b);
            var conn = new TcpConnection(a, -1, 64, 8);
            conn.Clear();   // its second life: its number is not its tag's
            conn.InitRefs();
            Track(a, conn);
            Assert.True(conn.TagGen != conn.Generation, "its tag is its life's number");
            Assert.True(conn.Movable, "a fleet's connection can't move");
            Receive(conn, 3);
            Assert.True(conn.TryGetItem(Snapshot(conn), out SpscRecvRing.Item item), "nothing was received");
            Assert.Equal((ushort)conn.Generation, item.Gen);
            conn.ReturnBuffer(in item);
            Assert.Equal(1L, ReturnedOf(conn));

            Untrack(a, conn);
            conn.LeaveFor(b);
            Track(b, conn);
            conn.ArriveOn(b);
            Assert.True(conn.TagGen != conn.Generation, "its tag is its life's number");
            Assert.True(conn.Movable && conn.Stamp == (ushort)conn.Generation, "where it arrived it carries something other than its life");
        });

        runner.Test("move: a slice that continues the last one received grows it, with Rebalance and without", () =>
        {
            var config = new ServerConfig { ReactorCount = 2, Udp = null, Tcp = new TcpOptions { Rebalance = true } };
            Reactor fleetMember = new(0, config);
            JoinFleet(fleetMember);
            foreach (Reactor reactor in new[] { NeverRunning(0), fleetMember })
            {
                var conn = new TcpConnection(reactor, -1, 64, 8);
                conn.Clear();   // its second life: its number is not its tag's
                conn.InitRefs();
                Track(reactor, conn);
                Assert.True(conn.TagGen != conn.Generation, "its tag is its life's number");
                GrowsTheLast(conn);
            }
        });

        runner.Test("move: without Rebalance a buffer goes back to its reactor under the tag it came with, as before connections moved", () =>
        {
            foreach (bool incremental in new[] { false, true })
            {
                var config = new ServerConfig
                {
                    ReactorCount = 1, Udp = null, Tcp = new TcpOptions(),
                    Incremental = incremental ? new IncrementalOptions { MaxConnections = 3, RecvSlots = 2, RecvBufferSize = 64 } : null,
                };
                var reactor = new Reactor(0, config);
                if (incremental)
                {
                    InitIncremental(reactor);
                }
                var conn = new TcpConnection(reactor, -1, 64, 8);
                conn.Clear();   // its second life: its number is not its tag's
                conn.InitRefs();
                Track(reactor, conn);
                conn.IncrementalMode = incremental;   // as its ring's setup leaves it
                Assert.True(conn.TagGen != conn.Generation, "its tag is its life's number");
                Receive(conn, 1);
                Receive(conn, 2);
                RecvSnapshot snapshot = Snapshot(conn);
                Assert.True(conn.TryGetItem(snapshot, out SpscRecvRing.Item first), "nothing was received");
                Assert.True(conn.TryGetItem(snapshot, out SpscRecvRing.Item second), "one was received");
                conn.ReturnBuffer(in first);
                conn.ReturnBuffers([second.AsMemoryManager()]);
                foreach (ushort bid in new ushort[] { 1, 2 })
                {
                    if (incremental)
                    {
                        Assert.True(ReturnQIncOf(reactor)!.TryDequeue(out ulong packed), $"buffer {bid} was not handed back (ring per connection)");
                        UnpackReturn(null, packed, out int slot, out ushort gen, out ushort got);
                        Assert.True(slot == conn.Slot && gen == (ushort)conn.TagGen && got == bid,
                            $"buffer {bid} came back as {got}, of slot {slot} under tag {gen}, not {conn.Slot} and {conn.TagGen}");
                    }
                    else
                    {
                        Assert.True(ReturnQOf(reactor).TryDequeue(out ushort got) && got == bid, $"buffer {bid} was not handed back (shared ring)");
                    }
                }
            }
        });

        runner.Test("move: two connections in one slot never share a tag, accepted there or given there", () =>
        {
            Reactor a = NeverRunning(0), b = NeverRunning(1);
            var seen = new HashSet<int>();
            for (int i = 0; i < 200; i++)
            {
                var conn = new TcpConnection(i % 3 == 0 ? a : b, -1, 64, 8);
                if (i % 3 == 0)
                {
                    Track(a, conn);
                    Untrack(a, conn);
                    FreeSlotsOf(a).Push(conn.Slot);
                    conn.LeaveFor(b);
                    Assert.Equal(-1, conn.Slot);
                }
                Track(b, conn);
                conn.ArriveOn(b);
                Assert.Equal(0, conn.Slot);
                Assert.True(seen.Add(conn.TagGen), $"tag generation {conn.TagGen} came twice");
                Untrack(b, conn);
                FreeSlotsOf(b).Push(conn.Slot);
                conn.Dispose();
            }
        });

        runner.Test("move: whose a connection is: its reactor's, and on that reactor's thread, once given away, the taker's", () =>
        {
            Reactor a = NeverRunning(0), b = NeverRunning(1);
            var conn = new TcpConnection(a, -1, 64, 8);
            Assert.True(ReferenceEquals(conn.Reactor, a), "a new connection is another reactor's");

            conn.LeaveFor(b);
            Assert.True(ReferenceEquals(conn.Reactor, a), "to another thread it has arrived before it did");   // which passes on what it is sent
            ThreadOf(a) = Environment.CurrentManagedThreadId;
            Assert.True(ReferenceEquals(conn.Reactor, b), "to the thread that gave it away it is still its own");
            ThreadOf(a) = 0;
            ThreadOf(b) = Environment.CurrentManagedThreadId;
            Assert.True(ReferenceEquals(conn.Reactor, a), "to the taker's thread it is the taker's before it was taken");

            Track(b, conn);
            conn.ArriveOn(b);
            Assert.True(ReferenceEquals(conn.Reactor, b), "to the taker's thread it is not the taker's");
            ThreadOf(b) = 0;
            ThreadOf(a) = Environment.CurrentManagedThreadId;
            Assert.True(ReferenceEquals(conn.Reactor, b), "to the thread it left it is not the taker's");
            ThreadOf(a) = 0;
            Assert.True(ReferenceEquals(conn.Reactor, b), "to another thread it has not arrived");
        });

        runner.Test("move: nothing of a move is left to the connection's next life", () =>
        {
            Reactor a = NeverRunning(0);
            var conn = new TcpConnection(a, -1, 64, 8) { Pinned = true, MoveState = TcpConnection.MoveWaiting, MoveTo = a, Weight = 5, WeighedTick = 7 };
            conn.Clear();
            Assert.True(!conn.Pinned && conn.MoveState == TcpConnection.MoveNone && conn.MoveTo is null && conn.Weight == 0 && conn.WeighedTick == long.MinValue,
                "a new life begins with what the last one ended with");
        });

        runner.Test("move: a group id is promised once, and a promise kept or taken back", () =>
        {
            var config = new ServerConfig { ReactorCount = 1, Udp = null, Tcp = new TcpOptions(), Incremental = new IncrementalOptions { MaxConnections = 3, RecvSlots = 2, RecvBufferSize = 64 } };
            var reactor = new Reactor(0, config);
            InitIncremental(reactor);
            Assert.Equal(3, RoomOf(reactor));
            Assert.True(TryReserveGid(reactor) && TryReserveGid(reactor) && TryReserveGid(reactor), "fewer than there are were promised");
            Assert.True(!TryReserveGid(reactor), "more than there are were promised");
            UnreserveGid(reactor);
            Assert.Equal(1, RoomOf(reactor));
            Assert.True(TryReserveGid(reactor) && !TryReserveGid(reactor), "one was taken back, and not one was to be had");

            // As many threads as there are ids, and more: each is promised once.
            for (int i = 0; i < 3; i++)
            {
                UnreserveGid(reactor);
            }
            for (int round = 0; round < 200; round++)
            {
                int promised = 0;
                Parallel.For(0, 8, _ =>
                {
                    if (TryReserveGid(reactor))
                    {
                        Interlocked.Increment(ref promised);
                    }
                });
                Assert.True(promised <= 3, $"{promised} of 3 were promised");
                for (int i = 0; i < promised; i++)
                {
                    UnreserveGid(reactor);
                }
                Assert.Equal(3, RoomOf(reactor));
            }
        });
    }

    // One that can move, as a fleet's are (TcpOptions.Rebalance), whose receives carry its life.
    private static TcpConnection Connection()
    {
        var conn = new TcpConnection(NeverRunning(0), -1, 64, 8) { Movable = true };
        conn.InitRefs();
        return conn;
    }

    private static unsafe void GrowsTheLast(TcpConnection conn)
    {
        byte* buffer = (byte*)System.Runtime.InteropServices.NativeMemory.Alloc(64);
        try
        {
            Assert.True(conn.Complete(4, 5, hasBuffer: true, ptr: buffer), "the queue is full");
            Assert.True(conn.TryExtendRecv(3, 5, buffer + 4), $"a slice continuing the last item did not grow it (movable: {conn.Movable})");
            Assert.True(conn.TryGetItem(Snapshot(conn), out SpscRecvRing.Item item) && item.Len == 7, "the item is not the two slices");
            conn.ReturnBuffer(in item);
        }
        finally
        {
            System.Runtime.InteropServices.NativeMemory.Free(buffer);
        }
    }

    // As its reactor does with what a recv brought, stamped as it stamps it.
    private static unsafe void Receive(TcpConnection conn, ushort bid)
        => Assert.True(conn.Complete(0, bid, hasBuffer: true, ptr: null), "the queue is full");

    private static Reactor NeverRunning(int id) => new(id, new ServerConfig { ReactorCount = 2, Tcp = new TcpOptions(), Udp = null });

    private static unsafe void Deliver(TcpConnection conn, ushort bid)
        => Assert.True(RecvOf(conn).TryEnqueue(new SpscRecvRing.Item { Ptr = null, Bid = bid, Len = 0, HasBuffer = true, Gen = (ushort)conn.Generation }), "the queue is full");

    private static RecvSnapshot Snapshot(TcpConnection conn)
    {
        ValueTask<RecvSnapshot> read = conn.ReadAsync();
        Assert.True(read.IsCompleted, "the read waits");
        return read.Result;
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_recv")]
    private static extern ref SpscRecvRing RecvOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushInProgress")]
    private static extern ref int InProgressOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_refs")]
    private static extern ref int RefsOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_reactorThreadId")]
    private static extern ref int ThreadOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Track")]
    private static extern void Track(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "JoinFleet")]
    private static extern void JoinFleet(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_returned")]
    private static extern ref long ReturnedOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_returnQ")]
    private static extern ref Mpsc<ushort> ReturnQOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_returnQInc")]
    private static extern ref Mpsc<ulong>? ReturnQIncOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.StaticMethod, Name = "UnpackReturn")]
    private static extern void UnpackReturn(Reactor? type, ulong packed, out int slot, out ushort gen, out ushort bid);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Untrack")]
    private static extern void Untrack(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_freeSlots")]
    private static extern ref Stack<int> FreeSlotsOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "ConnAt")]
    private static extern TcpConnection? ConnAt(Reactor reactor, int slot, ushort gen);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "InitIncremental")]
    private static extern void InitIncremental(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "TryReserveGid")]
    private static extern bool TryReserveGid(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "UnreserveGid")]
    private static extern void UnreserveGid(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_freeGidCount")]
    private static extern ref int FreeGidCountOf(Reactor reactor);

    private static int RoomOf(Reactor reactor) => Volatile.Read(ref FreeGidCountOf(reactor));
}
