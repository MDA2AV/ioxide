using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The slot a reactor gives a connection, on a reactor that never runs: which number it takes, when it is found by it,
/// and when the number goes to another connection.
/// </summary>
internal static class ConnectionSlotTests
{
    public static void Register(Runner runner)
    {
        runner.Test("slots: a connection takes the next number, and is found by it with its generation", () =>
        {
            const int Count = 2_500;   // past the table's first size
            Reactor reactor = NeverRunning();
            var conns = new TcpConnection[Count];
            for (int i = 0; i < Count; i++)
            {
                Track(reactor, conns[i] = Connection(reactor));
            }

            for (int i = 0; i < Count; i++)
            {
                Assert.Equal(i, conns[i].Slot);
                Assert.True(ReferenceEquals(At(reactor, i, conns[i]), conns[i]), $"connection {i} is not at its slot");
                Assert.True(ConnAt(reactor, i, (ushort)(conns[i].Generation + 1)) is null, $"slot {i} was found by another generation");
            }
            Assert.True(ConnAt(reactor, Count, 0) is null && ConnAt(reactor, -1, 0) is null && ConnAt(reactor, int.MaxValue, 0) is null,
                "a slot past the ones handed out was found");
            Assert.Equal(Count, SlotsUsedOf(reactor));

            // Every slot back, and taken again by as many.
            foreach (TcpConnection conn in conns)
            {
                Recycled(reactor, conn);
            }
            var again = new TcpConnection[Count];
            for (int i = 0; i < Count; i++)
            {
                Track(reactor, again[i] = Connection(reactor));
            }
            Assert.Equal(Count, again.Select(c => c.Slot).Distinct().Count());
            Assert.Equal(Count, SlotsUsedOf(reactor));

            foreach (TcpConnection conn in conns.Concat(again))
            {
                conn.Dispose();
            }
        });

        runner.Test("slots: one out of the table is not found, and its number is not given to another before it is recycled", () =>
        {
            Reactor reactor = NeverRunning();
            TcpConnection a = Tracked(reactor), b = Tracked(reactor), c = Tracked(reactor);
            (int slot, ushort generation) = (b.Slot, (ushort)b.Generation);
            Assert.Equal(3, LiveOf(reactor));

            Untrack(reactor, b);
            Assert.True(ConnAt(reactor, slot, generation) is null, "a connection out of the table was found");
            Assert.Equal(3, LiveOf(reactor));   // a stop still waits for it
            TcpConnection d = Tracked(reactor);
            Assert.True(d.Slot != slot, "its slot was given away before it was recycled");
            Assert.Equal(4, LiveOf(reactor));

            FreeSlotsOf(reactor).Push(slot);
            Assert.Equal(3, LiveOf(reactor));
            TcpConnection e = Tracked(reactor);
            Assert.Equal(4, LiveOf(reactor));
            Assert.Equal(slot, e.Slot);
            Assert.True(ConnAt(reactor, slot, generation) is null, "a tag of the connection before was served the slot's new one");
            Assert.True(ReferenceEquals(At(reactor, slot, e), e), "the slot's new connection is not found by it");

            foreach (TcpConnection conn in new[] { a, b, c, d, e })
            {
                conn.Dispose();
            }
        });

        runner.Test("slots: the last one freed is the first one taken, and the table is only as long as the most held at once", () =>
        {
            Reactor reactor = NeverRunning();
            TcpConnection a = Tracked(reactor), b = Tracked(reactor), c = Tracked(reactor);
            Recycled(reactor, a);
            Recycled(reactor, c);
            TcpConnection d = Tracked(reactor), e = Tracked(reactor), f = Tracked(reactor);
            Assert.Equal(2, d.Slot);
            Assert.Equal(0, e.Slot);
            Assert.Equal(3, f.Slot);
            Assert.Equal(4, SlotsUsedOf(reactor));

            for (int i = 0; i < 10_000; i++)
            {
                TcpConnection next = Tracked(reactor);
                Recycled(reactor, next);
                next.Dispose();
            }
            Assert.Equal(5, SlotsUsedOf(reactor));

            foreach (TcpConnection conn in new[] { a, b, c, d, e, f })
            {
                conn.Dispose();
            }
        });

        RegisterWalk(runner, "tick", TcpSweep);
        RegisterWalk(runner, "stop", CloseTcpConnections);
    }

    // Both walks, over a table that has grown twice and has gaps at its start, all through it and at its end.
    private static void RegisterWalk(Runner runner, string walk, Action<Reactor> run)
    {
        runner.Test($"slots: the {walk}'s walk reaches every connection in a table that has grown and has gaps, and none out of it", () =>
        {
            const int Count = 2_500;
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = new TcpOptions { SendTimeoutMs = 500, ReadTimeoutMs = 0 }, Udp = null });
            var conns = new TcpConnection[Count];
            for (int i = 0; i < Count; i++)
            {
                TcpConnection conn = conns[i] = Tracked(reactor);
                conn.InitRefs();
                InProgressOf(conn) = 1;   // a flush the kernel has had for ten seconds
                ArmedOf(conn) = 2;
                conn.FlushArmedMs = Native.MonotonicMs - 10_000;
            }

            bool InTable(int i) => i % 3 == 1 && i < Count - 100;
            for (int i = 0; i < Count; i++)
            {
                if (!InTable(i))
                {
                    Recycled(reactor, conns[i]);
                }
            }

            run(reactor);

            for (int i = 0; i < Count; i++)
            {
                Assert.True(conns[i].SweepClosed == InTable(i), $"connection {i}, in the table: {InTable(i)}, closed: {conns[i].SweepClosed}");
                conns[i].Dispose();
            }
        });
    }

    private static Reactor NeverRunning() => new(0, new ServerConfig { ReactorCount = 1, Tcp = new TcpOptions(), Udp = null });

    // fd -1: nothing here touches a socket.
    private static TcpConnection Connection(Reactor reactor) => new(reactor, -1, 64, 8);

    private static TcpConnection Tracked(Reactor reactor)
    {
        TcpConnection conn = Connection(reactor);
        Track(reactor, conn);
        return conn;
    }

    // What a connection's end does to the table: out of it, and later, at its recycle, its slot back.
    private static void Recycled(Reactor reactor, TcpConnection conn)
    {
        Untrack(reactor, conn);
        FreeSlotsOf(reactor).Push(conn.Slot);
    }

    private static TcpConnection? At(Reactor reactor, int slot, TcpConnection expected) => ConnAt(reactor, slot, (ushort)expected.Generation);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Track")]
    private static extern void Track(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Untrack")]
    private static extern void Untrack(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_freeSlots")]
    private static extern ref Stack<int> FreeSlotsOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_TcpLive")]
    private static extern int LiveOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "TcpSweep")]
    private static extern void TcpSweep(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "CloseTcpConnections")]
    private static extern void CloseTcpConnections(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushInProgress")]
    private static extern ref int InProgressOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushArmed")]
    private static extern ref int ArmedOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "ConnAt")]
    private static extern TcpConnection? ConnAt(Reactor reactor, int slot, ushort gen);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_slotsUsed")]
    private static extern ref int SlotsUsedOf(Reactor reactor);
}
