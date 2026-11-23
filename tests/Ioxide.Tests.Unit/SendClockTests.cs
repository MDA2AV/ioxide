using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The send clock, on a reactor that never runs: when a flush's time is written, and what the sweep does with a flush in
/// each state. Over sockets the kernel's own TCP_USER_TIMEOUT ends most stalls by itself, and hides a sweep that does not.
/// </summary>
internal static unsafe class SendClockTests
{
    private const int SendMs = 500;

    public static void Register(Runner runner)
    {
        // The arm is refused here, which shows what had come before it.
        runner.Test("send clock: a flush's time is on the clock before it arms", () =>
        {
            Reactor reactor = NeverRunning();
            TcpConnection conn = Connection(reactor);
            conn.Write("x"u8);
            ArmedOf(conn) = 1;
            Assert.Throws<InvalidOperationException>(() => conn.TryFlushOrPark(new Listener()), "already armed");
            Assert.True(reactor.NowMs > 0, "the reactor's clock never started");
            Assert.Equal(reactor.NowMs, conn.FlushArmedMs);
            conn.Dispose();
        });

        // Which is why the time is not written as soon as a flush is called: these would restart the deadline of the
        // flush in flight, or the read clock, which reads the same time.
        runner.Test("send clock: a call with nothing to send, or refused behind another flush, leaves the clock alone", () =>
        {
            TcpConnection conn = Connection(NeverRunning());
            conn.FlushArmedMs = 123;
            Assert.True(conn.FlushAsync().IsCompleted, "a flush with nothing staged waited");
            Assert.True(conn.TryFlushOrPark(new Listener()), "a flush with nothing staged parked");
            Assert.Equal(123L, conn.FlushArmedMs);

            InProgressOf(conn) = 1;
            Assert.Throws<InvalidOperationException>(() => _ = conn.FlushAsync(), "already in progress");
            Assert.Throws<InvalidOperationException>(() => _ = conn.TryFlushOrPark(new Listener()), "already in progress");
            Assert.True(conn.FlushIfIdleAsync().IsCompleted, "a teardown flush waited behind another");
            Assert.Equal(123L, conn.FlushArmedMs);
            conn.Dispose();
        });

        // Called and not armed, queued for the reactor, with the kernel.
        foreach ((int state, bool cut) in new[] { (0, false), (1, true), (2, true) })
        {
            runner.Test($"send clock: the sweep {(cut ? "cuts" : "leaves")} a flush in state {state} whose time is past the timeout", () =>
                Assert.Equal(cut, SweepCuts(state, agoMs: 20 * SendMs)));
        }

        runner.Test("send clock: the sweep leaves a flush with the kernel inside its timeout", () =>
            Assert.True(!SweepCuts(state: 2, agoMs: SendMs / 5), "cut inside its timeout"));
    }

    private static bool SweepCuts(int state, int agoMs)
    {
        Reactor reactor = NeverRunning();
        TcpConnection conn = Connection(reactor);
        conn.InitRefs();
        Track(reactor, conn);
        InProgressOf(conn) = 1;
        ArmedOf(conn) = state;
        ListenerOf(conn) = new Listener();   // what a close signals, for a flush the reactor has not claimed
        conn.FlushArmedMs = Native.MonotonicMs - agoMs;
        Sweep(reactor);

        bool cut = conn.SweepClosed;
        Assert.Equal(cut, conn.IsClosed);
        Untrack(reactor, conn);
        conn.Dispose();
        return cut;
    }

    private static Reactor NeverRunning() => new(0, new ServerConfig
    {
        ReactorCount = 1,
        Tcp = new TcpOptions { SendTimeoutMs = SendMs, ReadTimeoutMs = 0 },
        Udp = null,
    });

    // fd -1, so shutdown() has nothing to shut down.
    private static TcpConnection Connection(Reactor reactor) => new(reactor, -1, 64, 8);

    private sealed class Listener : IFlushListener
    {
        public void OnParking()
        {
        }

        public void OnFlushDone()
        {
        }
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushArmed")]
    private static extern ref int ArmedOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushInProgress")]
    private static extern ref int InProgressOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_flushListener")]
    private static extern ref IFlushListener? ListenerOf(TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Track")]
    private static extern void Track(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Untrack")]
    private static extern void Untrack(Reactor reactor, TcpConnection conn);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "TcpSweep")]
    private static extern void Sweep(Reactor reactor);
}
