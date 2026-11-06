using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A post made as its reactor stops. The poster enqueues and then reads the closed flag, the reactor sets
/// the flag and then drains, so one of the two has to see the other and take the post: a post left queued
/// is a switch that waits forever.
/// </summary>
/// <remarks>
/// The real post and drain, on a reactor that never runs, with this test doing the last two lines of
/// Teardown: a real teardown is too slow to aim a post at a gap of nanoseconds.
/// </remarks>
internal static class StoppedPostTests
{
    private const int Passes = 10;   // each with a new thread, so the OS places the two sides differently
    private const int BudgetMs = 10_000;   // a busy box has the two sides take turns on one CPU, at tens of us a round
    private const int MinOverlapped = 1_000;

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_postsClosed")]
    private static extern ref bool PostsClosedOf(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "DrainStoppedPosts")]
    private static extern void DrainStoppedPosts(Reactor reactor);

    public static void Register(Runner runner)
    {
        runner.Test("reactor: a post made as it stops is taken by the poster or the last drain, never left queued", () =>
        {
            Reactor reactor = WaiterSlotTests.NeverRunning();
            var queued = (ICollection)typeof(Reactor).GetField("_postQ", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(reactor)!;

            // Kept busy by a third thread. The store below has to win this line first and stores publish in
            // order, so the closed flag stays unpublished behind it while the drain reads on, widening the gap.
            var contended = new long[64];
            bool raced = false;
            var contender = new Thread(() =>
            {
                for (int n = 0; !Volatile.Read(ref raced); n++)
                {
                    Volatile.Write(ref contended[32], 1);
                    if (n % 4096 == 0)
                    {
                        Thread.Yield();   // on a busy box, the two sides still get to run
                    }
                }
            }) { IsBackground = true, Name = "stopped-post-contender" };
            contender.Start();

            int started = 0, finished = 0, overlapped = 0, stranded = 0;
            long deadline = Environment.TickCount64 + BudgetMs;
            try
            {
                for (int pass = 0; pass < Passes && stranded == 0 && Environment.TickCount64 < deadline; pass++)
                {
                    started = finished = 0;
                    WaiterSlotTests.Race(
                        setup: _ => PostsClosedOf(reactor) = false,
                        here: i =>
                        {
                            Volatile.Write(ref contended[32], 2);
                            Volatile.Write(ref PostsClosedOf(reactor), true);
                            DrainStoppedPosts(reactor);

                            if (Volatile.Read(ref started) == i && Volatile.Read(ref finished) != i)
                            {
                                overlapped++;   // the stop finished while the post was being made
                            }
                        },
                        there: i =>
                        {
                            Volatile.Write(ref started, i);
                            reactor.ScheduleOnReactor(static _ => { }, null);
                            Volatile.Write(ref finished, i);
                        },
                        check: _ =>
                        {
                            if (queued.Count != 0)
                            {
                                stranded++;
                                DrainStoppedPosts(reactor);
                            }
                        });
                }
            }
            finally
            {
                Volatile.Write(ref raced, true);
                contender.Join();
            }

            Assert.True(stranded == 0, $"{stranded} posts read the reactor as open after its last drain found the queue empty, so nothing will ever run them");
            Assert.True(overlapped >= MinOverlapped, $"only {overlapped} stops finished during a post: the race never ran");
        }, skip: Environment.ProcessorCount < 3);   // three threads that spin: with fewer CPUs the two sides never overlap
    }
}
