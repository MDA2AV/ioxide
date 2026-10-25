using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// The reactor's pool of Segmented overflow slabs: rented on the writer's thread, wherever its handler
/// runs, and returned on the reactor's when the send that carried them completes (#402).
/// </summary>
internal static unsafe class WriteSlabPoolTests
{
    private const int Threads = 4;
    private const int RoundsPerThread = 100_000;
    private const int MinObserved = 10_000;

    public static void Register(Runner runner)
    {
        runner.Test("reactor: a write slab is never out to two renters at once, whichever threads rent and return it", () =>
        {
            // Four threads take a slab, hold it a moment and hand it back, as writers on pool threads
            // and the reactor's send completions do. A slab already out to one must never be handed to
            // another: two connections would write into each other's responses, and the pool would
            // later free that slab twice. The pool was a bare Stack<nint>, whose push and pop corrupt
            // it when they overlap.
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });
            var live = new ConcurrentDictionary<nint, int>();
            var everRented = new ConcurrentDictionary<nint, byte>();
            int handedOutTwice = 0, reused = 0, overlapped = 0, inFlight = 0;
            Exception? fault = null;
            using var start = new Barrier(Threads);

            Thread[] threads = Enumerable.Range(0, Threads).Select(t => new Thread(() =>
            {
                try
                {
                    start.SignalAndWait();
                    for (int i = 0; i < RoundsPerThread; i++)
                    {
                        if (Interlocked.Increment(ref inFlight) > 1)
                        {
                            Interlocked.Increment(ref overlapped);   // another renter is mid-round with this one
                        }

                        nint slab = reactor.RentWriteSlab();
                        if (!everRented.TryAdd(slab, 0))
                        {
                            Interlocked.Increment(ref reused);   // it came back out of the pool
                        }
                        if (!live.TryAdd(slab, t))
                        {
                            Interlocked.Increment(ref handedOutTwice);
                        }

                        Thread.SpinWait(i % 16);
                        live.TryRemove(slab, out _);
                        reactor.ReturnWriteSlab(slab);
                        Interlocked.Decrement(ref inFlight);
                    }
                }
                catch (Exception e)
                {
                    fault ??= e;
                }
            }) { IsBackground = true, Name = $"slab-renter-{t}" }).ToArray();

            foreach (Thread thread in threads)
            {
                thread.Start();
            }
            foreach (Thread thread in threads)
            {
                thread.Join();
            }

            // The reactor never ran, so nothing drains its pool: free every slab once, by address,
            // whatever the pool holds - twice over, if it is broken.
            foreach (nint slab in everRented.Keys)
            {
                NativeMemory.AlignedFree((void*)slab);
            }
            Pool(reactor).Clear();

            Assert.True(fault == null, $"the pool threw under concurrent use: {fault?.GetType().Name}: {fault?.Message}");
            Assert.True(overlapped >= MinObserved, $"only {overlapped} rounds overlapped another renter's: the race never ran");
            Assert.True(reused >= MinObserved, $"only {reused} rents came back out of the pool: it was never exercised");
            Assert.True(handedOutTwice == 0, $"{handedOutTwice} rents handed out a slab another renter still held");
        }, skip: Environment.ProcessorCount < 2);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_writeSlabPool")]
    private static extern ref Stack<nint> Pool(Reactor reactor);
}
