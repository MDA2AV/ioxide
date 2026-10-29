using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="SpscRecvRing"/>, a connection's queue of recv completions (#427): order across wraps, its
/// capacity, and the snapshot a reader drains up to.
/// </summary>
/// <remarks>
/// Every field of item n derives from n, so an item out of place, torn or repeated shows.
/// </remarks>
internal static unsafe class SpscRecvRingTests
{
    // A plausible slab address; the ring never dereferences what it holds.
    private const long Slab = 0x7F00_0000_0000;

    public static void Register(Runner runner)
    {
        runner.Test("recv ring: items come out in order across many wraps of the ring", () =>
        {
            var ring = new SpscRecvRing(8);
            var random = new Random(416);
            int produced = 0, consumed = 0;

            // A random walk over every fill level, so head and tail meet each slot at every distance. The
            // two dequeues alternate: a handler's, up to its snapshot, and the recycle's drain.
            for (int step = 0; step < 20_000; step++)
            {
                int queued = produced - consumed;
                if (queued == 0 || (queued < 8 && random.Next(2) == 0))
                {
                    Assert.True(ring.TryEnqueue(ItemFor(produced)), $"item {produced} was refused with {queued} queued");
                    produced++;
                    continue;
                }

                SpscRecvRing.Item item;
                bool taken = random.Next(2) == 0
                    ? ring.TryDequeue(out item)
                    : ring.TryDequeueUntil(ring.SnapshotTail(), out item);
                Assert.True(taken, $"nothing came out with {queued} queued");
                AssertItem(consumed++, item);
            }

            while (ring.TryDequeue(out SpscRecvRing.Item rest))
            {
                AssertItem(consumed++, rest);
            }

            Assert.Equal(produced, consumed);
            Assert.True(produced > 8 * 1000, $"only {produced} items went through, too few wraps");
        });

        runner.Test("recv ring: an item past capacity is refused, and taken once a dequeue frees an entry", () =>
        {
            var ring = new SpscRecvRing(4);
            for (int n = 0; n < 4; n++)
            {
                Assert.True(ring.TryEnqueue(ItemFor(n)), $"item {n} was refused with room for it");
            }

            Assert.True(!ring.TryEnqueue(ItemFor(4)), "a fifth item fit in four entries");
            Assert.True(!ring.TryEnqueue(ItemFor(4)), "a fifth item fit in four entries on the second try");

            Assert.True(ring.TryDequeue(out SpscRecvRing.Item first), "a full ring gave nothing back");
            AssertItem(0, first);
            Assert.True(ring.TryEnqueue(ItemFor(4)), "the entry the dequeue freed was not taken");
            Assert.True(!ring.TryEnqueue(ItemFor(5)), "a fifth item fit after the freed entry was taken");

            // The refused attempts left no trace.
            for (int n = 1; n <= 4; n++)
            {
                Assert.True(ring.TryDequeue(out SpscRecvRing.Item item), $"item {n} was lost");
                AssertItem(n, item);
            }
            Assert.True(!ring.TryDequeue(out _), "an item came out of a drained ring");
        });

        runner.Test("recv ring: a dequeue stops at its snapshot's tail", () =>
        {
            var ring = new SpscRecvRing(8);
            for (int n = 0; n < 3; n++)
            {
                ring.TryEnqueue(ItemFor(n));
            }

            long snapshot = ring.SnapshotTail();
            for (int n = 3; n < 5; n++)
            {
                ring.TryEnqueue(ItemFor(n));   // after the snapshot: not that reader's yet
            }

            Assert.Equal(3, ring.CountUntil(snapshot));
            for (int n = 0; n < 3; n++)
            {
                Assert.True(ring.TryDequeueUntil(snapshot, out SpscRecvRing.Item item), $"item {n} was not taken through its snapshot");
                AssertItem(n, item);
            }
            Assert.True(!ring.TryDequeueUntil(snapshot, out _), "an item queued after the snapshot was taken through it");
            Assert.True(!ring.IsEmpty(), "the items queued after the snapshot were lost");

            long next = ring.SnapshotTail();
            for (int n = 3; n < 5; n++)
            {
                Assert.True(ring.TryDequeueUntil(next, out SpscRecvRing.Item item), $"item {n} was not taken through the next snapshot");
                AssertItem(n, item);
            }
            Assert.True(!ring.TryDequeueUntil(next, out _), "a drained ring gave an item through its snapshot");
            Assert.True(!ring.TryDequeueUntil(snapshot, out _), "an older snapshot took an item");
        });
    }

    private static SpscRecvRing.Item ItemFor(int n) => new()
    {
        Ptr = (byte*)(Slab + n * 4096L),
        Len = 1 + n % 4000,
        Bid = (ushort)(n & 0x7FFF),
        HasBuffer = n % 3 != 0,
        Gen = (ushort)(n * 3),
    };

    private static void AssertItem(int n, in SpscRecvRing.Item item)
    {
        SpscRecvRing.Item expected = ItemFor(n);
        Assert.True(item.Ptr == expected.Ptr && item.Len == expected.Len && item.Bid == expected.Bid
                    && item.HasBuffer == expected.HasBuffer && item.Gen == expected.Gen,
            $"item {n} came out as Ptr 0x{(nint)item.Ptr:x}, Len {item.Len}, Bid {item.Bid}, HasBuffer {item.HasBuffer}, Gen {item.Gen}");
    }
}
