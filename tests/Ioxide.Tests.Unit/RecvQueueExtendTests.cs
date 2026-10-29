using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// What incremental mode's receive queue merges (#431): a slice that continues the last item queued, in
/// its buffer and life, grows that item; anything else, and an item already taken, is left alone.
/// </summary>
internal static unsafe class RecvQueueExtendTests
{
    // A plausible slab address; the queue never dereferences what it holds.
    private static readonly byte* Slab = (byte*)0x7F00_0000_0000;

    public static void Register(Runner runner)
    {
        runner.Test("recv queue: a slice continuing the last item, in its buffer, grows it", () =>
        {
            var queue = new SpscRecvRing(4);
            Assert.True(queue.TryEnqueue(Item(Slab, 10, bid: 1, gen: 3)), "the first slice was refused");

            Assert.True(queue.TryExtendLast(Slab + 10, 5, bid: 1, gen: 3), "a slice continuing it did not grow it");
            Assert.True(queue.TryExtendLast(Slab + 15, 1, bid: 1, gen: 3), "a second slice continuing it did not grow it");

            Assert.True(queue.TryTakeUntil(queue.SnapshotTail(), out SpscRecvRing.Item taken), "nothing to take");
            Assert.Equal(16, taken.Len);
            Assert.True(taken.Ptr == Slab, "the grown item moved");
            Assert.True(!queue.TryTakeUntil(queue.SnapshotTail(), out _), "a grown slice was also queued on its own");
        });

        runner.Test("recv queue: a slice off the last item's end, in another buffer or another life is not merged", () =>
        {
            var queue = new SpscRecvRing(4);
            Assert.True(!queue.TryExtendLast(Slab, 1, bid: 1, gen: 3), "an empty queue took a growth");

            queue.TryEnqueue(Item(Slab, 10, bid: 1, gen: 3));
            Assert.True(!queue.TryExtendLast(Slab + 11, 1, bid: 1, gen: 3), "a slice past a gap was merged");
            Assert.True(!queue.TryExtendLast(Slab + 9, 1, bid: 1, gen: 3), "a slice overlapping the item was merged");
            Assert.True(!queue.TryExtendLast(Slab + 10, 1, bid: 2, gen: 3), "a slice in another buffer was merged");
            Assert.True(!queue.TryExtendLast(Slab + 10, 1, bid: 1, gen: 4), "a slice from another life was merged");

            Assert.True(queue.TryTakeUntil(queue.SnapshotTail(), out SpscRecvRing.Item taken), "nothing to take");
            Assert.Equal(10, taken.Len);
        });

        runner.Test("recv queue: only the last item grows, and one already taken stays as it was handed out", () =>
        {
            var queue = new SpscRecvRing(4);
            queue.TryEnqueue(Item(Slab, 10, bid: 1, gen: 3));
            queue.TryEnqueue(Item(Slab + 4096, 10, bid: 2, gen: 3));

            // The first item continues in its own buffer, but the producer has moved on from it.
            Assert.True(!queue.TryExtendLast(Slab + 10, 1, bid: 1, gen: 3), "an item before the last was grown");

            Assert.True(queue.TryTakeUntil(queue.SnapshotTail(), out SpscRecvRing.Item first), "nothing to take");
            Assert.Equal(10, first.Len);

            // Taken, the last item is its reader's: a slice continuing it is queued on its own, never merged
            // into an item that reader will not look at again. (A take racing the growth is the E2E test's.)
            Assert.True(queue.TryTakeUntil(queue.SnapshotTail(), out SpscRecvRing.Item last), "the last item was not taken");
            Assert.Equal(10, last.Len);
            Assert.True(!queue.TryExtendLast(Slab + 4096 + 10, 1, bid: 2, gen: 3), "a taken item was grown");
        });
    }

    private static SpscRecvRing.Item Item(byte* ptr, int len, ushort bid, ushort gen)
        => new() { Ptr = ptr, Len = len, Bid = bid, Gen = gen, HasBuffer = true };
}
