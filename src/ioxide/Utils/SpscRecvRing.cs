using System.Runtime.CompilerServices;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide.utils;

public sealed unsafe class SpscRecvRing
{
    public struct Item
    {
        public byte* Ptr;
        public ushort Bid;
        public int Len;
        public bool HasBuffer;
        public ushort Gen;   // connection generation when enqueued (incremental return guard)

        public ReadOnlySpan<byte> AsSpan() => new(Ptr, Len);

        public UnmanagedMemoryManager AsMemoryManager() => new(Ptr, Len, Bid, Gen);
    }

    private readonly Item[] _items;
    private readonly int _mask;
    private long _tail;
    private long _head;

    public SpscRecvRing(int capacityPow2)
    {
        if (capacityPow2 <= 0 || (capacityPow2 & (capacityPow2 - 1)) != 0)
        {
            throw new ArgumentException("capacity must be a power of two", nameof(capacityPow2));
        }

        _items = new Item[capacityPow2];
        _mask  = capacityPow2 - 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryEnqueue(in Item item)
    {
        long head = Volatile.Read(ref _head);
        long tail = _tail;

        if ((ulong)(tail - head) >= (ulong)_items.Length)
        {
            return false;
        }

        _items[(int)(tail & _mask)] = item;
        Volatile.Write(ref _tail, tail + 1);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryDequeue(out Item item)
    {
        long head = _head;
        long tail = Volatile.Read(ref _tail);

        if (head >= tail)
        {
            item = default;
            return false;
        }

        item = _items[(int)(head & _mask)];
        Volatile.Write(ref _head, head + 1);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public long SnapshotTail() => Volatile.Read(ref _tail);

    /// <summary>Items between the current head and <paramref name="tailSnapshot"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int CountUntil(long tailSnapshot) => (int)Math.Max(0, tailSnapshot - _head);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryDequeueUntil(long tailSnapshot, out Item item)
    {
        long head = _head;

        if (head >= tailSnapshot)
        {
            item = default;
            return false;
        }

        item = _items[(int)(head & _mask)];
        Volatile.Write(ref _head, head + 1);

        return true;
    }

    // The length a consumer leaves in the last item as it takes it, so an extension racing the take fails.
    private const int Taken = -1;

    /// <summary>
    /// Producer: grows the last item by a slice that continues it in the same buffer, instead of queueing
    /// the slice as an item of its own. False when there is no such item, or the consumer has taken it.
    /// </summary>
    public bool TryExtendLast(byte* ptr, int len, ushort bid, ushort gen)
    {
        long tail = _tail;
        if (tail <= Volatile.Read(ref _head))
        {
            return false;
        }

        ref Item last = ref _items[(int)((tail - 1) & _mask)];
        int had = Volatile.Read(ref last.Len);
        if (had < 0 || last.Bid != bid || last.Gen != gen || last.Ptr + had != ptr)
        {
            return false;
        }

        // Against TryTakeUntil's claim: one of the two has the length.
        return Interlocked.CompareExchange(ref last.Len, had + len, had) == had;
    }

    /// <summary>
    /// <see cref="TryDequeueUntil"/> for a ring whose producer extends its last item: that item's length
    /// is claimed as it is taken, so an extension lands before the take or not at all.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryTakeUntil(long tailSnapshot, out Item item)
    {
        long head = _head;

        if (head >= tailSnapshot)
        {
            item = default;
            return false;
        }

        // The tail before the item: one the producer has moved past is final.
        bool last = head == Volatile.Read(ref _tail) - 1;
        ref Item slot = ref _items[(int)(head & _mask)];
        item = slot;
        if (last)
        {
            item.Len = Interlocked.Exchange(ref slot.Len, Taken);
        }
        Volatile.Write(ref _head, head + 1);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool IsEmpty() => Volatile.Read(ref _head) >= Volatile.Read(ref _tail);

    // Reactor-thread-only, called during connection teardown (Clear) when no
    // handler is consuming. Discards any leftover items so the recycled
    // connection starts empty.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset()
    {
        _head = 0;
        _tail = 0;
    }
}
