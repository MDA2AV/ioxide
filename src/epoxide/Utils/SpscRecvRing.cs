using System.Runtime.CompilerServices;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace epoxide.utils;

/// <summary>
/// A connection's received buffers, oldest first, waiting for its reader. One producer at a time -
/// the reader's own recv, or the reactor's on behalf of a parked reader, never both, since the read
/// state hands that role over with a CAS - and one consumer, the reader.
/// </summary>
public sealed unsafe class SpscRecvRing
{
    public struct Item
    {
        public byte* Ptr;
        public int Bid;
        public int Len;
        public bool HasBuffer;
        public ushort Gen;   // connection generation when enqueued

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool IsEmpty() => Volatile.Read(ref _head) >= Volatile.Read(ref _tail);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool IsFull() => Volatile.Read(ref _tail) - Volatile.Read(ref _head) >= _items.Length;

    // Recycle only: discards what is queued so the next life starts empty. The indices carry on
    // instead of restarting at 0, so a snapshot kept from a previous life, its tail now at or behind
    // the head, finds nothing to take.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset() => Volatile.Write(ref _head, Volatile.Read(ref _tail));
}
