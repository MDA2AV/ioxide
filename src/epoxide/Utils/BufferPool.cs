using System.Runtime.InteropServices;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace epoxide.utils;

/// <summary>
/// Fixed-size native buffers that any thread can rent and return - recv buffers for a reactor's
/// connections, and the overflow slabs of a segmented write. epoll registers no memory with the
/// kernel, so the pool starts empty and grows a chunk at a time instead of being sized up front.
/// </summary>
/// <remarks>
/// A Treiber stack of buffer ids: the link to the next free id lives in the first four bytes of the
/// free buffer itself, and the head carries a 32-bit tag beside the id so a pop that raced a
/// pop-and-push of the same id fails its CAS instead of corrupting the list (ABA). Reading a link
/// out of a buffer another thread has just popped and is writing is harmless for the same reason -
/// that CAS fails and the read is thrown away - and the memory is never freed while the pool lives.
/// </remarks>
internal sealed unsafe class BufferPool : IDisposable
{
    private const int ChunkShift = 6;   // 64 buffers per chunk
    private const int ChunkMask = (1 << ChunkShift) - 1;

    private readonly int _bufferSize;

    // Bytes from one buffer to the next: the size asked for, but never less than the free-list link a
    // free buffer keeps in its first four bytes - so a one-byte buffer is legal, as in ioxide.
    private readonly int _stride;

    // Chunk base addresses. Replaced, never mutated in place, when it grows - a reader that took the
    // old array still finds every chunk it can have an id for.
    private nint[] _chunks = new nint[8];
    private int _chunkCount;
    private readonly object _growLock = new();

    // (tag << 32) | (id + 1); 0 in the low half is empty.
    private long _head;

    public BufferPool(int bufferSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);
        _bufferSize = bufferSize;
        _stride = Math.Max(bufferSize, sizeof(int));
    }

    public int BufferSize => _bufferSize;

    /// <summary>Every buffer this pool has allocated, free or rented.</summary>
    public int Count => Volatile.Read(ref _chunkCount) << ChunkShift;

    /// <summary>Take a buffer; grows the pool when none is free.</summary>
    public byte* Rent(out int id)
    {
        while (true)
        {
            long head = Volatile.Read(ref _head);
            int top = (int)head - 1;
            if (top < 0)
            {
                Grow();
                continue;
            }

            byte* buffer = Address(top);
            int next = *(int*)buffer;
            long replacement = ((head >> 32) + 1 << 32) | (uint)(next + 1);
            if (Interlocked.CompareExchange(ref _head, replacement, head) == head)
            {
                id = top;
                return buffer;
            }
        }
    }

    /// <summary>Give back a buffer from <see cref="Rent"/>, from any thread.</summary>
    public void Return(int id)
    {
        byte* buffer = Address(id);
        while (true)
        {
            long head = Volatile.Read(ref _head);
            *(int*)buffer = (int)head - 1;
            long replacement = ((head >> 32) + 1 << 32) | (uint)(id + 1);
            if (Interlocked.CompareExchange(ref _head, replacement, head) == head)
            {
                return;
            }
        }
    }

    public byte* Address(int id) => (byte*)Volatile.Read(ref _chunks)[id >> ChunkShift] + (nint)(id & ChunkMask) * _stride;

    private void Grow()
    {
        lock (_growLock)
        {
            // Another renter may have grown it, or a return refilled it, while this one waited.
            if ((int)Volatile.Read(ref _head) != 0)
            {
                return;
            }

            // In nuint: 64 buffers of 32 MiB or more is past int, and wrapped it asks for exabytes.
            nint chunk = (nint)NativeMemory.AlignedAlloc((nuint)_stride << ChunkShift, 64);
            int index = _chunkCount;
            if (index == _chunks.Length)
            {
                nint[] grown = new nint[_chunks.Length * 2];
                _chunks.CopyTo(grown, 0);
                Volatile.Write(ref _chunks, grown);
            }

            _chunks[index] = chunk;
            Volatile.Write(ref _chunkCount, index + 1);

            // Published before any of its ids can be popped: the push below is what makes them reachable.
            int first = index << ChunkShift;
            for (int i = (1 << ChunkShift) - 1; i >= 0; i--)
            {
                Return(first + i);
            }
        }
    }

    /// <summary>
    /// Free every chunk - only when every buffer is back, because a handler that outlived its reactor
    /// may still be reading one. Returns false, and keeps the memory, otherwise.
    /// </summary>
    public bool TryFree()
    {
        int free = 0;
        for (int top = (int)Volatile.Read(ref _head) - 1; top >= 0; top = *(int*)Address(top))
        {
            free++;
        }

        if (free != Count)
        {
            return false;
        }

        Dispose();
        return true;
    }

    public void Dispose()
    {
        for (int i = 0; i < _chunkCount; i++)
        {
            NativeMemory.AlignedFree((void*)_chunks[i]);
            _chunks[i] = 0;
        }
        _chunkCount = 0;
        _head = 0;
    }
}
