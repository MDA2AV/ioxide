using System.Buffers;
using epoxide.utils;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace epoxide;

/// <summary>
/// The connection as an <see cref="IBufferWriter{T}"/>: a response is written into a per-connection
/// slab. When it outgrows the slab the strategy is either Grow (realloc the buffer, TcpConnection.Write.Grow.cs)
/// or Segmented (spill into pooled segments, TcpConnection.Write.Segmented.cs). FlushAsync
/// (TcpConnection.Write.Flush.cs) then sends the buffered bytes.
/// </summary>
public sealed unsafe partial class TcpConnection : IBufferWriter<byte>
{
    // Current capacity of the per-connection write slab. Starts at _baseSlabSize and grows on demand
    // (GrowWriteSlab) when a response is larger than the slab; restored to _baseSlabSize on recycle.
    private int _writeSlabSize;
    private int _baseSlabSize;
    internal byte* WriteBuffer;
    internal int   WriteHead;
    internal int   WriteTail;
    internal int   WriteInFlight;

    // Write-overflow strategy, chosen once at construction. Grow (default) reallocs the primary slab;
    // Segmented chains pooled slabs flushed via one sendmsg (TcpConnection.Write.Segmented.cs).
    private WriteOverflowStrategy _overflow;

    private readonly UnmanagedMemoryManager _manager;

#region IBufferWriter<byte>

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        if (Volatile.Read(ref _flushInProgress) != 0)
        {
            throw new InvalidOperationException("Cannot write while flush is in progress.");
        }

        int need = sizeHint < 1 ? 1 : sizeHint;

        // Segmented mode backs GetMemory only while the primary slab still fits; spanning overflow
        // segments would need a per-segment MemoryManager. The consumers that actually overflow
        // (BuffersExtensions / stream copies) go through GetSpan, so this stays on the fast path.
        if (_overflow == WriteOverflowStrategy.Segmented && (_inOverflow || WriteTail + need > _writeSlabSize))
        {
            throw new NotSupportedException("GetMemory across segmented overflow is not supported; use GetSpan.");
        }

        if (WriteTail + need > _writeSlabSize)
        {
            GrowWriteSlab(WriteTail + need);
        }

        return _manager.Memory.Slice(WriteTail, _writeSlabSize - WriteTail);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        if (Volatile.Read(ref _flushInProgress) != 0)
        {
            throw new InvalidOperationException("Cannot write while flush is in progress.");
        }

        return EnsureWritable(sizeHint < 1 ? 1 : sizeHint);
    }

    public void Advance(int count)
    {
        if (Volatile.Read(ref _flushInProgress) != 0)
        {
            throw new InvalidOperationException("Cannot write while flush is in progress.");
        }

        if (_inOverflow)
        {
            _ov![_ovCount - 1].Used += count;
        }
        else
        {
            WriteTail += count;
        }
    }

#endregion

    public void Write(ReadOnlySpan<byte> source)
    {
        if (Volatile.Read(ref _flushInProgress) != 0)
        {
            throw new InvalidOperationException("Cannot write while flush is in progress.");
        }

        // Grow mode: one contiguous copy into the (possibly grown) slab.
        if (_overflow == WriteOverflowStrategy.Grow)
        {
            int len = source.Length;
            if (WriteTail + len > _writeSlabSize)
            {
                GrowWriteSlab(WriteTail + len);
            }

            source.CopyTo(new Span<byte>(WriteBuffer + WriteTail, len));
            WriteTail += len;
            return;
        }

        // Segmented mode: spill across the primary slab and pooled overflow segments.
        while (source.Length > 0)
        {
            Span<byte> dst = EnsureWritable(1);
            int n = Math.Min(dst.Length, source.Length);
            source.Slice(0, n).CopyTo(dst);
            if (_inOverflow)
            {
                _ov![_ovCount - 1].Used += n;
            }
            else
            {
                WriteTail += n;
            }
            source = source.Slice(n);
        }
    }

    // Returns a writable span at the current write position. Grow: grow the contiguous slab
    // (TcpConnection.Write.Grow.cs). Segmented: stay in the primary slab until it fills, then write into
    // pooled overflow segments (TcpConnection.Write.Segmented.cs).
    private Span<byte> EnsureWritable(int need)
    {
        if (_overflow == WriteOverflowStrategy.Grow)
        {
            if (WriteTail + need > _writeSlabSize)
            {
                GrowWriteSlab(WriteTail + need);
            }
            return new Span<byte>(WriteBuffer + WriteTail, _writeSlabSize - WriteTail);
        }

        if (!_inOverflow)
        {
            if (WriteTail + need <= _writeSlabSize)
            {
                return new Span<byte>(WriteBuffer + WriteTail, _writeSlabSize - WriteTail);
            }
            RentOverflow(need);
        }
        else
        {
            ref OvSeg cur = ref _ov![_ovCount - 1];
            if (cur.Used + need > cur.Cap)
            {
                RentOverflow(need);
            }
        }

        ref OvSeg seg = ref _ov![_ovCount - 1];
        return new Span<byte>((byte*)seg.Ptr + seg.Used, seg.Cap - seg.Used);
    }
}
