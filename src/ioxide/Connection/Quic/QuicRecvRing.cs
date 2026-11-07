using System.Runtime.CompilerServices;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>What a recv item describes: stream bytes, or a stream lifecycle event (the peer closed,
/// reset, or refused the stream). Events ride the same queue so the handler sees them in order
/// with the data.</summary>
public enum QuicStreamEvent : byte
{
    Data        = 0,
    Closed      = 1,   // stream fully closed (normal end or after abort)
    Reset       = 2,   // peer aborted its sending side (RESET_STREAM)
    StopSending = 3,   // we stopped reading this stream; a peer's STOP_SENDING is not this, see OnSendRefused
}

/// <summary>
/// SPSC queue of decrypted QUIC stream events: producer is the engine on the reactor thread
/// (inside iq_conn_read), consumer is the connection handler. QUIC's mirror of the TCP recv ring -
/// same head/tail discipline, separate type: items carry stream id + fin and a pooled copy of the
/// bytes instead of a buffer-ring slot (ngtcp2's spans die when iq_conn_read returns).
/// </summary>
public sealed class QuicRecvRing
{
    public struct Delivery
    {
        public long StreamId;
        public bool Fin;
        public byte[]? Buf;   // pooled copy (ArrayPool); null on fin-only and lifecycle items
        public int Len;
        public QuicStreamEvent Kind;
        public ulong AppError;   // lifecycle items: the peer's application error code

        public ReadOnlySpan<byte> AsSpan() => Buf is null ? default : Buf.AsSpan(0, Len);
    }

    private readonly Delivery[] _items;
    private readonly int _mask;
    private long _tail;
    private long _head;

    public QuicRecvRing(int capacityPow2)
    {
        if (capacityPow2 <= 0 || (capacityPow2 & (capacityPow2 - 1)) != 0)
        {
            throw new ArgumentException("capacity must be a power of two", nameof(capacityPow2));
        }

        _items = new Delivery[capacityPow2];
        _mask  = capacityPow2 - 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryEnqueue(in Delivery item)
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
    public bool TryDequeue(out Delivery item)
    {
        long head = _head;
        long tail = Volatile.Read(ref _tail);

        if (head >= tail)
        {
            item = default;
            return false;
        }

        item = _items[(int)(head & _mask)];
        _items[(int)(head & _mask)] = default;   // drop the array ref so the pool copy isn't pinned by the ring
        Volatile.Write(ref _head, head + 1);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public long SnapshotTail() => Volatile.Read(ref _tail);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryDequeueUntil(long tailSnapshot, out Delivery item)
    {
        long head = _head;

        if (head >= tailSnapshot)
        {
            item = default;
            return false;
        }

        item = _items[(int)(head & _mask)];
        _items[(int)(head & _mask)] = default;
        Volatile.Write(ref _head, head + 1);

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool IsEmpty() => Volatile.Read(ref _head) >= Volatile.Read(ref _tail);
}
