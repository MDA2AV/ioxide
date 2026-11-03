using System.Buffers.Binary;

namespace ioxide;

/// <summary>
/// A QUIC connection ID (RFC 9000 §5.1: 0-20 bytes), packed into a fixed-size value type so it can
/// key the demux dictionary without allocation. Server-minted CIDs are random, so the default
/// (per-process-randomized) hash is collision-resistant against remote attackers.
/// </summary>
public readonly struct QuicCid : IEquatable<QuicCid>
{
    public const int MaxLength = 20;

    private readonly ulong _a;   // bytes 0-7   (zero-padded past Length)
    private readonly ulong _b;   // bytes 8-15
    private readonly uint  _c;   // bytes 16-19
    private readonly byte  _len;

    public int Length => _len;

    /// <summary>
    /// The first byte, which is where a server-minted id carries its owning reactor. Zero for an
    /// empty id. <c>_a</c> is the little-endian read of bytes 0-7, so its low byte is byte 0.
    /// </summary>
    public byte FirstByte => (byte)(_a & 0xFF);

    public QuicCid(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaxLength)
        {
            throw new ArgumentException($"connection id length {bytes.Length} exceeds {MaxLength}", nameof(bytes));
        }
        Span<byte> tmp = stackalloc byte[24];
        tmp.Clear();
        bytes.CopyTo(tmp);
        _a   = BinaryPrimitives.ReadUInt64LittleEndian(tmp);
        _b   = BinaryPrimitives.ReadUInt64LittleEndian(tmp[8..]);
        _c   = BinaryPrimitives.ReadUInt32LittleEndian(tmp[16..]);
        _len = (byte)bytes.Length;
    }

    public bool Equals(QuicCid other) => _a == other._a && _b == other._b && _c == other._c && _len == other._len;
    public override bool Equals(object? obj) => obj is QuicCid other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(_a, _b, _c, _len);
    public override string ToString() => $"cid[{_len}]{_a:x16}{_b:x16}{_c:x8}";
}
