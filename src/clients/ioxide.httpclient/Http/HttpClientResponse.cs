using System.Buffers;

using System.Runtime.CompilerServices;


namespace ioxide.httpclient;

/// <summary>
/// One HTTP/1.1 response - status, field lines and body as raw bytes. Headers and body slice ONE
/// pooled buffer owned by this object, copied out of the connection's receive buffer at parse
/// time, which is what lets the connection go straight back to the pool instead of being pinned
/// until you finish reading.
///
/// Dispose returns that buffer to the pool. Skipping it costs GC pressure, never a stuck
/// connection - but every memory here dangles onto recycled storage afterwards, so treat Dispose
/// as the end of the response's life:
///
/// <code>
/// using HttpClientResponse response = await pool.GetAsync("/health"u8);
/// if (response.Status == 200) { /* response.Body ... */ }
/// </code>
/// </summary>
public sealed class HttpClientResponse : IDisposable
{
    /// <summary>Status code from the status line, e.g. 200.</summary>
    public int Status { get; internal set; }

    /// <summary>Response field lines, in wire order, names lowercased by the parser.</summary>
    public KeyValueList Headers { get; } = new();

    /// <summary>Response body, already de-chunked when the peer used chunked encoding.</summary>
    public ReadOnlyMemory<byte> Body { get; internal set; }

    /// <summary>True when the server asked to close (or spoke HTTP/1.0 without keep-alive), so
    /// the connection cannot be reused.</summary>
    public bool ConnectionClose { get; internal set; }

    // Storage the memories above point into: header bytes first, then the body. Ranges are
    // recorded while it may still grow; Freeze materializes the public memories at the end.
    private byte[] _arena = [];
    private int _arenaUsed;
    private readonly List<(int NameOffset, int NameLength, int ValueOffset, int ValueLength)> _ranges = [];
    private (int Offset, int Length) _bodyRange = (0, -1);

    /// <summary>Current arena fill - the offset the next Append will land at.</summary>
    internal int ArenaLength => _arenaUsed;

    // Ceiling on headers + body for this response. h2 and h3 stream a response in through native
    // callbacks with no Content-Length to check up front, so this is the only thing bounding what
    // a hostile or broken origin can make us allocate.
    //
    // Unbounded by default, and deliberately so. This type is shared by all three protocols, and
    // HTTP/1.1 bounds its responses a different way - it reads Content-Length and rejects an
    // oversize body before allocating (HttpClientConnection), never consulting Overflowed. A
    // default ceiling here therefore did not protect h1, it silently TRUNCATED it: parsing
    // completed while the arena dropped bytes, and the caller got status 200 with empty headers
    // and an empty body. The protocols that need a ceiling ask for one.
    private int _maxArenaBytes = MaxArenaBytesLimit;

    // ArrayPool.Rent throws above this regardless of free memory, and Rent is reached from inside
    // [UnmanagedCallersOnly] callbacks - so this is a hard ceiling on what any caller may ask for,
    // not merely a default.
    private static readonly int MaxArenaBytesLimit = Array.MaxLength;

    /// <summary>
    /// True once an Append was refused for exceeding the cap. Appends are driven from
    /// <c>[UnmanagedCallersOnly]</c> callbacks, where a throw would cross native frames and take
    /// the process down, so the overflow is RECORDED here and the owning connection turns it into
    /// a failed request once the native call has unwound.
    /// </summary>
    internal bool Overflowed { get; private set; }

    /// <summary>
    /// Bound this response's arena. Clamped at both ends: a caller asking for more than
    /// <see cref="Array.MaxLength"/> would otherwise turn a large response into a Rent failure
    /// inside a native callback, which is the crash this ceiling exists to prevent.
    /// </summary>
    internal void SetMaxArenaBytes(int max) => _maxArenaBytes = Math.Clamp(max, 1, MaxArenaBytesLimit);

    internal (int Offset, int Length) Append(ReadOnlySpan<byte> data)
    {
        // Past the cap: drop the bytes and record it. Growing to serve an origin that has already
        // overrun its budget is the thing being prevented, and the request is going to fail
        // anyway, so nothing is gained by keeping the data.
        if (Overflowed || data.Length > _maxArenaBytes - _arenaUsed)
        {
            Overflowed = true;
            return (_arenaUsed, 0);
        }

        if (_arena.Length - _arenaUsed < data.Length)
        {
            // In long, because the doubling overflows int once the arena reaches 1 GiB: size went
            // negative, Math.Max picked 4096, and the loop then doubled its way to int.MinValue
            // for ArrayPool.Rent to throw on - inside a native callback.
            long size = Math.Max(4096, (long)_arena.Length * 2);
            long needed = (long)_arenaUsed + data.Length;
            while (size < needed)
            {
                size *= 2;
            }

            byte[] grown = ArrayPool<byte>.Shared.Rent((int)Math.Min(size, _maxArenaBytes));
            _arena.AsSpan(0, _arenaUsed).CopyTo(grown);
            if (_arena.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_arena);
            }
            _arena = grown;
        }

        data.CopyTo(_arena.AsSpan(_arenaUsed));
        (int Offset, int Length) range = (_arenaUsed, data.Length);
        _arenaUsed += data.Length;
        return range;
    }

    // Field names are compared lowercase throughout the surface; the parser lowercases them in
    // place right after copying, so no second buffer is needed.
    internal void LowercaseArena((int Offset, int Length) range)
    {
        Span<byte> span = _arena.AsSpan(range.Offset, range.Length);
        for (int i = 0; i < span.Length; i++)
        {
            if (span[i] is >= (byte)'A' and <= (byte)'Z')
            {
                span[i] |= 0x20;
            }
        }
    }

    internal void AddHeaderRange((int Offset, int Length) name, (int Offset, int Length) value)
        => _ranges.Add((name.Offset, name.Length, value.Offset, value.Length));

    internal void SetBodyRange((int Offset, int Length) range) => _bodyRange = range;

    /// <summary>Discard an interim (1xx) head and reuse the arena for the real response.</summary>
    internal void ResetForInterim()
    {
        _ranges.Clear();
        _arenaUsed = 0;
        _bodyRange = (0, -1);
        Status = 0;
        ConnectionClose = false;
        Overflowed = false;
    }

    internal void Freeze()
    {
        // Freeze runs inside the same native callbacks Append does, so it must not throw either.
        // An overflowed response is about to be discarded and its recorded ranges describe bytes
        // the arena refused, so materializing them would be both pointless and out of bounds.
        if (Overflowed)
        {
            _ranges.Clear();
            Body = default;
            return;
        }

        foreach ((int nameOffset, int nameLength, int valueOffset, int valueLength) in _ranges)
        {
            Headers.Add(_arena.AsMemory(nameOffset, nameLength), _arena.AsMemory(valueOffset, valueLength));
        }
        _ranges.Clear();

        Body = _bodyRange.Length < 0 ? default : _arena.AsMemory(_bodyRange.Offset, _bodyRange.Length);
    }

    /// <summary>First value for a field name (names are lowercase), or false when absent.</summary>
    public bool TryGetHeader(ReadOnlySpan<byte> name, out ReadOnlyMemory<byte> value) => Headers.TryGetValue(name, out value);

    public void Dispose()
    {
        Headers.Clear();
        Body = default;
        _bodyRange = (0, -1);
        _arenaUsed = 0;
        Overflowed = false;
        if (_arena.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_arena);
            _arena = [];
        }
    }
}
