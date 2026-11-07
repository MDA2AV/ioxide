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

    internal (int Offset, int Length) Append(ReadOnlySpan<byte> data)
    {
        if (_arena.Length - _arenaUsed < data.Length)
        {
            // In long and clamped to Array.MaxLength, so doubling past 1 GiB never overflows int.
            long size = Math.Max(4096, (long)_arena.Length * 2);
            long needed = (long)_arenaUsed + data.Length;
            if (needed > Array.MaxLength)
            {
                throw new HttpClientException("response is too large for one array");
            }

            while (size < needed)
            {
                size *= 2;
            }

            byte[] grown = ArrayPool<byte>.Shared.Rent((int)Math.Min(size, Array.MaxLength));
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
    }

    internal void Freeze()
    {
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
        if (_arena.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_arena);
            _arena = [];
        }
    }
}
