using System.Runtime.CompilerServices;

namespace ioxide.http2;

/// <summary>
/// An ordered list of HTTP field lines as raw bytes - names and values both
/// <see cref="ReadOnlyMemory{T}"/>, never decoded to text. Enumerate with <see cref="AsSpan"/>.
/// Same shape as Glyph11's KeyValueList (the h1 stack's).
///
/// Ordered and duplicate-preserving: HTTP fields may repeat (set-cookie on responses, cookie on
/// h3 requests), so this is a list, not a map. The array is allocated lazily on first Add and
/// RETAINED by <see cref="Clear"/>, so a recycled request keeps its capacity. Not ArrayPool-backed
/// on purpose: response headers are app-built and never handed back, and rent-without-return
/// degrades the pool into a slow allocator (measured ~9% off the request rate).
/// </summary>
public sealed class KeyValueList
{
    private const int DefaultCapacity = 8;

    private KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>[] _items = [];
    private int _count;

    public int Count => _count;

    public KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> this[int index]
    {
        get
        {
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual((uint)index, (uint)_count);
            return _items[index];
        }
    }

    /// <summary>The populated entries, for allocation-free <c>foreach</c> over a span.</summary>
    public ReadOnlySpan<KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>> AsSpan()
        => _items.AsSpan(0, _count);

    /// <summary>Append a field line. Names must be lowercase ASCII (the h3 wire requirement).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Add(ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value)
    {
        if (_count == _items.Length)
        {
            Array.Resize(ref _items, _items.Length == 0 ? DefaultCapacity : _items.Length * 2);
        }
        _items[_count++] = new KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>(name, value);
    }

    /// <summary>Drop every entry, keeping the array for the next life.</summary>
    public void Clear()
    {
        _items.AsSpan(0, _count).Clear();   // release the memory references
        _count = 0;
    }
}
