using System.Buffers;

namespace ioxide.nghttp3;

/// <summary>
/// One HTTP/3 request, assembled from nghttp3's callbacks. The surface is post-QPACK BYTES
/// throughout - the library never decodes text; convert at the edge
/// (<c>Encoding.ASCII.GetString(request.Path.Span)</c>) or route by byte compare
/// (<c>request.Path.Span.SequenceEqual("/x"u8)</c>).
///
/// Every memory slices per-request storage that is guaranteed valid ONLY until the handler
/// returns: request objects, their arenas and body buffers are pooled per connection and recycled
/// the moment that contract ends - don't stash a memory past it.
/// </summary>
public sealed class Nghttp3Request
{
    public long StreamId { get; internal set; }

    /// <summary>":method" pseudo-header bytes, e.g. GET.</summary>
    public ReadOnlyMemory<byte> Method { get; internal set; }

    /// <summary>":path" pseudo-header bytes, e.g. /plaintext.</summary>
    public ReadOnlyMemory<byte> Path { get; internal set; }

    public ReadOnlyMemory<byte> Scheme { get; internal set; }
    public ReadOnlyMemory<byte> Authority { get; internal set; }

    /// <summary>Non-pseudo field lines; names arrive lowercase (h3 wire requirement), values are
    /// raw octets. Ordered and duplicate-preserving - use <c>GetAll</c> for repeatable fields.</summary>
    public KeyValueList Headers { get; } = new();

    /// <summary>Walk the request's cookies as (name, value) byte pairs - parsed on demand from
    /// the cookie field line(s), nothing stored.</summary>
    public CookieEnumerator Cookies => new(Headers);

    /// <summary>Value of one cookie by name, or false when it isn't present. Byte-level; the
    /// value slices the request's arena.</summary>
    public bool TryGetCookie(ReadOnlySpan<byte> name, out ReadOnlyMemory<byte> value)
    {
        foreach ((ReadOnlyMemory<byte> cookieName, ReadOnlyMemory<byte> cookieValue) in Cookies)
        {
            if (cookieName.Span.SequenceEqual(name))
            {
                value = cookieValue;
                return true;
            }
        }
        value = default;
        return false;
    }

    /// <summary>Whole body, assembled before dispatch (empty with <see cref="Nghttp3Options.StreamRequestBodies"/>).</summary>
    public ReadOnlyMemory<byte> Body { get; internal set; }

    /// <summary>
    /// The body as it arrives, set only with <see cref="Nghttp3Options.StreamRequestBodies"/>,
    /// where dispatch happens at end-of-headers and the body arrives while the handler runs.
    /// Without it the body is assembled into <see cref="Body"/> instead.
    /// </summary>
    public Nghttp3BodyReader? BodyReader { get; internal set; }

    // --- assembly state (reactor thread, inside ih3_read_stream) -------------------------------
    // Header bytes are copied into one growable arena as the callbacks fire (nghttp3 reclaims its
    // rcbufs when each callback returns). Only (offset, length) ranges are recorded during
    // assembly: growing the arena reallocates the array, which would strand any Memory handed out
    // earlier. Freeze() materializes the public memories once the arena is final, at dispatch.

    internal byte[] Arena = [];
    internal int ArenaUsed;
    internal (int Off, int Len) MethodR = (0, -1), PathR = (0, -1), SchemeR = (0, -1), AuthorityR = (0, -1);
    internal readonly List<(int NOff, int NLen, int VOff, int VLen)> HeaderRanges = [];

    // Body accumulation (buffered flavor): a pooled growable array, returned on recycle.
    internal byte[]? BodyArr;
    internal int BodyLen;

    internal bool HeadersDone;    // first field section decoded; later blocks are trailers (dropped)
    internal bool Complete;       // queued for dispatch
    internal bool Dispatched;     // handler invoked (streaming: request may outlive the dict entry)
    internal bool HandlerDone;    // streaming: the handler's ValueTask completed
    internal bool Detached;       // streaming: the stream closed while the handler was still running
    internal bool Pooled;         // recycled - guards double-release

    internal unsafe (int Off, int Len) Append(byte* source, int length)
    {
        if (Arena.Length - ArenaUsed < length)
        {
            int size = Math.Max(1024, Arena.Length * 2);
            while (size - ArenaUsed < length)
            {
                size *= 2;
            }
            Array.Resize(ref Arena, size);
        }

        new ReadOnlySpan<byte>(source, length).CopyTo(Arena.AsSpan(ArenaUsed));
        (int Off, int Len) range = (ArenaUsed, length);
        ArenaUsed += length;
        return range;
    }

    internal void AppendBody(ReadOnlySpan<byte> data)
    {
        if (BodyArr is null)
        {
            BodyArr = ArrayPool<byte>.Shared.Rent(Math.Max(4096, data.Length));
        }
        else if (BodyArr.Length - BodyLen < data.Length)
        {
            byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(BodyLen + data.Length, BodyArr.Length * 2));
            BodyArr.AsSpan(0, BodyLen).CopyTo(grown);
            ArrayPool<byte>.Shared.Return(BodyArr);
            BodyArr = grown;
        }

        data.CopyTo(BodyArr.AsSpan(BodyLen));
        BodyLen += data.Length;
    }

    internal void Freeze()
    {
        Method    = Slice(MethodR);
        Path      = Slice(PathR);
        Scheme    = Slice(SchemeR);
        Authority = Slice(AuthorityR);

        foreach ((int nameOffset, int nameLength, int valueOffset, int valueLength) in HeaderRanges)
        {
            Headers.Add(Arena.AsMemory(nameOffset, nameLength), Arena.AsMemory(valueOffset, valueLength));
        }
        HeaderRanges.Clear();

        if (BodyArr is not null)
        {
            Body = BodyArr.AsMemory(0, BodyLen);
        }
    }

    // Prepare a pooled instance for its next life. The arena array is kept (that's the point of
    // pooling) unless a pathological request grew it huge; the lists keep their capacity via Clear.
    internal void Reset(long streamId)
    {
        StreamId = streamId;
        Method = Path = Scheme = Authority = default;
        Headers.Clear();
        Body = default;
        BodyReader = null;

        if (Arena.Length > 16 * 1024)
        {
            Arena = [];
        }
        ArenaUsed = 0;
        MethodR = PathR = SchemeR = AuthorityR = (0, -1);
        HeaderRanges.Clear();

        if (BodyArr is not null)
        {
            ArrayPool<byte>.Shared.Return(BodyArr);
            BodyArr = null;
        }
        BodyLen = 0;

        HeadersDone = false;
        Complete = false;
        Dispatched = false;
        HandlerDone = false;
        Detached = false;
        Pooled = false;
    }

    private ReadOnlyMemory<byte> Slice((int Off, int Len) range) => range.Len < 0 ? default : Arena.AsMemory(range.Off, range.Len);
}
