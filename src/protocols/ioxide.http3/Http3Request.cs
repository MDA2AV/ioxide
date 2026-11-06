using System.Globalization;

namespace ioxide.http3;

/// <summary>
/// One HTTP/3 request - post-QPACK BYTES throughout, mirroring the ioxide.nghttp3 surface: route
/// by byte compare (<c>req.Path.Span.SequenceEqual("/x"u8)</c>) or decode at the edge. Every
/// memory slices a per-request buffer valid only until the handler returns, and a request whose
/// body arrived whole is itself reused for a later stream on the same connection after that.
/// </summary>
public sealed class Http3Request
{
    public long StreamId { get; internal set; }

    public ReadOnlyMemory<byte> Method { get; internal set; }
    public ReadOnlyMemory<byte> Path { get; internal set; }
    public ReadOnlyMemory<byte> Scheme { get; internal set; }
    public ReadOnlyMemory<byte> Authority { get; internal set; }

    /// <summary>Non-pseudo headers; names lowercase (h3 wire requirement), values raw octets.</summary>
    public List<(ReadOnlyMemory<byte> Name, ReadOnlyMemory<byte> Value)> Headers { get; } = [];

    /// <summary>Whole body, assembled before dispatch - empty when the handler takes a body reader.</summary>
    public ReadOnlyMemory<byte> Body { get; internal set; }

    // The body as it arrives, for a handler that takes a body reader - which is how it is handed one.
    internal Http3BodyReader? BodyReader { get; set; }

    // --- assembly (reactor thread; same arena/ranges design as the nghttp3 layer: only offsets
    //     are recorded while the arena can still grow, memories materialize at Freeze) ---

    internal byte[] Arena = [];
    internal int ArenaUsed;
    internal (int Off, int Len) MethodR = (0, -1), PathR = (0, -1), SchemeR = (0, -1), AuthorityR = (0, -1);
    internal readonly List<(int NOff, int NLen, int VOff, int VLen)> HeaderRanges = [];
    internal MemoryStream? BodyBuffer;

    // The DATA payload content-length still owes: -1 without one, -2 for an invalid or repeated one.
    internal long ContentLengthLeft = -1;

    // A pseudo-header out of place: the stream is refused once the section is decoded, never dispatched.
    internal bool Malformed;

    // The QPACK decoder lands every decoded field here; pseudo-headers route by byte compare.
    internal void AddField(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        if (name.Length > 0 && name[0] == (byte)':')
        {
            if      (name.SequenceEqual(":method"u8))    Pseudo(ref MethodR, value);
            else if (name.SequenceEqual(":path"u8))      Pseudo(ref PathR, value);
            else if (name.SequenceEqual(":scheme"u8))    Pseudo(ref SchemeR, value);
            else if (name.SequenceEqual(":authority"u8)) Pseudo(ref AuthorityR, value);
            else Malformed = true;
            return;
        }

        (int Off, int Len) nr = Append(name);
        (int Off, int Len) vr = Append(value);
        HeaderRanges.Add((nr.Off, nr.Len, vr.Off, vr.Len));

        if (name.SequenceEqual("content-length"u8))
        {
            // A repeated one is refused even when the values agree, as nghttp3 does.
            ContentLengthLeft = ContentLengthLeft == -1
                && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long length)
                    ? length
                    : -2;
        }
    }

    // RFC 9114 4.3: each at most once, and ahead of every regular field.
    private void Pseudo(ref (int Off, int Len) range, ReadOnlySpan<byte> value)
    {
        Malformed |= range.Len >= 0 || HeaderRanges.Count > 0;
        range = Append(value);
    }

    private (int Off, int Len) Append(ReadOnlySpan<byte> data)
    {
        if (Arena.Length - ArenaUsed < data.Length)
        {
            int size = Math.Max(1024, Arena.Length * 2);
            while (size - ArenaUsed < data.Length)
            {
                size *= 2;
            }
            Array.Resize(ref Arena, size);
        }

        data.CopyTo(Arena.AsSpan(ArenaUsed));
        (int Off, int Len) range = (ArenaUsed, data.Length);
        ArenaUsed += data.Length;
        return range;
    }

    internal void Freeze()
    {
        Method    = Slice(MethodR);
        Path      = Slice(PathR);
        Scheme    = Slice(SchemeR);
        Authority = Slice(AuthorityR);

        foreach ((int nOff, int nLen, int vOff, int vLen) in HeaderRanges)
        {
            Headers.Add((Arena.AsMemory(nOff, nLen), Arena.AsMemory(vOff, vLen)));
        }
        HeaderRanges.Clear();

        if (BodyBuffer is not null)
        {
            Body = BodyBuffer.GetBuffer().AsMemory(0, (int)BodyBuffer.Length);
            BodyBuffer = null;
        }
    }

    private ReadOnlyMemory<byte> Slice((int Off, int Len) r) => r.Len < 0 ? default : Arena.AsMemory(r.Off, r.Len);

    // Not above the inline-body limit, so a response body that waits for send capacity never points into a kept arena.
    internal const int MaxPooledArena = 4 * 1024;

    // Grew nothing a pooled request should keep: lists past this were a peer's thousands of header lines.
    internal bool IsSmall => Headers.Capacity <= 64 && HeaderRanges.Capacity <= 64;

    /// <summary>Fresh for the next stream, keeping the arena and both lists' capacity.</summary>
    internal void Reset()
    {
        StreamId = 0;
        Method = Path = Scheme = Authority = Body = default;
        Headers.Clear();
        BodyReader = null;

        if (Arena.Length > MaxPooledArena)
        {
            Arena = [];
        }
        ArenaUsed = 0;
        MethodR = PathR = SchemeR = AuthorityR = (0, -1);
        HeaderRanges.Clear();
        BodyBuffer = null;
        ContentLengthLeft = -1;
    }
}

/// <summary>
/// One HTTP/3 response: status, headers, in-memory body - bytes throughout. Everything is encoded
/// and handed to the QUIC engine synchronously at submit, so the memories can be pooled or static.
/// A response kept past its handler has to own them: a request's are reused for a later stream.
/// </summary>
public sealed class Http3Response
{
    public int Status { get; init; } = 200;
    public List<(ReadOnlyMemory<byte> Name, ReadOnlyMemory<byte> Value)> Headers { get; } = [];
    public ReadOnlyMemory<byte> Body { get; init; }

    // The encoded HEADERS frame for this response - QPACK field section, content-length and the
    // DATA frame header - kept because none of it can change once the response is built. A hot
    // handler reuses one response instance for every request, so encoding it per request is pure
    // repetition. Guarded by the shape it was built from, so a mutated response re-encodes.
    internal byte[]? EncodedHead;
    internal int EncodedHeadLen;
    internal int EncodedForStatus = -1;
    internal int EncodedForHeaderCount = -1;
    internal int EncodedForBodyLength = -1;

    internal bool HeadIsValid =>
        EncodedHead is not null && EncodedForStatus == Status
        && EncodedForHeaderCount == Headers.Count && EncodedForBodyLength == Body.Length;

    private static readonly byte[] ContentTypeName = "content-type"u8.ToArray();
    private static readonly byte[] TextPlainValue  = "text/plain; charset=utf-8"u8.ToArray();

    /// <summary>Convenience for text bodies: UTF-8 encodes and stamps content-type.</summary>
    public static Http3Response Text(string body, int status = 200)
    {
        var response = new Http3Response
        {
            Status = status,
            Body = System.Text.Encoding.UTF8.GetBytes(body),
        };

        response.Headers.Add((ContentTypeName, TextPlainValue));

        return response;
    }
}
