using System.Globalization;

namespace ioxide.http3;

/// <summary>
/// One HTTP/3 request - post-QPACK BYTES throughout, mirroring the ioxide.nghttp3 surface: route
/// by byte compare (<c>req.Path.Span.SequenceEqual("/x"u8)</c>) or decode at the edge. Every
/// memory slices a per-request buffer valid only until the handler returns.
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

    // The QPACK decoder lands every decoded field here; pseudo-headers route by byte compare.
    internal void AddField(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        if (name.Length > 0 && name[0] == (byte)':')
        {
            (int Off, int Len) r = Append(value);
            if      (name.SequenceEqual(":method"u8))    MethodR = r;
            else if (name.SequenceEqual(":path"u8))      PathR = r;
            else if (name.SequenceEqual(":scheme"u8))    SchemeR = r;
            else if (name.SequenceEqual(":authority"u8)) AuthorityR = r;
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
}

/// <summary>
/// One HTTP/3 response: status, headers, in-memory body - bytes throughout. Everything is encoded
/// and handed to the QUIC engine synchronously at submit, so the memories can be pooled or static.
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
