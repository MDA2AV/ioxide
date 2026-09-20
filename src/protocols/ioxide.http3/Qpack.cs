using System.Buffers;

namespace ioxide.http3;

/// <summary>
/// QPACK (RFC 9204) without the dynamic table: our SETTINGS advertise capacity 0, so a conforming
/// peer may only send static-table references and literals - which reduces the decoder to the
/// static table, prefixed integers, and Huffman. The encoder mirrors that: indexed :status where
/// the table has the code, literal name references otherwise, literal names for everything else,
/// no Huffman on output (legal, and keeps the writer trivial).
/// </summary>
internal static class Qpack
{
    // --- prefixed integers (RFC 7541 §5.1, reused by QPACK) ------------------------------------

    public static bool TryReadInt(ReadOnlySpan<byte> input, int prefixBits, out long value, out int consumed)
    {
        value = 0;
        consumed = 0;
        if (input.IsEmpty)
        {
            return false;
        }

        int max = (1 << prefixBits) - 1;
        long v = input[0] & max;
        consumed = 1;
        if (v < max)
        {
            value = v;
            return true;
        }

        int shift = 0;
        while (true)
        {
            if (consumed >= input.Length)
            {
                consumed = 0;
                return false;
            }
            byte b = input[consumed++];
            v += (long)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0)
            {
                value = v;
                return true;
            }
            if (shift > 56)
            {
                consumed = 0;
                return false;   // absurd - treat as malformed
            }
        }
    }

    public static int WriteInt(Span<byte> output, byte firstByteBits, int prefixBits, long value)
    {
        int max = (1 << prefixBits) - 1;
        if (value < max)
        {
            output[0] = (byte)(firstByteBits | value);
            return 1;
        }
        output[0] = (byte)(firstByteBits | max);
        value -= max;
        int w = 1;
        while (value >= 0x80)
        {
            output[w++] = (byte)(0x80 | (value & 0x7F));
            value >>= 7;
        }
        output[w++] = (byte)value;
        return w;
    }

    // --- field-section decoding ----------------------------------------------------------------

    /// <summary>
    /// Decode a whole encoded field section into <paramref name="request"/> (pseudo-headers routed
    /// to the dedicated fields, the rest appended). Returns false on malformed input or any
    /// dynamic-table reference (illegal against our capacity-0 advertisement).
    /// </summary>
    public static bool TryDecodeFieldSection(ReadOnlySpan<byte> input, Http3Request request)
    {
        // Prefix: Required Insert Count (8-bit prefix) + sign/Delta Base (7-bit prefix). With no
        // dynamic table a conforming encoder sends RIC = 0; anything else references state we
        // don't have.
        if (!TryReadInt(input, 8, out long ric, out int c1) || ric != 0)
        {
            return false;
        }
        input = input[c1..];
        if (!TryReadInt(input, 7, out _, out int c2))
        {
            return false;
        }
        input = input[c2..];

        while (!input.IsEmpty)
        {
            byte first = input[0];

            if ((first & 0x80) != 0)
            {
                // Indexed Field Line: 1 T index(6+). T=1 static.
                if ((first & 0x40) == 0)
                {
                    return false;   // dynamic reference
                }
                if (!TryReadInt(input, 6, out long idx, out int consumed) || idx >= QpackStatic.Table.Length)
                {
                    return false;
                }
                input = input[consumed..];
                (byte[] name, byte[] value) = QpackStatic.Table[idx];
                request.AddField(name, value);
                continue;
            }

            if ((first & 0x40) != 0)
            {
                // Literal With Name Reference: 01 N T index(4+), then value string.
                if ((first & 0x10) == 0)
                {
                    return false;   // dynamic name reference
                }
                if (!TryReadInt(input, 4, out long idx, out int consumed) || idx >= QpackStatic.Table.Length)
                {
                    return false;
                }
                input = input[consumed..];
                if (!TryDecodeString(ref input, 7, out byte[] value, out int valueLen))
                {
                    return false;
                }
                request.AddField(QpackStatic.Table[idx].Name, value.AsSpan(0, valueLen));
                ArrayPool<byte>.Shared.Return(value);
                continue;
            }

            if ((first & 0x20) != 0)
            {
                // Literal With Literal Name: 001 N H namelen(3+), name, then value string.
                if (!TryDecodeString(ref input, 3, out byte[] name, out int nameLen))
                {
                    return false;
                }
                if (!TryDecodeString(ref input, 7, out byte[] value, out int valueLen))
                {
                    ArrayPool<byte>.Shared.Return(name);
                    return false;
                }
                request.AddField(name.AsSpan(0, nameLen), value.AsSpan(0, valueLen));
                ArrayPool<byte>.Shared.Return(name);
                ArrayPool<byte>.Shared.Return(value);
                continue;
            }

            return false;   // post-base forms (0001/0000) - dynamic table only
        }

        return true;
    }

    // A QPACK string: H bit ahead of an N-bit-prefix length, then bytes (Huffman-coded when H).
    // Output is a pooled buffer + length; the caller returns it.
    private static bool TryDecodeString(ref ReadOnlySpan<byte> input, int prefixBits, out byte[] buffer, out int length)
    {
        buffer = [];
        length = 0;
        if (input.IsEmpty)
        {
            return false;
        }

        bool huffman = (input[0] & (1 << prefixBits)) != 0;
        if (!TryReadInt(input, prefixBits, out long len, out int consumed) || len > 256 * 1024)
        {
            return false;
        }
        input = input[consumed..];
        if (input.Length < len)
        {
            return false;
        }

        ReadOnlySpan<byte> raw = input[..(int)len];
        input = input[(int)len..];

        if (!huffman)
        {
            buffer = ArrayPool<byte>.Shared.Rent((int)len);
            raw.CopyTo(buffer);
            length = (int)len;
            return true;
        }

        buffer = ArrayPool<byte>.Shared.Rent(Huffman.MaxDecodedLength((int)len));
        length = Huffman.Decode(raw, buffer);
        if (length < 0)
        {
            ArrayPool<byte>.Shared.Return(buffer);
            buffer = [];
            return false;
        }
        return true;
    }

    // --- field-section encoding (responses) ----------------------------------------------------

    private static readonly (int Status, byte Index)[] IndexedStatuses =
    [
        (103, 24), (200, 25), (304, 26), (404, 27), (503, 28),
        (100, 63), (204, 64), (206, 65), (302, 66), (400, 67), (403, 68), (421, 69), (425, 70), (500, 71),
    ];

    /// <summary>
    /// The static table indexed for encoding: distinct names, each with the entries sharing it.
    /// </summary>
    /// <remarks>
    /// Grouped rather than flat so a lookup rejects most candidates on length alone. Built once from
    /// the 99 fixed entries.
    /// </remarks>
    private static readonly (byte[] Name, int NameIndex, (byte[] Value, int Index)[] Values)[][] StaticByLength = BuildStaticNames();

    /// <summary>Longest field name in the static table, so a longer name skips the lookup entirely.</summary>
    private static readonly int LongestStaticName = StaticByLength.Length - 1;

    private static (byte[] Name, int NameIndex, (byte[] Value, int Index)[] Values)[][] BuildStaticNames()
    {
        var byName = new List<(byte[] Name, int NameIndex, List<(byte[] Value, int Index)> Values)>();

        for (int i = 0; i < QpackStatic.Table.Length; i++)
        {
            (byte[] name, byte[] value) = QpackStatic.Table[i];

            int at = -1;
            for (int j = 0; j < byName.Count; j++)
            {
                if (byName[j].Name.AsSpan().SequenceEqual(name))
                {
                    at = j;
                    break;
                }
            }

            if (at < 0)
            {
                byName.Add((name, i, [(value, i)]));
            }
            else
            {
                byName[at].Values.Add((value, i));
            }
        }

        // Bucketed by name length. A per-header linear scan of every distinct name is far too
        // expensive at this request rate - it cost about 6% of throughput - and length alone
        // narrows 50-odd candidates down to one or two.
        int longest = 0;

        foreach ((byte[] name, int _, List<(byte[] Value, int Index)> _) in byName)
        {
            longest = Math.Max(longest, name.Length);
        }

        var buckets = new List<(byte[], int, (byte[], int)[])>[longest + 1];

        foreach ((byte[] name, int nameIndex, List<(byte[] Value, int Index)> values) in byName)
        {
            buckets[name.Length] ??= [];
            buckets[name.Length].Add((name, nameIndex, values.ToArray()));
        }

        var result = new (byte[], int, (byte[], int)[])[longest + 1][];

        for (int i = 0; i <= longest; i++)
        {
            result[i] = buckets[i]?.ToArray() ?? [];
        }

        return result;
    }

    /// <summary>
    /// Finds a header in the static table: an exact name and value match, or failing that a name.
    /// </summary>
    /// <remarks>
    /// Names match case-insensitively, so a caller holding HTTP's conventional capitalisation still
    /// resolves - and then never writes the name at all. Values match exactly, because a field value
    /// is case-sensitive.
    /// </remarks>
    private static bool TryFindStatic(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, out int exact, out int nameIndex)
    {
        exact = -1;
        nameIndex = -1;

        if (name.Length > LongestStaticName)
        {
            return false;
        }

        foreach ((byte[] candidate, int candidateIndex, (byte[] Value, int Index)[] values) in StaticByLength[name.Length])
        {
            if (!EqualsIgnoreCase(candidate, name))
            {
                continue;
            }

            nameIndex = candidateIndex;

            foreach ((byte[] entryValue, int entryIndex) in values)
            {
                if (entryValue.AsSpan().SequenceEqual(value))
                {
                    exact = entryIndex;
                    break;
                }
            }

            return true;
        }

        return false;
    }

    private static bool EqualsIgnoreCase(ReadOnlySpan<byte> lowercase, ReadOnlySpan<byte> other)
    {
        for (int i = 0; i < lowercase.Length; i++)
        {
            byte c = other[i];

            if (c is >= (byte)'A' and <= (byte)'Z')
            {
                c |= 0x20;
            }

            if (c != lowercase[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Writes one header, preferring the static table over spelling the name out.
    /// </summary>
    /// <remarks>
    /// Three tiers, cheapest first: name and value both in the table cost a single byte; a known
    /// name costs an index plus the literal value; anything else falls back to the full literal.
    /// Unlike the dynamic table this needs nothing from the peer, so it applies to every client.
    /// </remarks>
    private static int WriteHeader(Span<byte> buf, ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        if (TryFindStatic(name, value, out int exact, out int nameIndex))
        {
            if (exact >= 0)
            {
                // Indexed Field Line: 1 T=1 index(6+).
                return WriteInt(buf, 0xC0, 6, exact);
            }

            // Literal With Name Reference: 01 N=0 T=1 nameindex(4+), then H=0 value(7+).
            int written = WriteInt(buf, 0x50, 4, nameIndex);
            written += WriteInt(buf[written..], 0x00, 7, value.Length);
            value.CopyTo(buf[written..]);

            return written + value.Length;
        }

        // Literal With Literal Name: 001 N=0 H=0 namelen(3+), lowercased name, H=0 value(7+).
        int w = WriteInt(buf, 0x20, 3, name.Length);

        foreach (byte b in name)
        {
            buf[w++] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b | 0x20) : b;
        }

        w += WriteInt(buf[w..], 0x00, 7, value.Length);
        value.CopyTo(buf[w..]);

        return w + value.Length;
    }

    public static byte[] EncodeResponseFields(Http3Response response, out int written)
    {
        int cap = 2 + 8;
        foreach ((ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) in response.Headers)
        {
            cap += 8 + name.Length + 8 + value.Length;
        }

        byte[] buf = ArrayPool<byte>.Shared.Rent(cap);
        int w = 0;

        // Prefix: RIC 0, Delta Base 0 - the no-dynamic-table constant.
        buf[w++] = 0x00;
        buf[w++] = 0x00;

        // :status - indexed when the static table has it, literal with name ref (idx 24) otherwise.
        byte statusIdx = 0;
        foreach ((int status, byte idx) in IndexedStatuses)
        {
            if (status == response.Status)
            {
                statusIdx = idx;
                break;
            }
        }
        if (statusIdx != 0)
        {
            w += WriteInt(buf.AsSpan(w), 0xC0, 6, statusIdx);        // 1 T=1 index
        }
        else
        {
            w += WriteInt(buf.AsSpan(w), 0x50, 4, 24);               // 01 N=0 T=1 nameidx
            Span<byte> digits = stackalloc byte[3];
            System.Buffers.Text.Utf8Formatter.TryFormat(response.Status, digits, out int dlen);
            w += WriteInt(buf.AsSpan(w), 0x00, 7, dlen);             // H=0 value
            digits[..dlen].CopyTo(buf.AsSpan(w));
            w += dlen;
        }

        foreach ((ReadOnlyMemory<byte> nameM, ReadOnlyMemory<byte> valueM) in response.Headers)
        {
            w += WriteHeader(buf.AsSpan(w), nameM.Span, valueM.Span);
        }

        written = w;
        return buf;
    }
}
