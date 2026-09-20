namespace ioxide.http2;

/// <summary>
/// The encoding half of HPACK. Deliberately simple: it uses the static table where a name or a
/// name+value pair matches exactly, and sends everything else as a literal WITHOUT indexing.
///
/// Never adding to the dynamic table means the encoder holds no per-connection compression state,
/// so it cannot desynchronise from the peer's decoder - the failure mode that makes HPACK bugs so
/// unpleasant. It costs bytes on repeated custom headers, which a server sends far fewer of than a
/// client; the pseudo-headers and common response fields that dominate a small response are all
/// static-table hits either way.
///
/// Literals are sent unencoded rather than Huffman-coded. Huffman saves roughly 20% on header
/// octets and costs CPU per response; for a server whose headers are mostly static-table indices
/// already, that trade is not obviously worth it.
/// </summary>
internal static class HpackEncoder
{
    /// <summary>Append one field. Returns the number of bytes written.</summary>
    internal static int Encode(Span<byte> destination, ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        int exact = HpackStatic.FindExact(name, value);
        if (exact != 0)
        {
            // 1xxxxxxx - the whole field in one index. ":status 200" lands here.
            return WriteInteger(destination, (uint)exact, 7, 0x80);
        }

        int nameOnly = HpackStatic.FindName(name);
        int written;

        if (nameOnly != 0)
        {
            // 0000xxxx with a non-zero index: known name, new value, do not index.
            written = WriteInteger(destination, (uint)nameOnly, 4, 0x00);
        }
        else
        {
            // 0000 0000: new name follows as a literal.
            destination[0] = 0x00;
            written = 1;
            written += WriteLiteralName(destination[written..], name);
        }

        written += WriteLiteral(destination[written..], value);
        return written;
    }

    /// <summary>Upper bound for one field, so callers can size a buffer without measuring.</summary>
    internal static int MaxEncodedLength(int nameLength, int valueLength)
        => 1 + 5 + nameLength + 5 + valueLength;

    // RFC 7541 section 5.1, mirrored from the decoder: the low prefixBits carry the value, or all
    // ones then a 7-bit-group varint.
    private static int WriteInteger(Span<byte> destination, uint value, int prefixBits, byte flags)
    {
        int mask = (1 << prefixBits) - 1;

        if (value < mask)
        {
            destination[0] = (byte)(flags | value);
            return 1;
        }

        destination[0] = (byte)(flags | mask);
        int written = 1;
        value -= (uint)mask;

        while (value >= 0x80)
        {
            destination[written++] = (byte)((value & 0x7F) | 0x80);
            value >>= 7;
        }
        destination[written++] = (byte)value;
        return written;
    }

    private static int WriteLiteral(Span<byte> destination, ReadOnlySpan<byte> value)
    {
        // Top bit clear: not Huffman coded.
        int written = WriteInteger(destination, (uint)value.Length, 7, 0x00);
        value.CopyTo(destination[written..]);
        return written + value.Length;
    }

    /// <summary>
    /// A literal field NAME, lowercased on the way out.
    ///
    /// RFC 9113 8.2.1 makes an uppercase letter in a field name malformed, and a peer is entitled
    /// to treat the whole message as a stream error - which is what a strict client does, leaving
    /// a response that looks like a clean 200 carrying no body at all. Callers hold headers in
    /// whatever case their own API uses ("Vary", "Content-Type"), and HTTP field names are
    /// case-insensitive everywhere else, so the conversion belongs here rather than in every
    /// caller.
    /// </summary>
    private static int WriteLiteralName(Span<byte> destination, ReadOnlySpan<byte> name)
    {
        int written = WriteInteger(destination, (uint)name.Length, 7, 0x00);

        for (int i = 0; i < name.Length; i++)
        {
            byte c = name[i];
            destination[written + i] = c is >= (byte)'A' and <= (byte)'Z' ? (byte)(c | 0x20) : c;
        }

        return written + name.Length;
    }
}
