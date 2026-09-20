namespace ioxide.http2;

/// <summary>
/// The HPACK static table, RFC 7541 Appendix A. Sixty-one entries, indexed from 1, that both peers
/// know without exchanging anything - which is where most of HPACK's compression comes from on a
/// typical request: <c>:method GET</c> is one byte on the wire.
/// </summary>
internal static class HpackStatic
{
    /// <summary>Entries at their RFC index. Slot 0 is unused so indexing reads naturally.</summary>
    internal static readonly (byte[] Name, byte[] Value)[] Entries =
    [
        ([], []),
        (":authority"u8.ToArray(), []),
        (":method"u8.ToArray(), "GET"u8.ToArray()),
        (":method"u8.ToArray(), "POST"u8.ToArray()),
        (":path"u8.ToArray(), "/"u8.ToArray()),
        (":path"u8.ToArray(), "/index.html"u8.ToArray()),
        (":scheme"u8.ToArray(), "http"u8.ToArray()),
        (":scheme"u8.ToArray(), "https"u8.ToArray()),
        (":status"u8.ToArray(), "200"u8.ToArray()),
        (":status"u8.ToArray(), "204"u8.ToArray()),
        (":status"u8.ToArray(), "206"u8.ToArray()),
        (":status"u8.ToArray(), "304"u8.ToArray()),
        (":status"u8.ToArray(), "400"u8.ToArray()),
        (":status"u8.ToArray(), "404"u8.ToArray()),
        (":status"u8.ToArray(), "500"u8.ToArray()),
        ("accept-charset"u8.ToArray(), []),
        ("accept-encoding"u8.ToArray(), "gzip, deflate"u8.ToArray()),
        ("accept-language"u8.ToArray(), []),
        ("accept-ranges"u8.ToArray(), []),
        ("accept"u8.ToArray(), []),
        ("access-control-allow-origin"u8.ToArray(), []),
        ("age"u8.ToArray(), []),
        ("allow"u8.ToArray(), []),
        ("authorization"u8.ToArray(), []),
        ("cache-control"u8.ToArray(), []),
        ("content-disposition"u8.ToArray(), []),
        ("content-encoding"u8.ToArray(), []),
        ("content-language"u8.ToArray(), []),
        ("content-length"u8.ToArray(), []),
        ("content-location"u8.ToArray(), []),
        ("content-range"u8.ToArray(), []),
        ("content-type"u8.ToArray(), []),
        ("cookie"u8.ToArray(), []),
        ("date"u8.ToArray(), []),
        ("etag"u8.ToArray(), []),
        ("expect"u8.ToArray(), []),
        ("expires"u8.ToArray(), []),
        ("from"u8.ToArray(), []),
        ("host"u8.ToArray(), []),
        ("if-match"u8.ToArray(), []),
        ("if-modified-since"u8.ToArray(), []),
        ("if-none-match"u8.ToArray(), []),
        ("if-range"u8.ToArray(), []),
        ("if-unmodified-since"u8.ToArray(), []),
        ("last-modified"u8.ToArray(), []),
        ("link"u8.ToArray(), []),
        ("location"u8.ToArray(), []),
        ("max-forwards"u8.ToArray(), []),
        ("proxy-authenticate"u8.ToArray(), []),
        ("proxy-authorization"u8.ToArray(), []),
        ("range"u8.ToArray(), []),
        ("referer"u8.ToArray(), []),
        ("refresh"u8.ToArray(), []),
        ("retry-after"u8.ToArray(), []),
        ("server"u8.ToArray(), []),
        ("set-cookie"u8.ToArray(), []),
        ("strict-transport-security"u8.ToArray(), []),
        ("transfer-encoding"u8.ToArray(), []),
        ("user-agent"u8.ToArray(), []),
        ("vary"u8.ToArray(), []),
        ("via"u8.ToArray(), []),
        ("www-authenticate"u8.ToArray(), []),
    ];

    internal const int Count = 61;

    /// <summary>Static index for a fully matching name+value pair, or 0.</summary>
    internal static int FindExact(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        for (int i = 1; i <= Count; i++)
        {
            if (EqualsIgnoreCase(Entries[i].Name, name) && Entries[i].Value.AsSpan().SequenceEqual(value))
            {
                return i;
            }
        }
        return 0;
    }

    /// <summary>Static index for a matching NAME, or 0. Used to send a known name with a new value.</summary>
    internal static int FindName(ReadOnlySpan<byte> name)
    {
        for (int i = 1; i <= Count; i++)
        {
            if (EqualsIgnoreCase(Entries[i].Name, name))
            {
                return i;
            }
        }
        return 0;
    }

    // Table names are lowercase and a field name is case-insensitive, so a caller that kept the
    // canonical capitalisation - "Content-Type", "Vary" - still resolves to its index instead of
    // being written out as a literal.
    private static bool EqualsIgnoreCase(byte[] lowercase, ReadOnlySpan<byte> other)
    {
        if (lowercase.Length != other.Length)
        {
            return false;
        }

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
}
