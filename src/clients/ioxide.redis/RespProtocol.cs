using System.Buffers.Text;

namespace ioxide.redis;

/// <summary>RESP2 wire format: write a command as an array of bulk strings; parse one reply.</summary>
internal static class RespProtocol
{
    // Real replies nest a few arrays deep; the parser recurses per level, on the reactor's stack.
    private const int MaxDepth = 512;

    /// <summary>
    /// Bytes needed to encode a command as a RESP array of bulk strings, given a pre-framed name
    /// token (<c>$len\r\nNAME\r\n</c>, see <see cref="FrameName"/>) plus the argument list.
    /// </summary>
    public static int CommandSize(ReadOnlySpan<byte> nameToken, ReadOnlySpan<RedisArg> args)
    {
        int size = 1 + IntLen(args.Length + 1) + 2;       // *<n>\r\n
        size += nameToken.Length;                          // name is already framed
        foreach (RedisArg arg in args)
        {
            size += BulkSize(arg.Bytes.Length);
        }

        return size;
    }

    /// <summary>Write a command into <paramref name="dst"/> (sized by <see cref="CommandSize"/>).</summary>
    public static int WriteCommand(Span<byte> dst, ReadOnlySpan<byte> nameToken, ReadOnlySpan<RedisArg> args)
    {
        int p = 0;
        dst[p++] = (byte)'*';
        p += WriteInt(dst[p..], args.Length + 1);
        dst[p++] = (byte)'\r';
        dst[p++] = (byte)'\n';

        nameToken.CopyTo(dst[p..]);   // pre-framed $len\r\nNAME\r\n - one memcpy, no per-call framing
        p += nameToken.Length;

        foreach (RedisArg arg in args)
        {
            p += WriteBulk(dst[p..], arg.Bytes);
        }

        return p;
    }

    /// <summary>
    /// Frame a command name as a RESP bulk-string token (<c>$len\r\nNAME\r\n</c>). Computed once per
    /// command name and cached, so the hot path memcpy's the whole token instead of re-framing it.
    /// </summary>
    public static byte[] FrameName(ReadOnlySpan<byte> name)
    {
        byte[] token = new byte[BulkSize(name.Length)];
        WriteBulk(token, name);
        return token;
    }

    private static int WriteBulk(Span<byte> dst, ReadOnlySpan<byte> payload)
    {
        int p = 0;
        dst[p++] = (byte)'$';
        p += WriteInt(dst[p..], payload.Length);
        dst[p++] = (byte)'\r';
        dst[p++] = (byte)'\n';
        payload.CopyTo(dst[p..]);
        p += payload.Length;
        dst[p++] = (byte)'\r';
        dst[p++] = (byte)'\n';
        return p;
    }

    private static int BulkSize(int payloadLength) => 1 + IntLen(payloadLength) + 2 + payloadLength + 2;

    private static int WriteInt(Span<byte> dst, int value)
    {
        Utf8Formatter.TryFormat(value, dst, out int written);
        return written;
    }

    private static int IntLen(int value)
    {
        int len = value < 0 ? 1 : 0;
        do
        {
            len++;
            value /= 10;
        } while (value != 0);
        return len;
    }

    /// <summary>
    /// Parse one complete reply (recursively, for arrays) from <paramref name="buffer"/>. False if
    /// the reply isn't fully buffered yet; on true, <paramref name="consumed"/> is its byte length.
    /// On false, <paramref name="needed"/> is the buffer length required before a re-parse can make
    /// progress (0 = unknown), so the caller can avoid re-scanning until enough bytes arrive.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RespValue value, out int consumed, out int needed)
    {
        int pos = 0;
        needed = 0;
        if (TryParseAt(buffer, ref pos, out value, ref needed, depth: 0))
        {
            consumed = pos;
            return true;
        }
        consumed = 0;
        return false;
    }

    private static bool TryParseAt(ReadOnlySpan<byte> buffer, ref int pos, out RespValue value, ref int needed, int depth)
    {
        value = default;
        if (pos >= buffer.Length)
        {
            return false;
        }

        byte type = buffer[pos];
        int lineEnd = buffer[(pos + 1)..].IndexOf("\r\n"u8);
        if (lineEnd < 0)
        {
            return false;
        }
        ReadOnlySpan<byte> line = buffer.Slice(pos + 1, lineEnd);
        int afterLine = pos + 1 + lineEnd + 2;

        switch (type)
        {
            case (byte)'+':
                value = RespValue.Simple(line.ToArray());
                pos = afterLine;
                return true;

            case (byte)'-':
                value = RespValue.Err(line.ToArray());
                pos = afterLine;
                return true;

            case (byte)':':
                value = RespValue.Int(ParseLong(line));
                pos = afterLine;
                return true;

            case (byte)'$':
            {
                long len = ParseLong(line);
                if (len == -1)
                {
                    value = RespValue.Null;
                    pos = afterLine;
                    return true;
                }

                if (len < -1)
                {
                    throw new RedisException($"invalid bulk length {len}");
                }

                if (afterLine + len + 2 > buffer.Length)
                {
                    // Body not fully buffered: report how many bytes are needed so the reader can
                    // skip re-parsing until they arrive, instead of re-scanning on every recv.
                    needed = afterLine + (int)len + 2;
                    return false;
                }
                value = RespValue.Bulk(buffer.Slice(afterLine, (int)len).ToArray());
                pos = afterLine + (int)len + 2;
                return true;
            }

            case (byte)'*':
            {
                long count = ParseLong(line);
                if (count == -1)
                {
                    value = RespValue.Null;
                    pos = afterLine;
                    return true;
                }

                if (count < -1 || count > int.MaxValue)
                {
                    throw new RedisException($"invalid array length {count}");
                }

                if (depth >= MaxDepth)
                {
                    throw new RedisException($"RESP reply nested more than {MaxDepth} arrays deep");
                }

                var items = new RespValue[count];
                int p = afterLine;
                for (int i = 0; i < count; i++)
                {
                    if (!TryParseAt(buffer, ref p, out RespValue item, ref needed, depth + 1))
                    {
                        return false;
                    }
                    items[i] = item;
                }
                value = RespValue.Arr(items);
                pos = p;
                return true;
            }

            case (byte)'_':   // RESP3 null; tolerated even though we negotiate RESP2
                value = RespValue.Null;
                pos = afterLine;
                return true;

            default:
                throw new RedisException($"unexpected RESP type byte 0x{type:x2} (RESP2 expected)");
        }
    }

    // Strict: RESP integers and bulk/array lengths are an optional '-' then ASCII digits. Anything
    // else is a malformed reply - throw so the reader breaks the connection cleanly instead of
    // computing a garbage length and wedging (or slicing out of range).
    private static long ParseLong(ReadOnlySpan<byte> s)
    {
        bool neg = s.Length > 0 && s[0] == (byte)'-';
        if (neg) s = s[1..];
        if (s.IsEmpty)
        {
            throw new RedisException("malformed RESP integer");
        }

        long n = 0;
        foreach (byte c in s)
        {
            if (c < (byte)'0' || c > (byte)'9')
            {
                throw new RedisException($"malformed RESP integer (byte 0x{c:x2})");
            }
            n = checked(n * 10 + (c - '0'));
        }

        return neg ? -n : n;
    }
}
