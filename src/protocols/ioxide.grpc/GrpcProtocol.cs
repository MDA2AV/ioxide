using System.Buffers.Text;
using System.Text;
using Grpc.Core;

namespace ioxide.grpc;

/// <summary>Adds one field line to whichever stack's field list a call is building.</summary>
internal interface IFieldSink
{
    void Add(ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value);
}

/// <summary>
/// The gRPC-over-HTTP/2 wire (PROTOCOL-HTTP2.md): the fields a call reads and writes, and how status,
/// metadata and timeouts are spelled in them.
/// </summary>
internal static class GrpcProtocol
{
    internal const int PrefixLength = 5;   // compressed flag + 4-byte big-endian length

    internal static readonly byte[] ContentTypeName = "content-type"u8.ToArray();
    internal static readonly byte[] ContentTypeGrpc = "application/grpc"u8.ToArray();
    internal static readonly byte[] StatusName = "grpc-status"u8.ToArray();
    internal static readonly byte[] MessageName = "grpc-message"u8.ToArray();
    internal static readonly byte[] AcceptEncodingName = "grpc-accept-encoding"u8.ToArray();
    internal static readonly byte[] Identity = "identity"u8.ToArray();

    private static readonly byte[][] StatusCodes = [.. Enumerable.Range(0, 17).Select(code => Encoding.ASCII.GetBytes(code.ToString()))];

    /// <summary>application/grpc, or one of its +format or ;parameter forms - never application/grpc-web.</summary>
    internal static bool IsGrpcContentType(ReadOnlySpan<byte> value)
        => value.StartsWith(ContentTypeGrpc)
           && (value.Length == ContentTypeGrpc.Length || value[ContentTypeGrpc.Length] is (byte)'+' or (byte)';');

    /// <summary>
    /// grpc-timeout: at most 8 digits and a unit, H M S m u n. False for anything else, which leaves the
    /// call without a deadline rather than failing it.
    /// </summary>
    internal static bool TryParseTimeout(ReadOnlySpan<byte> value, out TimeSpan timeout)
    {
        timeout = default;
        if (value.Length is < 2 or > 9)
        {
            return false;
        }

        long amount = 0;
        foreach (byte digit in value[..^1])
        {
            if (digit is < (byte)'0' or > (byte)'9')
            {
                return false;
            }
            amount = (amount * 10) + (digit - '0');
        }

        // Nanoseconds and microseconds round up to a tick, so a short timeout never becomes none.
        timeout = value[^1] switch
        {
            (byte)'H' => TimeSpan.FromHours(amount),
            (byte)'M' => TimeSpan.FromMinutes(amount),
            (byte)'S' => TimeSpan.FromSeconds(amount),
            (byte)'m' => TimeSpan.FromMilliseconds(amount),
            (byte)'u' => TimeSpan.FromTicks((amount + 9) / 10),
            (byte)'n' => TimeSpan.FromTicks((amount + 99) / 100),
            _ => TimeSpan.MinValue,
        };
        return timeout != TimeSpan.MinValue;
    }

    /// <summary>grpc-status, and grpc-message when there is a detail.</summary>
    internal static void AppendStatus<TSink>(ref TSink sink, Status status) where TSink : struct, IFieldSink
    {
        int code = (int)status.StatusCode;
        sink.Add(StatusName, code is >= 0 and < 17 ? StatusCodes[code] : Encoding.ASCII.GetBytes(code.ToString()));

        if (!string.IsNullOrEmpty(status.Detail))
        {
            sink.Add(MessageName, PercentEncode(status.Detail));
        }
    }

    /// <summary>Custom metadata as field lines; -bin values travel as unpadded base64.</summary>
    internal static void AppendMetadata<TSink>(ref TSink sink, Metadata metadata) where TSink : struct, IFieldSink
    {
        foreach (Metadata.Entry entry in metadata)
        {
            byte[] value = entry.IsBinary ? ToBase64(entry.ValueBytes) : Encoding.ASCII.GetBytes(entry.Value);
            sink.Add(Encoding.ASCII.GetBytes(entry.Key), value);
        }
    }

    /// <summary>
    /// The request's custom metadata: every field but the pseudo-headers and the ones this layer
    /// consumes itself. A name Metadata cannot hold is skipped rather than failing the call.
    /// </summary>
    internal static Metadata ReadMetadata(ReadOnlySpan<KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>> fields)
    {
        var metadata = new Metadata();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in fields)
        {
            ReadOnlySpan<byte> name = field.Key.Span;
            if (name.IsEmpty || name[0] == (byte)':' || IsConsumed(name))
            {
                continue;
            }

            try
            {
                string key = Encoding.ASCII.GetString(name);
                if (name.EndsWith("-bin"u8))
                {
                    metadata.Add(key, FromBase64(field.Value.Span));
                }
                else
                {
                    metadata.Add(key, Encoding.ASCII.GetString(field.Value.Span));
                }
            }
            catch (FormatException)
            {
            }
            catch (ArgumentException)
            {
            }
        }
        return metadata;
    }

    private static bool IsConsumed(ReadOnlySpan<byte> name)
        => name.SequenceEqual(ContentTypeName) || name.SequenceEqual("te"u8)
           || name.SequenceEqual("grpc-timeout"u8) || name.SequenceEqual("grpc-encoding"u8)
           || name.SequenceEqual(AcceptEncodingName);

    // PROTOCOL-HTTP2.md: the UTF-8 bytes, with everything outside space..~ and '%' itself as %XX.
    internal static byte[] PercentEncode(string detail)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(detail);

        int length = utf8.Length;
        foreach (byte b in utf8)
        {
            if (NeedsEscape(b))
            {
                length += 2;
            }
        }
        if (length == utf8.Length)
        {
            return utf8;
        }

        var encoded = new byte[length];
        int at = 0;
        foreach (byte b in utf8)
        {
            if (NeedsEscape(b))
            {
                encoded[at++] = (byte)'%';
                encoded[at++] = (byte)"0123456789ABCDEF"[b >> 4];
                encoded[at++] = (byte)"0123456789ABCDEF"[b & 0xF];
            }
            else
            {
                encoded[at++] = b;
            }
        }
        return encoded;

        static bool NeedsEscape(byte b) => b is < 0x20 or > 0x7E or (byte)'%';
    }

    private static byte[] ToBase64(byte[] value)
    {
        byte[] encoded = new byte[Base64.GetMaxEncodedToUtf8Length(value.Length)];
        Base64.EncodeToUtf8(value, encoded, out _, out int written);
        while (written > 0 && encoded[written - 1] == (byte)'=')
        {
            written--;   // senders SHOULD omit the padding
        }
        return encoded.AsSpan(0, written).ToArray();
    }

    // Receivers MUST take it padded or not.
    private static byte[] FromBase64(ReadOnlySpan<byte> value)
    {
        int padding = (4 - (value.Length % 4)) % 4;
        byte[] padded = new byte[value.Length + padding];
        value.CopyTo(padded);
        padded.AsSpan(value.Length).Fill((byte)'=');

        byte[] decoded = new byte[Base64.GetMaxDecodedFromUtf8Length(padded.Length)];
        if (Base64.DecodeFromUtf8(padded, decoded, out _, out int written) != System.Buffers.OperationStatus.Done)
        {
            throw new FormatException("A -bin metadata value is not base64.");
        }
        return decoded.AsSpan(0, written).ToArray();
    }
}
