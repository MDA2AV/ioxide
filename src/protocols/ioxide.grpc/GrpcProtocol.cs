using System.Buffers.Text;
using System.Text;
using Grpc.Core;

namespace ioxide.grpc;

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
    private static readonly byte[] AllowName = "allow"u8.ToArray();
    private static readonly byte[] Post = "POST"u8.ToArray();

    private static readonly byte[][] StatusCodes = [.. Enumerable.Range(0, 17).Select(code => Encoding.ASCII.GetBytes(code.ToString()))];

    // Shared by every call that ends plain OK; only ever read, so every reactor can at once.
    private static readonly KeyValueList OkTrailers = NewOkTrailers();

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

        // Nanoseconds round up to a tick, so a short timeout never becomes none.
        timeout = value[^1] switch
        {
            (byte)'H' => TimeSpan.FromHours(amount),
            (byte)'M' => TimeSpan.FromMinutes(amount),
            (byte)'S' => TimeSpan.FromSeconds(amount),
            (byte)'m' => TimeSpan.FromMilliseconds(amount),
            (byte)'u' => TimeSpan.FromTicks(amount * TimeSpan.TicksPerMicrosecond),
            (byte)'n' => TimeSpan.FromTicks((amount + TimeSpan.NanosecondsPerTick - 1) / TimeSpan.NanosecondsPerTick),
            _ => TimeSpan.MinValue,
        };
        return timeout != TimeSpan.MinValue;
    }

    /// <summary>A call's response headers: content-type, grpc-accept-encoding when the request named an encoding, then <paramref name="metadata"/>.</summary>
    internal static void AddHeaders(KeyValueList fields, Metadata? metadata, bool acceptEncoding)
    {
        fields.Add(ContentTypeName, ContentTypeGrpc);
        if (acceptEncoding)
        {
            fields.Add(AcceptEncodingName, Identity);
        }
        if (metadata is not null)
        {
            AddMetadata(fields, metadata);
        }
    }

    /// <summary>The trailer section that ends a call: its status, then <paramref name="metadata"/>.</summary>
    internal static KeyValueList Trailers(Status status, Metadata? metadata)
    {
        if (status.StatusCode == StatusCode.OK && string.IsNullOrEmpty(status.Detail) && metadata is not { Count: > 0 })
        {
            return OkTrailers;
        }

        var fields = new KeyValueList();
        AddStatus(fields, status);
        if (metadata is not null)
        {
            AddMetadata(fields, metadata);
        }
        return fields;
    }

    private static KeyValueList NewOkTrailers()
    {
        var fields = new KeyValueList();
        AddStatus(fields, Status.DefaultSuccess);
        return fields;
    }

    /// <summary>
    /// The fields of a call that ends on its headers. A call's (200) are its headers and trailers in one,
    /// the trailers-only response; a refused request's are its gRPC status beside the HTTP one.
    /// </summary>
    internal static void AddHeadersOnly(KeyValueList fields, int httpStatus, Status status, Metadata? trailers, bool acceptEncoding)
    {
        if (httpStatus == 200)
        {
            AddHeaders(fields, metadata: null, acceptEncoding);
        }
        else if (httpStatus == 405)
        {
            fields.Add(AllowName, Post);   // RFC 9110 15.5.6
        }

        AddStatus(fields, status);
        if (trailers is not null)
        {
            AddMetadata(fields, trailers);
        }
    }

    private static void AddStatus(KeyValueList fields, Status status)
    {
        int code = (int)status.StatusCode;
        fields.Add(StatusName, code >= 0 && code < StatusCodes.Length ? StatusCodes[code] : Encoding.ASCII.GetBytes(code.ToString()));

        if (!string.IsNullOrEmpty(status.Detail))
        {
            fields.Add(MessageName, PercentEncode(status.Detail));
        }
    }

    // -bin values travel as unpadded base64. A text value outside space..~ is dropped: no peer could read it.
    private static void AddMetadata(KeyValueList fields, Metadata metadata)
    {
        foreach (Metadata.Entry entry in metadata)
        {
            if (!entry.IsBinary && entry.Value.AsSpan().ContainsAnyExceptInRange(' ', '~'))
            {
                Console.Error.WriteLine($"[ioxide.grpc] metadata '{entry.Key}' dropped: its value is not printable ASCII");
                continue;
            }

            byte[] value = entry.IsBinary ? ToBase64(entry.ValueBytes) : Encoding.ASCII.GetBytes(entry.Value);
            fields.Add(Encoding.ASCII.GetBytes(entry.Key), value);
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
                    // A peer may join several values with commas; each is decoded on its own.
                    ReadOnlySpan<byte> values = field.Value.Span;
                    foreach (Range value in values.Split((byte)','))
                    {
                        metadata.Add(key, FromBase64(values[value]));
                    }
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
