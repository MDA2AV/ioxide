using System.Buffers;
using System.IO.Pipelines;

namespace ioxide.nghttp2;

/// <summary>
/// Response submission and the egress drain. nghttp2 produces bytes only when asked, so every pass
/// ends here: whatever the session has queued - SETTINGS, HEADERS, DATA, WINDOW_UPDATE, GOAWAY -
/// is pulled out and staged into the connection's write slab as ONE flush.
/// </summary>
public sealed partial class Nghttp2Connection
{
    private static readonly byte[] StatusName = ":status"u8.ToArray();

    private unsafe void SubmitResponse(int streamId, Nghttp2Response response)
    {
        byte[] headers = PackHeaders(response, out int headersLength);
        try
        {
            int result;
            fixed (byte* headerBytes = headers)
            fixed (byte* bodyBytes = response.Body.Span)
            {
                result = Nghttp2.ih2_submit_response(_handle, streamId,
                    headerBytes, (nuint)headersLength,
                    bodyBytes, (nuint)response.Body.Length);
            }

            if (result != 0)
            {
                _failed = true;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(headers);
        }
    }

    // [u16 namelen][name][u16 valuelen][value]... with :status first, which is the order HTTP/2
    // requires and the same packing the request side and the nghttp3 shim use.
    private static byte[] PackHeaders(Nghttp2Response response, out int written)
        => PackFields(response.Status, response.Headers, out written);

    // A null status packs a trailer section, which carries none.
    private static byte[] PackFields(int? status, KeyValueList fields, out int written)
    {
        int capacity = 16 + StatusName.Length + 8;
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in fields.AsSpan())
        {
            capacity += 4 + field.Key.Length + field.Value.Length;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(capacity);
        int cursor = 0;

        if (status is int code)
        {
            Span<byte> digits = stackalloc byte[3];
            int statusLength = WriteStatus(code, digits);
            Write(buffer, ref cursor, StatusName, digits[..statusLength]);
        }

        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in fields.AsSpan())
        {
            Write(buffer, ref cursor, field.Key.Span, field.Value.Span);
        }

        written = cursor;
        return buffer;
    }

    private static void Write(byte[] buffer, ref int cursor, ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        BitConverter.TryWriteBytes(buffer.AsSpan(cursor), (ushort)name.Length);
        cursor += 2;
        name.CopyTo(buffer.AsSpan(cursor));
        cursor += name.Length;

        BitConverter.TryWriteBytes(buffer.AsSpan(cursor), (ushort)value.Length);
        cursor += 2;
        value.CopyTo(buffer.AsSpan(cursor));
        cursor += value.Length;
    }

    // Always three ASCII digits - HTTP/2 has no reason phrase, and every valid status is 100..599.
    private static int WriteStatus(int status, Span<byte> destination)
    {
        int clamped = status is >= 100 and <= 599 ? status : 500;
        destination[0] = (byte)('0' + (clamped / 100));
        destination[1] = (byte)('0' + ((clamped / 10) % 10));
        destination[2] = (byte)('0' + (clamped % 10));
        return 3;
    }

    /// <summary>
    /// Pull everything nghttp2 has queued into the write slab and flush once. Looping until the
    /// session reports nothing left is what keeps a batch of responses to a single send.
    /// </summary>
    // One drain at a time. Both the read loop and a handler that finished late can start one, and a
    // drain awaits a real flush - so without this they interleave writes out of the single _egress
    // buffer, and a PipeWriter refuses a Write while a flush is outstanding anyway.
    private bool _draining;
    private bool _drainAgain;

    private async ValueTask FlushEgressAsync()
    {
        if (_handle == 0)
        {
            return;
        }

        if (_draining)
        {
            // A drain owns the pipe. Whatever was just submitted is sitting in nghttp2's own
            // queue rather than in ours, so the loop below will pull it before it returns - which
            // is why this needs no queue of its own, unlike the managed stack.
            _drainAgain = true;
            return;
        }

        _draining = true;
        try
        {
            do
            {
                _drainAgain = false;

                bool staged = false;
                while (true)
                {
                    int produced = DrainOnce();
                    if (produced <= 0)
                    {
                        break;
                    }

                    _pipe.Output.Write(_egress.AsSpan(0, produced));
                    staged = true;
                }

                if (staged)
                {
                    await _pipe.Output.FlushAsync();
                }
            }
            while (_drainAgain && _handle != 0);
        }
        finally
        {
            _draining = false;
        }

        WakeParkedWriters();
    }

    private unsafe int DrainOnce()
    {
        fixed (byte* buffer = _egress)
        {
            nint produced = Nghttp2.ih2_write(_handle, buffer, (nuint)_egress.Length);
            if (produced < 0)
            {
                _failed = true;
                return 0;
            }
            return (int)produced;
        }
    }
}
