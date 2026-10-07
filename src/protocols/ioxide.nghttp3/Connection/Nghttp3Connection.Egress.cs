using System.Buffers;
using System.Buffers.Text;

namespace ioxide.nghttp3;

/// <summary>Egress: submit a response into nghttp3 (packed headers + body, both copied by the
/// native side) and drain its produced stream chunks into the QUIC engine.</summary>
public sealed partial class Nghttp3Connection
{
    private unsafe void QueueResponse(long streamId, Nghttp3Response response)
    {
        if (_nghttp3Handle == 0)
        {
            return;   // connection torn down under an in-flight streaming handler
        }

        byte[] headers = PackHeaders(response, out int headersLength);
        int submitResult;
        fixed (byte* headersPointer = headers)
        fixed (byte* bodyPointer = response.Body.Span)
        {
            submitResult = Nghttp3.ih3_submit_response(_nghttp3Handle, streamId, headersPointer, (nuint)headersLength,
                bodyPointer, (nuint)response.Body.Length);
        }
        ArrayPool<byte>.Shared.Return(headers);

        // A stream that closed while its handler ran was a cancelled request, not a failed connection.
        if (submitResult != 0 && submitResult != Nghttp3.NGHTTP3_ERR_STREAM_NOT_FOUND)
        {
            Console.Error.WriteLine($"[ioxide.nghttp3] submit_response failed: {Nghttp3.StrError(submitResult)}");
            FailProtocol(submitResult);
        }
    }

    // Pump nghttp3's egress (SETTINGS, QPACK prefaces, response frames) into the QUIC engine.
    private unsafe bool PumpEgress()
    {
        bool producedAnything = false;
        if (_nghttp3Handle == 0)
        {
            return producedAnything;
        }
        fixed (byte* egressPointer = _egress)
        {
            while (true)
            {
                // Backpressure: stop draining a large response once the connection's send retention
                // is at its high-water. nghttp3 holds the un-pulled tail; the RunBuffered loop calls
                // PumpEgress again on the next inbound datagram (acks drain retention), so it resumes.
                if (!_quicConnection.CanQueueSend)
                {
                    return producedAnything;
                }

                long streamId;
                int fin;
                long producedBytes = Nghttp3.ih3_writev(_nghttp3Handle, &streamId, &fin, egressPointer, (nuint)_egress.Length);
                if (producedBytes < 0)
                {
                    Console.Error.WriteLine($"[ioxide.nghttp3] writev failed: {Nghttp3.StrError((int)producedBytes)}");
                    FailProtocol((int)producedBytes);
                    return producedAnything;
                }
                if (producedBytes > 0)
                {
                    producedAnything = true;
                }

                if (producedBytes == 0 && streamId == -1)
                {
                    return producedAnything;
                }
                _quicConnection.SendStream(streamId, _egress.AsSpan(0, (int)producedBytes), fin != 0);
            }
        }
    }

    // [u16 namelen][name][u16 valuelen][value]... (little-endian u16, written and read on the
    // same host) - ":status" first, content-length appended when a body is present and the
    // handler didn't set one. Names are lowercased as they're copied (h3 wire requirement);
    // numbers go through Utf8Formatter - no strings anywhere. The buffer is pooled: nghttp3
    // copies the entries during submit (NGHTTP3_NV_FLAG_NONE), so it's returned right after.
    private static byte[] PackHeaders(Nghttp3Response response, out int written)
    {
        int capacity = (4 + 7 + 3) + (4 + 14 + 20);   // :status + a worst-case content-length
        foreach ((ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) in response.Headers.AsSpan())
        {
            capacity += 4 + name.Length + value.Length;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(capacity);
        int cursor = 0;
        Span<byte> numberScratch = stackalloc byte[20];

        static void WriteUInt16(byte[] destination, ref int offset, int value)
        {
            destination[offset++] = (byte)value;
            destination[offset++] = (byte)(value >> 8);
        }

        WriteUInt16(buffer, ref cursor, 7);
        ":status"u8.CopyTo(buffer.AsSpan(cursor));
        cursor += 7;
        Utf8Formatter.TryFormat(response.Status, numberScratch, out int numberLength);
        WriteUInt16(buffer, ref cursor, numberLength);
        numberScratch[..numberLength].CopyTo(buffer.AsSpan(cursor));
        cursor += numberLength;

        bool hasContentLength = false;
        foreach ((ReadOnlyMemory<byte> nameMemory, ReadOnlyMemory<byte> valueMemory) in response.Headers.AsSpan())
        {
            ReadOnlySpan<byte> name = nameMemory.Span;
            WriteUInt16(buffer, ref cursor, name.Length);
            int nameStart = cursor;
            foreach (byte nameByte in name)
            {
                buffer[cursor++] = nameByte is >= (byte)'A' and <= (byte)'Z' ? (byte)(nameByte | 0x20) : nameByte;
            }
            hasContentLength |= buffer.AsSpan(nameStart, name.Length).SequenceEqual("content-length"u8);

            WriteUInt16(buffer, ref cursor, valueMemory.Length);
            valueMemory.Span.CopyTo(buffer.AsSpan(cursor));
            cursor += valueMemory.Length;
        }

        if (!hasContentLength && response.Body.Length > 0)
        {
            WriteUInt16(buffer, ref cursor, 14);
            "content-length"u8.CopyTo(buffer.AsSpan(cursor));
            cursor += 14;
            Utf8Formatter.TryFormat(response.Body.Length, numberScratch, out numberLength);
            WriteUInt16(buffer, ref cursor, numberLength);
            numberScratch[..numberLength].CopyTo(buffer.AsSpan(cursor));
            cursor += numberLength;
        }

        written = cursor;
        return buffer;
    }
}
