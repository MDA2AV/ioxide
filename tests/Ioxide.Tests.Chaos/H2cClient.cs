using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace Ioxide.Tests;

/// <summary>
/// A raw h2c (cleartext, prior-knowledge HTTP/2) client - just enough framing to open a connection,
/// throw hand-built frames at the server, and see whether a request comes back answered. It never
/// decodes the response headers (the server's handler always answers 200); a HEADERS frame arriving
/// on the request stream is the liveness signal. Encoding is the simplest legal HPACK: literal, no
/// indexing, no Huffman.
/// </summary>
public sealed class H2cClient : IDisposable
{
    // RFC 9113 3.4 - the connection preface every h2c client sends first.
    private static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    private const byte Data = 0x0, Headers = 0x1, Settings = 0x4, Ping = 0x6, GoAway = 0x7, WindowUpdate = 0x8;
    private const byte EndStream = 0x1, EndHeaders = 0x4, Padded = 0x8, Ack = 0x1;
    private const ushort InitialWindowSizeSetting = 0x4;
    private const int MaxFrame = 16384;   // RFC 9113's floor for SETTINGS_MAX_FRAME_SIZE; neither server raises it

    // The server's flow-control windows as this client must respect them, kept across streams so
    // several uploads can share one connection. RFC 9113's 65535 until the server says otherwise.
    private long _connectionWindow = 65535;
    private long _initialWindow = 65535;

    private static readonly byte[] PingPayload = new byte[8];

    public const byte RstStream = 0x3, Continuation = 0x9;

    /// <summary>RFC 9113 ENHANCE_YOUR_CALM, what both servers reset an oversized request body with.</summary>
    public const uint EnhanceYourCalm = 0xb;

    /// <summary>How an <see cref="Upload"/> ended.</summary>
    public enum UploadEnd
    {
        /// <summary>HEADERS came back on the stream: the request was served.</summary>
        Answered,

        /// <summary>RST_STREAM on the stream. The error code says why.</summary>
        Reset,

        /// <summary>GOAWAY: the whole connection ended, not just the stream.</summary>
        GoAway,

        /// <summary>The connection closed, or nothing arrived in time.</summary>
        Silent,
    }

    /// <summary>
    /// POST <paramref name="length"/> body bytes of <see cref="PatternAt"/> within the server's
    /// flow-control windows, reading what arrives before sending more, until the server has answered
    /// and the whole body is sent, or it resets the stream, or goes away. An answer that comes early
    /// does not stop the body: a real client still sends it, and the server still has to credit it.
    /// </summary>
    /// <param name="padding">
    /// Pad every DATA frame with this many bytes. Padding counts against both windows and never
    /// reaches the handler.
    /// </param>
    /// <param name="onStall">
    /// Called once, with the bytes sent so far, when the client is out of window and the server has
    /// demonstrably caught up without granting more: a PING sent after the last DATA came back
    /// acknowledged with no WINDOW_UPDATE ahead of it.
    /// </param>
    /// <returns>How it ended, the RST_STREAM or GOAWAY error code, and the body bytes sent.</returns>
    public (UploadEnd End, uint ErrorCode, long Sent) Upload(int streamId, long length, string path = "/upload",
        int padding = 0, Action<long>? onStall = null, int timeoutMs = 30_000)
    {
        int overhead = padding > 0 ? 1 + padding : 0;   // the pad length byte, then the padding
        long streamWindow = _initialWindow, sent = 0;
        bool answered = false, pinged = false, pingAcked = false;
        byte[] frame = new byte[MaxFrame];

        WriteFrame(Headers, EndHeaders, streamId, Hpack("POST", path));

        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            long window = Math.Min(_connectionWindow, streamWindow) - overhead;
            long allowed = Math.Min(Math.Min(window, MaxFrame - overhead), length - sent);
            if (allowed > 0 && _tcp.Available == 0)
            {
                int at = 0;
                if (padding > 0)
                {
                    frame[at++] = (byte)padding;
                }
                for (int i = 0; i < allowed; i++)
                {
                    frame[at++] = PatternAt(sent + i);
                }
                frame.AsSpan(at, padding).Clear();

                sent += allowed;
                byte flags = (byte)((sent == length ? EndStream : 0) | (padding > 0 ? Padded : 0));
                WriteFrame(Data, flags, streamId, frame.AsSpan(0, at + padding));
                _connectionWindow -= allowed + overhead;
                streamWindow -= allowed + overhead;
                pinged = pingAcked = false;
                continue;
            }

            if (answered && sent == length)
            {
                return (UploadEnd.Answered, 0, sent);
            }

            if (onStall is not null && sent < length && _tcp.Available == 0)
            {
                if (pingAcked)
                {
                    onStall(sent);
                    onStall = null;
                }
                else if (!pinged)
                {
                    WriteFrame(Ping, 0, 0, PingPayload);
                    pinged = true;
                }
            }

            long initialBefore = _initialWindow;
            if (!TryReadFrame(out byte type, out byte frameFlags, out int sid, out byte[] payload))
            {
                return (UploadEnd.Silent, 0, sent);
            }
            streamWindow += _initialWindow - initialBefore;   // RFC 9113 6.9.2: it resizes open streams too

            if (type == Settings && (frameFlags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
            }
            else if (type == WindowUpdate && sid == streamId && payload.Length == 4)
            {
                streamWindow += BinaryPrimitives.ReadUInt32BigEndian(payload) & 0x7FFFFFFF;
            }
            else if (type == Ping && (frameFlags & Ack) != 0 && pinged)
            {
                pingAcked = true;   // a WINDOW_UPDATE written with it may still be in the socket
            }
            else if (type == RstStream && sid == streamId && payload.Length == 4)
            {
                return (UploadEnd.Reset, BinaryPrimitives.ReadUInt32BigEndian(payload), sent);
            }
            else if (type == Headers && sid == streamId)
            {
                answered = true;
            }
            else if (type == GoAway && payload.Length >= 8)
            {
                return (UploadEnd.GoAway, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4)), sent);
            }
        }

        return (UploadEnd.Silent, 0, sent);
    }

    /// <summary>
    /// The body byte <see cref="Upload"/> and <see cref="SendData"/> send at an offset: position-dependent,
    /// so a body reassembled out of order fails on content rather than passing on length.
    /// </summary>
    public static byte PatternAt(long offset) => (byte)(offset % 251);

    /// <summary>HEADERS opening a POST to <paramref name="path"/>, with the body still to follow.</summary>
    public void OpenPost(int streamId, string path, long? contentLength = null)
        => WriteFrame(Headers, EndHeaders, streamId, Hpack("POST", path, contentLength));

    /// <summary>One DATA frame of the body from <paramref name="offset"/>, charged to the connection window.</summary>
    public void SendData(int streamId, long offset, int length)
    {
        byte[] body = new byte[length];
        for (int i = 0; i < length; i++)
        {
            body[i] = PatternAt(offset + i);
        }
        WriteFrame(Data, 0, streamId, body);
        _connectionWindow -= length;
    }

    /// <summary>RST_STREAM with <paramref name="errorCode"/>: the client abandons the stream.</summary>
    public void ResetStream(int streamId, uint errorCode)
    {
        Span<byte> code = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(code, errorCode);
        WriteFrame(RstStream, 0, streamId, code);
    }

    /// <summary>
    /// Pump until the server has credited the connection window back to <paramref name="window"/>,
    /// answering SETTINGS as they arrive. False on timeout, GOAWAY or a closed connection.
    /// </summary>
    public bool AwaitConnectionWindow(long window, int timeoutMs = 8000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (_connectionWindow < window && Environment.TickCount64 < deadline)
        {
            if (!TryReadFrame(out byte type, out byte flags, out _, out _) || type == GoAway)
            {
                return false;
            }
            if (type == Settings && (flags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
            }
        }
        return _connectionWindow >= window;
    }

    /// <summary>
    /// The stream id of the FIRST response to come back, whichever it is. Ordering rather than a
    /// stopwatch is what makes a head-of-line test deterministic: if dispatch waits for each
    /// handler in turn, the slow stream answers first because it was dispatched first.
    /// </summary>
    public int AwaitFirstResponse(int timeoutMs = 8000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (!TryReadFrame(out byte type, out byte flags, out int sid, out _))
            {
                return -1;
            }
            if (type == Settings && (flags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
            }
            else if (type == Headers)
            {
                return sid;
            }
        }
        return -1;
    }

    /// <summary>
    /// Read a stream to its end, reporting how many DATA frames carried it, how many body bytes
    /// arrived, and whether END_STREAM ever came. Frame COUNT is the point: a body delivered whole
    /// and a body delivered in chunks weigh the same.
    /// </summary>
    public (int Frames, int Bytes, bool Ended) DrainBody(int streamId, int timeoutMs = 8000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        int frames = 0, bytes = 0;

        while (Environment.TickCount64 < deadline)
        {
            if (!TryReadFrame(out byte type, out byte flags, out int sid, out byte[] payload))
            {
                return (frames, bytes, false);
            }

            if (type == Settings && (flags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
            }
            else if (type == Data && sid == streamId)
            {
                if (payload.Length > 0)
                {
                    frames++;
                    bytes += payload.Length;
                }
                if ((flags & EndStream) != 0)
                {
                    return (frames, bytes, true);
                }
            }
            else if (type == GoAway)
            {
                return (frames, bytes, false);
            }
        }

        return (frames, bytes, false);
    }

    /// <summary>HEADERS that deliberately leaves the block OPEN, so CONTINUATION must follow.</summary>
    public void RequestHeadersOnly(int streamId, bool endHeaders = true, bool endStream = true)
        => WriteFrame(Headers, (byte)((endHeaders ? EndHeaders : 0) | (endStream ? EndStream : 0)),
                      streamId, Hpack("GET", "/"));

    /// <summary>A WINDOW_UPDATE crediting <paramref name="increment"/> to a stream, or to the connection on stream 0.</summary>
    public void WriteWindowUpdate(int streamId, int increment)
        => WriteFrame(0x8, flags: 0, streamId,
                      [(byte)(increment >> 24), (byte)(increment >> 16), (byte)(increment >> 8), (byte)increment]);

    /// <summary>
    /// Pump until the server sends one of <paramref name="wanted"/> (0 = any stream), answering
    /// SETTINGS as they arrive. Returns the frame type seen, or 0 on timeout or a closed connection.
    /// </summary>
    public byte AwaitAnyOf(ReadOnlySpan<byte> wanted, int streamId = 0, int timeoutMs = 4000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (!TryReadFrame(out byte type, out byte flags, out int sid, out _))
            {
                return 0;
            }
            if (type == Settings && (flags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
                continue;
            }
            foreach (byte want in wanted)
            {
                if (type == want && (streamId == 0 || sid == streamId))
                {
                    return type;
                }
            }
        }
        return 0;
    }

    private readonly TcpClient _tcp;
    private readonly NetworkStream _s;
    private Stream _out;   // where frames go: the socket, or the batch InOneWrite is gathering

    public H2cClient(int port, int timeoutMs = 6000)
    {
        _tcp = new TcpClient();
        _tcp.Connect("127.0.0.1", port);
        _tcp.ReceiveTimeout = timeoutMs;
        _s = _tcp.GetStream();
        _out = _s;
    }

    /// <summary>Preface plus an empty SETTINGS frame - a well-formed connection opening.</summary>
    public void Open()
    {
        _s.Write(Preface);
        WriteFrame(Settings, flags: 0, streamId: 0, ReadOnlySpan<byte>.Empty);
    }

    /// <summary>Send a complete request (HEADERS with END_HEADERS|END_STREAM) on a stream.</summary>
    public void Request(int streamId, string method = "GET", string path = "/")
        => WriteFrame(Headers, EndHeaders | EndStream, streamId, Hpack(method, path));

    /// <summary>A complete request whose header block opens with a dynamic table size update (RFC 7541 6.3).</summary>
    public void RequestWithTableSize(int streamId, int size)
    {
        // 001 and a 5-bit prefixed integer (RFC 7541 5.1).
        var block = new List<byte>();
        if (size < 31)
        {
            block.Add((byte)(0x20 | size));
        }
        else
        {
            block.Add(0x3F);
            for (size -= 31; size >= 0x80; size >>= 7)
            {
                block.Add((byte)(0x80 | (size & 0x7F)));
            }
            block.Add((byte)size);
        }
        block.AddRange(Hpack("GET", "/"));
        WriteFrame(Headers, EndHeaders | EndStream, streamId, block.ToArray());
    }

    /// <summary>Raw preface bytes with no framing - for the bad-preface assault.</summary>
    public void WriteRaw(ReadOnlySpan<byte> bytes)
    {
        _s.Write(bytes);
        _s.Flush();
    }

    public void WriteFrame(byte type, byte flags, int streamId, ReadOnlySpan<byte> payload)
        => WriteFrameHeader(type, flags, streamId, payload.Length, payload);

    /// <summary>
    /// Every frame <paramref name="frames"/> writes goes out in ONE write, so the server reads them
    /// in a single pass instead of acting on the first before the last arrives.
    /// </summary>
    public void InOneWrite(Action frames)
    {
        var batch = new MemoryStream();
        _out = batch;
        try
        {
            frames();
        }
        finally
        {
            _out = _s;
        }
        WriteRaw(batch.ToArray());
    }

    /// <summary>
    /// A frame header whose declared length may DISAGREE with the bytes that follow - the primitive
    /// behind the oversize-frame (declare huge, send nothing) and truncated-frame (declare N, send
    /// fewer) assaults.
    /// </summary>
    public void WriteFrameHeader(byte type, byte flags, int streamId, int declaredLen, ReadOnlySpan<byte> actual)
    {
        Span<byte> hdr = stackalloc byte[9];
        hdr[0] = (byte)(declaredLen >> 16);
        hdr[1] = (byte)(declaredLen >> 8);
        hdr[2] = (byte)declaredLen;
        hdr[3] = type;
        hdr[4] = flags;
        hdr[5] = (byte)(streamId >> 24);
        hdr[6] = (byte)(streamId >> 16);
        hdr[7] = (byte)(streamId >> 8);
        hdr[8] = (byte)streamId;
        _out.Write(hdr);
        if (!actual.IsEmpty)
        {
            _out.Write(actual);
        }
        _out.Flush();
    }

    /// <summary>
    /// Pump inbound frames until a HEADERS lands on <paramref name="streamId"/> (the server answered)
    /// or the deadline passes. Server SETTINGS are ACKed as they arrive; a GOAWAY ends the wait.
    /// </summary>
    public bool AwaitResponse(int streamId, int timeoutMs = 4000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (!TryReadFrame(out byte type, out byte flags, out int sid, out _))
            {
                return false;
            }
            if (type == Settings && (flags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);   // ACK the server's SETTINGS
            }
            else if (type == Headers && sid == streamId)
            {
                return true;
            }
            else if (type == GoAway)
            {
                return false;
            }
        }
        return false;
    }

    /// <summary>
    /// Pump until the server answers a stream, resets one or ends the connection, answering SETTINGS
    /// as they arrive. Returns which, as text a failed assertion prints: "HEADERS 1", "DATA 1",
    /// "RST_STREAM 1 FLOW_CONTROL_ERROR", "GOAWAY PROTOCOL_ERROR" - or "nothing" on a timeout or a
    /// closed connection.
    /// </summary>
    public string AwaitVerdict(int timeoutMs = 4000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (!TryReadFrame(out byte type, out byte flags, out int sid, out byte[] payload))
            {
                return "nothing";
            }
            if (type == Settings && (flags & Ack) == 0)
            {
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
            }
            else if (type == Headers)
            {
                return $"HEADERS {sid}";
            }
            else if (type == Data)
            {
                return $"DATA {sid}";
            }
            else if (type == RstStream && payload.Length == 4)
            {
                return $"RST_STREAM {sid} {ErrorName(payload, 0)}";
            }
            else if (type == GoAway && payload.Length >= 8)
            {
                return $"GOAWAY {ErrorName(payload, 4)}";
            }
        }
        return "nothing";
    }

    /// <summary>The <see cref="AwaitVerdict"/> on <paramref name="frames"/>, sent on a fresh connection.</summary>
    public static string Verdict(int port, Action<H2cClient> frames)
    {
        using var client = new H2cClient(port);
        client.Open();
        frames(client);
        return client.AwaitVerdict();
    }

    // RFC 9113 section 7, for the codes these tests meet.
    private static string ErrorName(byte[] payload, int at)
    {
        uint code = (uint)((payload[at] << 24) | (payload[at + 1] << 16) | (payload[at + 2] << 8) | payload[at + 3]);
        return code switch
        {
            0x1 => "PROTOCOL_ERROR",
            0x3 => "FLOW_CONTROL_ERROR",
            0x7 => "REFUSED_STREAM",
            0x9 => "COMPRESSION_ERROR",
            _ => $"0x{code:x}",
        };
    }

    private bool TryReadFrame(out byte type, out byte flags, out int streamId, out byte[] payload)
    {
        type = 0;
        flags = 0;
        streamId = 0;
        payload = [];

        Span<byte> hdr = stackalloc byte[9];
        if (!ReadFully(hdr))
        {
            return false;
        }

        int len = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2];
        type = hdr[3];
        flags = hdr[4];
        streamId = ((hdr[5] & 0x7f) << 24) | (hdr[6] << 16) | (hdr[7] << 8) | hdr[8];

        payload = new byte[len];
        if (len > 0 && !ReadFully(payload))
        {
            return false;
        }

        // Credit is counted here, whoever is reading, so an upload after any other exchange starts
        // from the windows the server actually granted.
        if (type == WindowUpdate && streamId == 0 && len == 4)
        {
            _connectionWindow += BinaryPrimitives.ReadUInt32BigEndian(payload) & 0x7FFFFFFF;
        }
        else if (type == Settings && (flags & Ack) == 0)
        {
            for (int at = 0; at + 6 <= len; at += 6)
            {
                if (BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(at)) == InitialWindowSizeSetting)
                {
                    _initialWindow = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(at + 2));
                }
            }
        }
        return true;
    }

    private bool ReadFully(Span<byte> buf)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n;
            try
            {
                n = _s.Read(buf[off..]);
            }
            catch (IOException)
            {
                return false;   // read timeout or reset
            }
            if (n <= 0)
            {
                return false;
            }
            off += n;
        }
        return true;
    }

    // Literal header field without indexing, new name, no Huffman (RFC 7541 6.2.2): 0x00, then a
    // length-prefixed name and value. The four request pseudo-headers, in the required order.
    private static byte[] Hpack(string method, string path, long? contentLength = null)
    {
        var buf = new List<byte>();

        void Literal(string name, string value)
        {
            buf.Add(0x00);
            buf.Add((byte)name.Length);
            buf.AddRange(Encoding.ASCII.GetBytes(name));
            buf.Add((byte)value.Length);
            buf.AddRange(Encoding.ASCII.GetBytes(value));
        }

        Literal(":method", method);
        Literal(":scheme", "http");
        Literal(":path", path);
        Literal(":authority", "chaos");
        if (contentLength is { } length)
        {
            Literal("content-length", length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        return buf.ToArray();
    }

    public void Dispose()
    {
        _s.Dispose();
        _tcp.Dispose();
    }
}
