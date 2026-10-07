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

    private const byte Data = 0x0, Headers = 0x1, Settings = 0x4, GoAway = 0x7, WindowUpdate = 0x8;
    private const byte EndStream = 0x1, EndHeaders = 0x4, Ack = 0x1;
    private const ushort InitialWindowSizeSetting = 0x4;

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
    /// POST <paramref name="length"/> body bytes within the server's flow-control windows, reading
    /// what arrives before sending more, until the server answers, resets the stream or goes away.
    /// Windows are counted from the connection's start: call it first, right after <see cref="Open"/>.
    /// </summary>
    /// <returns>How it ended, the RST_STREAM or GOAWAY error code, and the body bytes sent.</returns>
    public (UploadEnd End, uint ErrorCode, long Sent) Upload(int streamId, long length, int timeoutMs = 30_000)
    {
        const int MaxFrame = 16384;   // RFC 9113's floor for SETTINGS_MAX_FRAME_SIZE; neither server raises it

        long connectionWindow = 65535, streamWindow = 65535, initialWindow = 65535, sent = 0;
        byte[] chunk = new byte[MaxFrame];

        WriteFrame(Headers, EndHeaders, streamId, Hpack("POST", "/upload"));

        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            long allowed = Math.Min(Math.Min(connectionWindow, streamWindow), Math.Min(MaxFrame, length - sent));
            if (allowed > 0 && _tcp.Available == 0)
            {
                sent += allowed;
                WriteFrame(Data, sent == length ? EndStream : (byte)0, streamId, chunk.AsSpan(0, (int)allowed));
                connectionWindow -= allowed;
                streamWindow -= allowed;
                continue;
            }

            if (!TryReadFrame(out byte type, out byte flags, out int sid, out byte[] payload))
            {
                return (UploadEnd.Silent, 0, sent);
            }

            if (type == Settings && (flags & Ack) == 0)
            {
                for (int at = 0; at + 6 <= payload.Length; at += 6)
                {
                    if (BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(at)) == InitialWindowSizeSetting)
                    {
                        // RFC 9113 6.9.2: a new initial window resizes streams that are already open.
                        long initial = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(at + 2));
                        streamWindow += initial - initialWindow;
                        initialWindow = initial;
                    }
                }
                WriteFrame(Settings, Ack, 0, ReadOnlySpan<byte>.Empty);
            }
            else if (type == WindowUpdate && payload.Length == 4)
            {
                long increment = BinaryPrimitives.ReadUInt32BigEndian(payload) & 0x7FFFFFFF;
                if (sid == 0)
                {
                    connectionWindow += increment;
                }
                else if (sid == streamId)
                {
                    streamWindow += increment;
                }
            }
            else if (type == RstStream && sid == streamId && payload.Length == 4)
            {
                return (UploadEnd.Reset, BinaryPrimitives.ReadUInt32BigEndian(payload), sent);
            }
            else if (type == Headers && sid == streamId)
            {
                return (UploadEnd.Answered, 0, sent);
            }
            else if (type == GoAway && payload.Length >= 8)
            {
                return (UploadEnd.GoAway, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4)), sent);
            }
        }

        return (UploadEnd.Silent, 0, sent);
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
        return len == 0 || ReadFully(payload);
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
    private static byte[] Hpack(string method, string path)
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
        return buf.ToArray();
    }

    public void Dispose()
    {
        _s.Dispose();
        _tcp.Dispose();
    }
}
