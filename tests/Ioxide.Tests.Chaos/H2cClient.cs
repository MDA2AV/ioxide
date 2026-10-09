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

    private const byte Data = 0x0, Headers = 0x1, Settings = 0x4, GoAway = 0x7;
    private const byte EndStream = 0x1, EndHeaders = 0x4, Ack = 0x1;

    public const byte RstStream = 0x3, Continuation = 0x9;

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

    public H2cClient(int port, int timeoutMs = 6000)
    {
        _tcp = new TcpClient();
        _tcp.Connect("127.0.0.1", port);
        _tcp.ReceiveTimeout = timeoutMs;
        _s = _tcp.GetStream();
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
        _s.Write(hdr);
        if (!actual.IsEmpty)
        {
            _s.Write(actual);
        }
        _s.Flush();
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
