using System.Buffers;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using Glyph11;
using Glyph11.Parser;
using Glyph11.Parser.UltraHardened;
using Glyph11.Protocol;
using Glyph11.Validation;
using ioxide.utils;

namespace ioxide.httpclient;

/// <summary>
/// One keep-alive HTTP/1.1 connection whose connect, sends and receives all run on the owning
/// reactor's ring and resume inline - the client mirror of the server's connection loop. Sends one
/// request at a time (concurrency comes from the pool's connections, not from pipelining, which
/// real servers handle unevenly).
///
/// Reactor thread only. The send/receive buffers are native and reused across requests; every
/// response gets its own pooled copy, so this connection returns to the pool the moment the
/// response is parsed rather than being pinned until the caller finishes reading.
///
/// C# forbids <c>await</c> inside an unsafe context, so the buffer pointers are touched only by
/// the small non-async helpers below; the async methods stay pure control flow.
/// </summary>
internal sealed class HttpClientConnection : IDisposable
{
    private readonly HttpClientOptions _options;
    private readonly IClientTransport _transport;
    private readonly byte[] _hostHeaderLine;

    private nint _send;
    private int _sendCapacity;

    private nint _receive;
    private int _receiveCapacity;
    private UnmanagedMemoryManager _receiveView;
    private int _received;    // bytes held in the receive buffer
    private int _consumed;    // parsed prefix of those bytes

    // Glyph11's parse target, reused across requests - Clear() between, Dispose() at the end, so
    // the header list's pooled arrays are rented once for the connection's life rather than per
    // response. Its spans point into the receive buffer and stay valid only until the next
    // receive, which is why ParseHead copies what the response keeps.
    private readonly BinaryResponse _head = new();
    private readonly ParserLimits _limits;

    // Framing of the response being read, decided by ParseHead.
    private BodyFramingResult _framing = BodyFramingResult.NoBody;

    private bool _broken;

    /// <summary>True once the connection can't serve another request (peer closed, protocol error,
    /// or the server asked to close). The pool drops these and opens replacements.</summary>
    public bool IsBroken => _broken;

    private unsafe HttpClientConnection(HttpClientOptions options, IClientTransport transport, byte[] hostHeaderLine)
    {
        _options = options;
        _transport = transport;
        _hostHeaderLine = hostHeaderLine;

        // A header block cannot exceed the response ceiling, so the two agree rather than the
        // parser accepting a megabyte of headers the arena would then refuse.
        _limits = ParserLimits.Default with
        {
            MaxTotalHeaderBytes = Math.Min(ParserLimits.Default.MaxTotalHeaderBytes, options.MaxResponseBytes),
        };

        _sendCapacity = options.SendBufferSize;
        _send = (nint)NativeMemory.Alloc((nuint)_sendCapacity);

        _receiveCapacity = options.ReceiveBufferSize;
        _receive = (nint)NativeMemory.Alloc((nuint)_receiveCapacity);

        // Memory<byte> cannot wrap a raw pointer, and Glyph11's zero-copy path slices whatever it
        // is handed - without this view every header block would be copied into a managed array
        // just to be parsed. Rebuilt only when the buffer moves.
        _receiveView = new UnmanagedMemoryManager((byte*)_receive, _receiveCapacity);
    }

    public static async Task<HttpClientConnection> ConnectAsync(IRingHost host, HttpClientOptions options)
    {
        // "host: <authority>\r\n" is fixed for the connection's life - build it once.
        string authority = options.Port is 80 or 443 ? options.Host : $"{options.Host}:{options.Port}";
        byte[] hostHeaderLine = System.Text.Encoding.ASCII.GetBytes($"host: {authority}\r\n");

        IClientTransport transport = await ClientTransport.ConnectAsync(
            host, options.Host, options.Port, options.Tls);

        return new HttpClientConnection(options, transport, hostHeaderLine);
    }

    /// <summary>Send one request and read its response. The response owns its bytes.</summary>
    public async ValueTask<HttpClientResponse> SendAsync(HttpClientRequest request)
    {
        if (_broken)
        {
            throw new HttpClientException("connection is broken");
        }

        try
        {
            await WriteRequestAsync(request);
            return await ReadResponseAsync(request);
        }
        catch
        {
            _broken = true;
            throw;
        }
    }

    // --- request ------------------------------------------------------------------------------

    private async ValueTask WriteRequestAsync(HttpClientRequest request)
    {
        int head = BuildHead(request);

        // A small body rides the same send as the head (one syscall); a large one is sent straight
        // from the caller's memory instead of being copied through the send buffer.
        if (request.Body.Length > 0 && head + request.Body.Length <= _sendCapacity)
        {
            CopyIntoSend(request.Body.Span, head);
            await SendAllAsync(_send, head + request.Body.Length);
            return;
        }

        await SendAllAsync(_send, head);

        if (request.Body.Length > 0)
        {
            using MemoryHandle pinned = request.Body.Pin();
            await SendAllAsync(PointerOf(pinned), request.Body.Length);
        }
    }

    private async ValueTask SendAllAsync(nint buffer, int length)
    {
        int sent = 0;
        while (sent < length)
        {
            int n = await _transport.SendAsync(buffer + sent, length - sent);
            if (n <= 0)
            {
                throw new HttpClientException(n == 0 ? "peer closed while sending" : $"send failed: errno {-n}");
            }
            sent += n;
        }
    }

    // --- response -----------------------------------------------------------------------------

    private async ValueTask<HttpClientResponse> ReadResponseAsync(HttpClientRequest request)
    {
        // Leftovers from the previous response (there should be none) move to the front, so every
        // response parses from offset 0.
        Compact();

        var response = new HttpClientResponse();
        try
        {
            _consumed = await ReadHeadAsync(response, request);

            // 1xx are INTERIM (103 Early Hints, 100 Continue): the real response follows on the
            // same connection. Returning one as final would hand the caller a placeholder and
            // leave the true response buffered for the NEXT request to misread.
            while (response.Status is >= 100 and < 200)
            {
                response.ResetForInterim();
                Compact();
                _consumed = await ReadHeadAsync(response, request);
            }

            await ReadBodyAsync(response);

            response.Freeze();
            if (response.ConnectionClose)
            {
                _broken = true;   // the pool discards and replaces this connection
            }
            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    // Receive until a complete header block is buffered and parsed; returns its total size.
    // Completeness is the parser's call rather than a separate scan for the terminator - one pass
    // decides "not yet" and "here it is, validated" together.
    private async ValueTask<int> ReadHeadAsync(HttpClientResponse response, HttpClientRequest request)
    {
        while (true)
        {
            int headSize = TryParseHead(response, request);
            if (headSize > 0)
            {
                return headSize;
            }
            await ReceiveMoreAsync();
        }
    }

    private async ValueTask ReadBodyAsync(HttpClientResponse response)
    {
        BodyFramingResult framing = _framing;
        _framing = BodyFramingResult.NoBody;

        switch (framing.Framing)
        {
            // HEAD, 1xx, 204, 304 and a CONNECT tunnel all land here. The detector needs the
            // request method to know that, which is why it is passed in: a HEAD response carries
            // the Content-Length its body WOULD have had, so framing on the response alone reads
            // the next response as this one's content.
            case BodyFraming.None:
                response.SetBodyRange((0, 0));
                break;

            case BodyFraming.Chunked:
                await ReadChunkedBodyAsync(response);
                break;

            case BodyFraming.ContentLength:
                await ReadFixedBodyAsync(response, framing.ContentLength);
                break;

            default:
                // No framing header at all: the body runs until the peer closes (HTTP/1.0 style),
                // which also means this connection cannot be reused.
                await ReadUntilCloseAsync(response);
                response.ConnectionClose = true;
                break;
        }
    }

    private async ValueTask ReadFixedBodyAsync(HttpClientResponse response, long length)
    {
        if (length > _options.MaxResponseBytes)
        {
            throw new HttpClientException($"response body of {length} exceeds MaxResponseBytes");
        }

        int start = response.ArenaLength;
        long copied = 0;
        while (copied < length)
        {
            if (_consumed == _received)
            {
                await ReceiveMoreAsync();
            }
            copied += AppendAvailable(response, length - copied);
        }

        response.SetBodyRange((start, (int)length));
    }

    private async ValueTask ReadChunkedBodyAsync(HttpClientResponse response)
    {
        int bodyStart = response.ArenaLength;
        long bodyLength = 0;   // long: an int here wraps negative on a hostile chunk size and
                               // slips past the MaxResponseBytes check below

        while (true)
        {
            int lineEnd = await ReadLineAsync();
            if (!TryParseChunkSize(lineEnd, out int chunkSize))
            {
                throw new HttpClientException("malformed chunk size");
            }
            _consumed = lineEnd + 2;

            if (chunkSize == 0)
            {
                // Trailer section (usually empty) through the final blank line.
                while (true)
                {
                    int trailerEnd = await ReadLineAsync();
                    bool blank = trailerEnd == _consumed;
                    _consumed = trailerEnd + 2;
                    if (blank)
                    {
                        break;
                    }
                }
                break;
            }

            bodyLength += chunkSize;
            if (bodyLength > _options.MaxResponseBytes)
            {
                throw new HttpClientException("chunked response exceeds MaxResponseBytes");
            }

            int copied = 0;
            while (copied < chunkSize)
            {
                if (_consumed == _received)
                {
                    await ReceiveMoreAsync();
                }
                copied += AppendAvailable(response, chunkSize - copied);
            }

            _consumed = await ReadLineAsync() + 2;   // the CRLF terminating the chunk
        }

        response.SetBodyRange((bodyStart, (int)bodyLength));
    }

    private async ValueTask ReadUntilCloseAsync(HttpClientResponse response)
    {
        int start = response.ArenaLength;
        int total = AppendAvailable(response, long.MaxValue);

        while (true)
        {
            try
            {
                await ReceiveMoreAsync();
            }
            catch (HttpClientException)
            {
                break;   // peer closed - that IS the framing here
            }

            total += AppendAvailable(response, long.MaxValue);
            if (total > _options.MaxResponseBytes)
            {
                throw new HttpClientException("response body exceeds MaxResponseBytes");
            }
        }

        response.SetBodyRange((start, total));
    }

    // Ensure one CRLF-terminated line is buffered; returns the offset of its CR.
    private async ValueTask<int> ReadLineAsync()
    {
        while (true)
        {
            int marker = IndexOfCrLf();
            if (marker >= 0)
            {
                return marker;
            }
            await ReceiveMoreAsync();
        }
    }

    // One recv appended to the buffer; returns the byte count, compacting or growing as needed.
    private async ValueTask<int> ReceiveMoreAsync()
    {
        EnsureReceiveSpace();

        int n = await _transport.RecvAsync(_receive + _received, _receiveCapacity - _received);
        if (n <= 0)
        {
            throw new HttpClientException(n == 0 ? "peer closed mid-response" : $"recv failed: errno {-n}");
        }
        _received += n;
        return n;
    }

    // --- pointer helpers (no await inside any of these) ---------------------------------------

    private static unsafe nint PointerOf(MemoryHandle handle) => (nint)handle.Pointer;

    private unsafe void CopyIntoSend(ReadOnlySpan<byte> data, int offset)
        => data.CopyTo(new Span<byte>((void*)(_send + offset), _sendCapacity - offset));

    private unsafe int IndexOfCrLf()
    {
        if (_received <= _consumed)
        {
            return -1;
        }
        int marker = new ReadOnlySpan<byte>((void*)(_receive + _consumed), _received - _consumed)
            .IndexOf("\r\n"u8);
        return marker < 0 ? -1 : _consumed + marker;
    }

    private unsafe bool TryParseChunkSize(int lineEnd, out int size)
    {
        var line = new ReadOnlySpan<byte>((void*)(_receive + _consumed), lineEnd - _consumed);
        int extension = line.IndexOf((byte)';');
        if (extension >= 0)
        {
            line = line[..extension];
        }
        return Utf8Parser.TryParse(line, out size, out _, 'x');
    }

    /// <summary>Copy up to <paramref name="limit"/> unconsumed bytes into the response's arena;
    /// returns how many moved.</summary>
    private unsafe int AppendAvailable(HttpClientResponse response, long limit)
    {
        int take = (int)Math.Min(limit, _received - _consumed);
        if (take <= 0)
        {
            return 0;
        }

        response.Append(new ReadOnlySpan<byte>((void*)(_receive + _consumed), take));
        _consumed += take;
        return take;
    }

    /// <summary>
    /// Parse the buffered bytes as a response head. Returns its total size, or 0 when the block is
    /// not complete yet and more must be received.
    /// </summary>
    /// <remarks>
    /// Structure and hardening are Glyph11's: bare LF, obs-fold, whitespace before the colon,
    /// token and field-value charsets, duplicate and malformed Content-Length, and the
    /// Transfer-Encoding + Content-Length pair that lets a proxy and a client disagree about where
    /// this response ends. What stays here is what Glyph11 has no opinion on - copying the fields
    /// the caller keeps, and connection reuse.
    /// </remarks>
    private unsafe int TryParseHead(HttpClientResponse response, HttpClientRequest request)
    {
        if (_received == 0)
        {
            return 0;
        }

        _head.Clear();
        ReadOnlyMemory<byte> buffered = ReceiveBufferAsMemory();

        bool complete;
        int bytesRead;
        try
        {
            complete = UltraHardenedParser.TryExtractFullResponseHeaderROM(
                ref buffered, _head, in _limits, out bytesRead);
        }
        catch (HttpParseException e)
        {
            // A malformed response is not recoverable on a keep-alive connection: the framing is
            // exactly what was in doubt, so there is no safe offset to resume from.
            throw new HttpClientException($"malformed response head: {e.Message}", e);
        }

        if (!complete)
        {
            return 0;
        }

        // Glyph11 reports one less than the block's real size - see the note in its diff harness,
        // "C# returns total-1; the C ABI returns the clean total".
        int headSize = bytesRead + 1;

        response.Status = _head.Status;

        for (int i = 0; i < _head.Headers.Count; i++)
        {
            var field = _head.Headers[i];

            (int Offset, int Length) nameRange = response.Append(field.Key.Span);
            response.LowercaseArena(nameRange);
            (int Offset, int Length) valueRange = response.Append(field.Value.Span);
            response.AddHeaderRange(nameRange, valueRange);
        }

        // Framing needs the request method - see ReadBodyAsync.
        _framing = BodyFramingDetector.DetectResponseBodyFraming(_head, request.Method.Span);
        response.ConnectionClose = ShouldClose();

        return headSize;
    }

    /// <summary>
    /// Whether this connection can carry another request. Not a parsing question - Glyph11 reads
    /// the field, RFC 9112 §9.3 decides what it means - and the default flips with the version:
    /// HTTP/1.1 persists unless told to close, HTTP/1.0 closes unless told to persist.
    /// </summary>
    private bool ShouldClose()
    {
        bool http10 = _head.Version.Length == 8 && _head.Version.Span[7] == (byte)'0';
        bool sawClose = false;
        bool sawKeepAlive = false;

        for (int i = 0; i < _head.Headers.Count; i++)
        {
            var field = _head.Headers[i];
            if (!EqualsIgnoreCase(field.Key.Span, "connection"u8))
            {
                continue;
            }

            sawClose |= ContainsToken(field.Value.Span, "close"u8);
            sawKeepAlive |= ContainsToken(field.Value.Span, "keep-alive"u8);
        }

        return http10 ? !sawKeepAlive : sawClose;
    }

    private ReadOnlyMemory<byte> ReceiveBufferAsMemory() => _receiveView!.Memory[.._received];

    private unsafe void Compact()
    {
        if (_consumed == 0)
        {
            return;
        }
        int remaining = _received - _consumed;
        if (remaining > 0)
        {
            Buffer.MemoryCopy((void*)(_receive + _consumed), (void*)_receive, _receiveCapacity, remaining);
        }
        _received = remaining;
        _consumed = 0;
    }

    private unsafe void EnsureReceiveSpace()
    {
        if (_received < _receiveCapacity)
        {
            return;
        }

        Compact();
        if (_received < _receiveCapacity)
        {
            return;
        }

        if (_receiveCapacity >= _options.MaxResponseBytes)
        {
            throw new HttpClientException("response exceeds MaxResponseBytes");
        }
        _receiveCapacity = Math.Min(_receiveCapacity * 2, _options.MaxResponseBytes);
        _receive = (nint)NativeMemory.Realloc((void*)_receive, (nuint)_receiveCapacity);

        // Realloc can move the block, so the view handed to the parser has to be rebuilt. Reset is
        // internal to ioxide, and this only happens when the buffer actually grows.
        _receiveView = new UnmanagedMemoryManager((byte*)_receive, _receiveCapacity);
    }

    /// <summary>Refuses a CR, LF or NUL anywhere in the head, which BuildHead would write as given.</summary>
    internal static void ValidateHead(HttpClientRequest request)
    {
        ThrowIfLineBreak(request.Method.Span, "method");
        ThrowIfLineBreak(request.Path.Span, "target");
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            ThrowIfLineBreak(field.Key.Span, "header name");
            ThrowIfLineBreak(field.Value.Span, "header value");
        }
    }

    // CR or LF ends the line early, adding field lines or a second request; servers disagree on NUL.
    private static void ThrowIfLineBreak(ReadOnlySpan<byte> part, string what)
    {
        if (part.IndexOfAny((byte)'\r', (byte)'\n', (byte)0) >= 0)
        {
            throw new ArgumentException($"request {what} contains CR, LF or NUL", "request");
        }
    }

    private unsafe int BuildHead(HttpClientRequest request)
    {
        int needed = request.Method.Length + request.Path.Length + _hostHeaderLine.Length + 64;
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            needed += field.Key.Length + field.Value.Length + 4;
        }
        if (needed > _sendCapacity)
        {
            _sendCapacity = needed;
            _send = (nint)NativeMemory.Realloc((void*)_send, (nuint)_sendCapacity);
        }

        var buffer = new Span<byte>((void*)_send, _sendCapacity);
        int cursor = 0;

        request.Method.Span.CopyTo(buffer[cursor..]);
        cursor += request.Method.Length;
        buffer[cursor++] = (byte)' ';

        request.Path.Span.CopyTo(buffer[cursor..]);
        cursor += request.Path.Length;

        " HTTP/1.1\r\n"u8.CopyTo(buffer[cursor..]);
        cursor += 11;

        _hostHeaderLine.CopyTo(buffer[cursor..]);
        cursor += _hostHeaderLine.Length;

        if (request.Body.Length > 0)
        {
            "content-length: "u8.CopyTo(buffer[cursor..]);
            cursor += 16;
            Utf8Formatter.TryFormat(request.Body.Length, buffer[cursor..], out int written);
            cursor += written;
            "\r\n"u8.CopyTo(buffer[cursor..]);
            cursor += 2;
        }

        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            field.Key.Span.CopyTo(buffer[cursor..]);
            cursor += field.Key.Length;
            ": "u8.CopyTo(buffer[cursor..]);
            cursor += 2;
            field.Value.Span.CopyTo(buffer[cursor..]);
            cursor += field.Value.Length;
            "\r\n"u8.CopyTo(buffer[cursor..]);
            cursor += 2;
        }

        "\r\n"u8.CopyTo(buffer[cursor..]);
        return cursor + 2;
    }

    private static bool EqualsIgnoreCase(ReadOnlySpan<byte> left, ReadOnlySpan<byte> lowercaseRight)
    {
        if (left.Length != lowercaseRight.Length)
        {
            return false;
        }
        for (int i = 0; i < left.Length; i++)
        {
            byte b = left[i];
            if (b is >= (byte)'A' and <= (byte)'Z')
            {
                b = (byte)(b | 0x20);
            }
            if (b != lowercaseRight[i])
            {
                return false;
            }
        }
        return true;
    }

    // Case-insensitive comma-separated token match ("keep-alive, Upgrade" contains "keep-alive").
    private static bool ContainsToken(ReadOnlySpan<byte> value, ReadOnlySpan<byte> lowercaseToken)
    {
        while (!value.IsEmpty)
        {
            int comma = value.IndexOf((byte)',');
            ReadOnlySpan<byte> token = (comma < 0 ? value : value[..comma]).Trim((byte)' ');
            if (EqualsIgnoreCase(token, lowercaseToken))
            {
                return true;
            }
            if (comma < 0)
            {
                break;
            }
            value = value[(comma + 1)..];
        }
        return false;
    }

    public unsafe void Dispose()
    {
        _broken = true;
        _transport.Dispose();
        _head.Dispose();   // returns the header list's pooled arrays
        if (_send != 0)
        {
            NativeMemory.Free((void*)_send);
            _send = 0;
        }
        if (_receive != 0)
        {
            NativeMemory.Free((void*)_receive);
            _receive = 0;
        }
    }
}

/// <summary>Any client-side failure: connect, send, recv, or a malformed response.</summary>
public sealed class HttpClientException : Exception
{
    public HttpClientException(string message) : base(message) { }

    /// <summary>
    /// Wraps the underlying failure - a parse rejection carries which rule the origin broke, which
    /// is the whole diagnostic when a response is refused.
    /// </summary>
    public HttpClientException(string message, Exception innerException)
        : base(message, innerException) { }
}
