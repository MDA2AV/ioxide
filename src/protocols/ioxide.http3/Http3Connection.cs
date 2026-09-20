using System.Buffers;
using ioxide;

namespace ioxide.http3;

/// <summary>
/// HTTP/3 over any <see cref="QuicConnection"/>, implemented entirely in C# - frame parsing,
/// QPACK (static table + Huffman) and request dispatch, no native dependencies. The public
/// surface mirrors ioxide.nghttp3's H3Connection: a buffered overload (dispatch at end-of-stream,
/// body pre-assembled) and a streaming overload (dispatch at end-of-headers, body pulled through
/// <see cref="Http3Request.BodyReader"/> while the request stream is flow-control paced).
///
/// Our SETTINGS advertise QPACK dynamic-table capacity 0, which pins conforming peers to
/// static-table references and literals - the entire decoder surface this library implements.
/// Everything runs on the reactor thread; wakes for parked body reads are deferred to the end of
/// each drain pass (the same fire-after-unwind discipline the engine uses).
/// </summary>
public sealed partial class Http3Connection
{
    private readonly QuicConnection _quicConnection;
    private bool _fatal;

    // RFC 9114 section 8.1. The code a protocol error closes the connection with.
    private const ulong H3GeneralProtocolError = 0x0101;
    // RFC 9114 8.1 draws the line by WHY the frame is wrong, and the two are not interchangeable:
    // UNEXPECTED is a frame that is not permitted in this state or on this stream, ERROR is one
    // whose layout or size is invalid. A peer debugging its own framing is told different things.
    private const ulong H3FrameUnexpected = 0x0105;
    private const ulong H3FrameError = 0x0106;
    private const ulong H3ExcessiveLoad = 0x0107;
    private const ulong QpackDecompressionFailed = 0x0200;

    private ulong _fatalCode = H3GeneralProtocolError;

    // The transport reported the connection closed. Tracked here because the run loop is where it
    // is observable - QuicConnection keeps its own closed flag private - and because IsBroken has
    // to include it: a streamed writer parked on send capacity is released by nothing else.
    private bool _peerGone;

    // ALPN is settled once, and only once the handshake has finished.
    private bool _alpnChecked;
    private bool _streaming;
    private bool _controlSent;

    // Per-stream ingress state, keyed by stream id. Client bidi (id % 4 == 0) = request streams;
    // client uni (id % 4 == 2) = control / QPACK / push streams.
    private readonly Dictionary<long, ReqStream> _requests = new();
    private readonly Dictionary<long, UniStream> _unis = new();
    private readonly List<long> _ready = [];
    private readonly List<Http3BodyReader> _bodyWakes = [];

    private const long FrameData = 0x0;
    private const long FrameHeaders = 0x1;
    private const int MaxHeaderSection = 64 * 1024;

    private enum ParseState : byte
    {
        FrameHeader,     // accumulating the type+length varints
        HeadersPayload,  // accumulating an encoded field section
        DataPayload,     // streaming DATA payload through
        Skip,            // draining an unknown/greased frame
    }

    private sealed class ReqStream
    {
        public readonly Http3Request Request = new();
        public Http3BodyReader? Sink;

        public ParseState State = ParseState.FrameHeader;
        public readonly byte[] Carry = new byte[16];   // partial frame-header varints across chunks
        public int CarryLen;
        public long Remaining;                          // payload bytes left in the current frame

        public byte[]? HeadersBuf;                      // pooled accumulation for a HEADERS frame
        public int HeadersLen;

        public bool HeadersDone;                        // first HEADERS decoded (later ones = trailers)
        public bool Dispatched;                         // streaming: handler already started
        public bool Finished;                           // fin seen and processed
    }

    private sealed class UniStream
    {
        public bool TypeKnown;
        public bool IsControl;
        public readonly byte[] Carry = new byte[16];
        public int CarryLen;
        // Control-stream frame walk (SETTINGS and friends are parsed-and-ignored, but must be
        // framed correctly); non-control uni streams are drained wholesale.
        public ParseState State = ParseState.FrameHeader;
        public long Remaining;
    }

    public Http3Connection(QuicConnection quicConnection)
    {
        _quicConnection = quicConnection;
    }

    /// <summary>Buffered flavor: dispatch at end-of-stream with the whole body in <see cref="Http3Request.Body"/>.
    /// Owns the handler's connection ref (DecRef on exit).</summary>
    public Task RunAsync(Func<Http3Request, Http3Response> handler)
        => RunCoreAsync(handler, null);

    /// <summary>Streaming flavor: dispatch at END-OF-HEADERS, body pulled through
    /// <see cref="Http3Request.BodyReader"/> while the stream's flow-control window paces the peer.
    /// The handler must resume on the reactor (every ioxide await does). Owns the handler's
    /// connection ref (DecRef on exit).</summary>
    public Task RunAsync(Func<Http3Request, ValueTask<Http3Response>> handler)
        => RunCoreAsync(null, handler);

    private async Task RunCoreAsync(Func<Http3Request, Http3Response>? buffered, Func<Http3Request, ValueTask<Http3Response>>? streaming)
    {
        _streaming = streaming is not null;
        try
        {
            while (true)
            {
                QuicRecvSnapshot snap = await _quicConnection.ReadAsync();
                _peerGone |= snap.IsClosed;

                if (!_controlSent && !_fatal)
                {
                    SendControlStream();
                }

                // RFC 9114 section 3.1: h3 runs over a connection that negotiated the "h3" token,
                // and RFC 9001 section 8.1 makes ALPN mandatory for QUIC. A QuicEngine built with
                // no allow list confirms whatever the client asked for - including nothing at all -
                // so without this an engine created from the constructor's own doc example served
                // HTTP/3 to a client that never claimed to speak it. Pinning ["h3"] on the engine
                // refuses those clients properly during the handshake, with no_application_protocol;
                // this is the backstop for an engine that did not.
                //
                // Checked HERE rather than on entry because the handler runs before the handshake
                // completes, when there is no negotiated protocol to read yet. An open control
                // stream means uni streams are openable, which means the handshake finished.
                if (_controlSent && !_alpnChecked)
                {
                    _alpnChecked = true;
                    if (_quicConnection.NegotiatedProtocol != "h3")
                    {
                        Fatal($"negotiated '{_quicConnection.NegotiatedProtocol ?? "(none)"}', not h3");
                    }
                }

                while (_quicConnection.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                {
                    if (!_fatal)
                    {
                        Feed(in item);
                    }
                    _quicConnection.ReturnBuffer(in item);
                }

                if (!_fatal)
                {
                    FireBodyWakes();
                    if (_streaming)
                    {
                        DispatchReadyStreaming(streaming!);
                    }
                    else
                    {
                        DispatchReady(buffered!);
                    }
                }

                if (snap.IsClosed || _fatal)
                {
                    break;
                }
                _quicConnection.ResetRead();
            }
        }
        finally
        {
            foreach (ReqStream rs in _requests.Values)
            {
                rs.Sink?.Drop();
                ReleaseParseBuffers(rs);
            }
            FireBodyWakes();
            _requests.Clear();

            // Tell the peer why. A protocol error used to end the handler and leave the connection
            // registered and routable: no H3 error code ever reached the client, and the connection
            // sat there until the transport's idle sweep - up to a minute per abusive peer, and
            // with nothing on the wire to explain a request that simply stopped.
            if (_fatal)
            {
                _quicConnection.Close(_fatalCode);
            }

            _quicConnection.DecRef();
        }
    }

    // Our control stream: stream type 0x00, then SETTINGS pinning the QPACK dynamic table to 0
    // (QPACK_MAX_TABLE_CAPACITY = 0, QPACK_BLOCKED_STREAMS = 0) - the contract the decoder relies on.
    private void SendControlStream()
    {
        long ctrl = _quicConnection.OpenUniStream();
        if (ctrl < 0)
        {
            return;   // pre-handshake wake: uni streams aren't openable yet - retry next pass
        }
        _controlSent = true;

        Span<byte> buf = stackalloc byte[16];
        int w = 0;
        w += Varint.Write(buf[w..], 0x00);   // stream type: control
        w += Varint.Write(buf[w..], 0x4);    // SETTINGS
        w += Varint.Write(buf[w..], 4);      //   length
        w += Varint.Write(buf[w..], 0x1);    //   QPACK_MAX_TABLE_CAPACITY
        w += Varint.Write(buf[w..], 0);      //     = 0
        w += Varint.Write(buf[w..], 0x7);    //   QPACK_BLOCKED_STREAMS
        w += Varint.Write(buf[w..], 0);      //     = 0
        _quicConnection.SendStream(ctrl, buf[..w], fin: false);
    }

    // --- ingress -------------------------------------------------------------------------------

    private void Feed(in QuicRecvRing.Delivery item)
    {
        if (item.Kind != QuicStreamEvent.Data)
        {
            if (_requests.Remove(item.StreamId, out ReqStream? dead))
            {
                dead.Sink?.End();
                ReleaseParseBuffers(dead);
            }
            _unis.Remove(item.StreamId);
            return;
        }

        if ((item.StreamId & 0x3) == 0x2)
        {
            FeedUni(item.StreamId, item.AsSpan(), item.Fin);
            return;
        }
        if ((item.StreamId & 0x3) != 0x0)
        {
            return;   // server-initiated ids never carry peer data
        }

        if (!_requests.TryGetValue(item.StreamId, out ReqStream? rs))
        {
            if (item.Fin && item.Len == 0)
            {
                return;   // empty stream - nothing ever to answer
            }
            rs = new ReqStream();
            rs.Request.StreamId = item.StreamId;
            _requests[item.StreamId] = rs;
        }

        FeedRequest(item.StreamId, rs, item.AsSpan(), item.Fin);
    }

    private void FeedRequest(long sid, ReqStream rs, ReadOnlySpan<byte> data, bool fin)
    {
        // Bytes the parser consumes that are NOT handed to the body sink (frame headers, HEADERS
        // payload, trailers, grease) credit the flow-control window immediately once the stream is
        // paced; sink bytes credit as the handler pulls them.
        int immediateCredit = 0;

        while (!data.IsEmpty && !_fatal)
        {
            switch (rs.State)
            {
                case ParseState.FrameHeader:
                {
                    int take = Math.Min(rs.Carry.Length - rs.CarryLen, data.Length);
                    data[..take].CopyTo(rs.Carry.AsSpan(rs.CarryLen));
                    int have = rs.CarryLen + take;

                    if (!Varint.TryRead(rs.Carry.AsSpan(0, have), out long type, out int c1) ||
                        !Varint.TryRead(rs.Carry.AsSpan(c1, have - c1), out long len, out int c2))
                    {
                        if (have == rs.Carry.Length)
                        {
                            Fatal("oversized frame header", H3FrameError);
                            return;
                        }
                        rs.CarryLen = have;
                        if (rs.Sink is not null)
                        {
                            immediateCredit += take;
                        }
                        data = data[take..];
                        continue;
                    }

                    int headerBytes = c1 + c2;
                    int fromData = headerBytes - rs.CarryLen;   // header bytes consumed from THIS chunk
                    rs.CarryLen = 0;
                    if (rs.Sink is not null)
                    {
                        immediateCredit += fromData;
                    }
                    data = data[fromData..];

                    if (type == FrameData)
                    {
                        if (!rs.HeadersDone)
                        {
                            Fatal("DATA before HEADERS", H3FrameUnexpected);
                            return;
                        }
                        rs.State = len == 0 ? ParseState.FrameHeader : ParseState.DataPayload;
                        rs.Remaining = len;
                    }
                    else if (type == FrameHeaders)
                    {
                        if (len > MaxHeaderSection)
                        {
                            Fatal("header section too large", H3ExcessiveLoad);
                            return;
                        }
                        rs.HeadersBuf = ArrayPool<byte>.Shared.Rent((int)len);
                        rs.HeadersLen = 0;
                        rs.State = ParseState.HeadersPayload;
                        rs.Remaining = len;
                        if (len == 0)
                        {
                            Fatal("empty HEADERS frame", H3FrameError);
                            return;
                        }
                    }
                    else if (type is 0x3 or 0x4 or 0x5 or 0x7 or 0xD)
                    {
                        Fatal($"frame 0x{type:x} unexpected on a request stream", H3FrameUnexpected);
                        return;
                    }
                    else
                    {
                        rs.State = len == 0 ? ParseState.FrameHeader : ParseState.Skip;   // grease
                        rs.Remaining = len;
                    }
                    break;
                }

                case ParseState.HeadersPayload:
                {
                    int take = (int)Math.Min(rs.Remaining, data.Length);
                    data[..take].CopyTo(rs.HeadersBuf.AsSpan(rs.HeadersLen));
                    rs.HeadersLen += take;
                    rs.Remaining -= take;
                    if (rs.Sink is not null)
                    {
                        immediateCredit += take;
                    }
                    data = data[take..];

                    if (rs.Remaining == 0)
                    {
                        OnHeadersComplete(sid, rs);
                        ArrayPool<byte>.Shared.Return(rs.HeadersBuf!);
                        rs.HeadersBuf = null;
                        rs.State = ParseState.FrameHeader;
                    }
                    break;
                }

                case ParseState.DataPayload:
                {
                    int take = (int)Math.Min(rs.Remaining, data.Length);
                    if (rs.Sink is not null)
                    {
                        rs.Sink.Push(data[..take]);   // credited on hand-out, not here
                    }
                    else
                    {
                        rs.Request.BodyBuffer ??= new MemoryStream();
                        rs.Request.BodyBuffer.Write(data[..take]);
                    }
                    rs.Remaining -= take;
                    data = data[take..];
                    if (rs.Remaining == 0)
                    {
                        rs.State = ParseState.FrameHeader;
                    }
                    break;
                }

                case ParseState.Skip:
                {
                    int take = (int)Math.Min(rs.Remaining, data.Length);
                    rs.Remaining -= take;
                    if (rs.Sink is not null)
                    {
                        immediateCredit += take;
                    }
                    data = data[take..];
                    if (rs.Remaining == 0)
                    {
                        rs.State = ParseState.FrameHeader;
                    }
                    break;
                }
            }
        }

        if (immediateCredit > 0)
        {
            _quicConnection.ConsumeStreamData(sid, immediateCredit);
        }

        if (fin && !_fatal && !rs.Finished)
        {
            if (rs.State != ParseState.FrameHeader || rs.CarryLen != 0)
            {
                Fatal("stream ended mid-frame", H3FrameError);
                return;
            }
            rs.Finished = true;

            if (_streaming)
            {
                rs.Sink?.End();
            }
            else if (rs.HeadersDone)
            {
                _ready.Add(sid);
            }
        }
    }

    // First HEADERS frame = the request's field section; later ones are trailers (validated by the
    // frame walk, contents dropped - nothing in the surface carries them yet).
    private void OnHeadersComplete(long sid, ReqStream rs)
    {
        if (rs.HeadersDone)
        {
            return;
        }

        if (!Qpack.TryDecodeFieldSection(rs.HeadersBuf.AsSpan(0, rs.HeadersLen), rs.Request))
        {
            Fatal("malformed field section", QpackDecompressionFailed);
            return;
        }
        rs.HeadersDone = true;

        if (_streaming && !rs.Dispatched)
        {
            rs.Dispatched = true;
            var sink = new Http3BodyReader(this, sid, ended: false);
            rs.Sink = sink;
            rs.Request.BodyReader = sink;
            _quicConnection.SetStreamPaced(sid, true);
            _ready.Add(sid);
        }
    }

    // Client uni streams: type varint, then control-stream frames (parsed, ignored) or a plain
    // drain for QPACK/push/greased types - with capacity 0 the QPACK streams carry nothing we need.
    private void FeedUni(long sid, ReadOnlySpan<byte> data, bool fin)
    {
        if (!_unis.TryGetValue(sid, out UniStream? us))
        {
            us = new UniStream();
            _unis[sid] = us;
        }

        if (!us.TypeKnown)
        {
            int take = Math.Min(us.Carry.Length - us.CarryLen, data.Length);
            data[..take].CopyTo(us.Carry.AsSpan(us.CarryLen));
            int have = us.CarryLen + take;
            if (!Varint.TryRead(us.Carry.AsSpan(0, have), out long type, out int consumed))
            {
                us.CarryLen = have;
                return;
            }
            us.TypeKnown = true;
            us.IsControl = type == 0x00;
            int fromData = consumed - us.CarryLen;
            us.CarryLen = 0;
            data = data[fromData..];
        }

        if (!us.IsControl)
        {
            return;   // QPACK enc/dec, push, grease: drain (auto-credited - uni streams are never paced)
        }

        while (!data.IsEmpty && !_fatal)
        {
            if (us.State == ParseState.FrameHeader)
            {
                int take = Math.Min(us.Carry.Length - us.CarryLen, data.Length);
                data[..take].CopyTo(us.Carry.AsSpan(us.CarryLen));
                int have = us.CarryLen + take;
                if (!Varint.TryRead(us.Carry.AsSpan(0, have), out _, out int c1) ||
                    !Varint.TryRead(us.Carry.AsSpan(c1, have - c1), out long len, out int c2))
                {
                    if (have == us.Carry.Length)
                    {
                        Fatal("oversized control frame header", H3FrameError);
                        return;
                    }
                    us.CarryLen = have;
                    return;
                }
                int fromData = c1 + c2 - us.CarryLen;
                us.CarryLen = 0;
                data = data[fromData..];
                us.State = len == 0 ? ParseState.FrameHeader : ParseState.Skip;
                us.Remaining = len;   // SETTINGS/GOAWAY/MAX_PUSH_ID payloads: parsed as framing, values ignored
            }
            else
            {
                int take = (int)Math.Min(us.Remaining, data.Length);
                us.Remaining -= take;
                data = data[take..];
                if (us.Remaining == 0)
                {
                    us.State = ParseState.FrameHeader;
                }
            }
        }

        if (fin)
        {
            _unis.Remove(sid);
        }
    }

    // --- dispatch ------------------------------------------------------------------------------

    private void DispatchReady(Func<Http3Request, Http3Response> handler)
    {
        for (int i = 0; i < _ready.Count && !_fatal; i++)
        {
            if (!_requests.Remove(_ready[i], out ReqStream? rs))
            {
                continue;
            }
            rs.Request.Freeze();

            if (TryDispatchStreamedResponse(rs.Request))
            {
                continue;   // the writer owns this stream now
            }

            Http3Response resp;
            try
            {
                resp = handler(rs.Request);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ioxide.http3] request handler faulted: {e.GetBaseException().Message}");
                resp = new Http3Response { Status = 500 };
            }

            Submit(rs.Request.StreamId, resp);
        }
        _ready.Clear();
    }

    private void DispatchReadyStreaming(Func<Http3Request, ValueTask<Http3Response>> handler)
    {
        for (int i = 0; i < _ready.Count && !_fatal; i++)
        {
            long sid = _ready[i];
            if (!_requests.TryGetValue(sid, out ReqStream? rs))
            {
                continue;
            }
            rs.Request.Freeze();

            ValueTask<Http3Response> pending;
            try
            {
                pending = handler(rs.Request);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ioxide.http3] request handler faulted: {e.GetBaseException().Message}");
                Submit(sid, new Http3Response { Status = 500 });
                continue;
            }

            if (pending.IsCompletedSuccessfully)
            {
                Submit(sid, pending.Result);
            }
            else
            {
                _ = CompleteStreamingAsync(pending, sid);
            }
        }
        _ready.Clear();
    }

    private async Task CompleteStreamingAsync(ValueTask<Http3Response> pending, long streamId)
    {
        Http3Response resp;
        try
        {
            resp = await pending;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[ioxide.http3] request handler faulted: {e.GetBaseException().Message}");
            resp = new Http3Response { Status = 500 };
        }

        if (_fatal)
        {
            return;
        }
        Submit(streamId, resp);
    }

    // --- egress --------------------------------------------------------------------------------

    // Encode and send one response: HEADERS frame (+ DATA frame header) in one SendStream call,
    // the body (with fin) in a second - the engine copies into its retention chunks either way.
    private void Submit(long streamId, Http3Response resp)
    {
        if (resp.HeadIsValid)
        {
            SendSubmitted(streamId, resp, resp.EncodedHead!, resp.EncodedHeadLen);
            return;
        }

        byte[] fields = Qpack.EncodeResponseFields(resp, out int fieldsLen);

        bool hasContentLength = false;
        foreach ((ReadOnlyMemory<byte> name, _) in resp.Headers)
        {
            hasContentLength |= name.Span.SequenceEqual("content-length"u8);
        }

        byte[] head = ArrayPool<byte>.Shared.Rent(fieldsLen + 64);
        int w = 0;

        if (!hasContentLength && resp.Body.Length > 0)
        {
            // content-length appended into the field section: re-encode is overkill, so it rides
            // as an extra literal at the end of the same section buffer.
            Span<byte> digits = stackalloc byte[20];
            System.Buffers.Text.Utf8Formatter.TryFormat(resp.Body.Length, digits, out int dlen);
            Span<byte> extra = stackalloc byte[32];
            int e = Qpack.WriteInt(extra, 0x50, 4, 4);          // literal w/ name ref: content-length (idx 4)
            e += Qpack.WriteInt(extra[e..], 0x00, 7, dlen);
            digits[..dlen].CopyTo(extra[e..]);
            e += dlen;

            w += Varint.Write(head.AsSpan(w), FrameHeaders);
            w += Varint.Write(head.AsSpan(w), fieldsLen + e);
            fields.AsSpan(0, fieldsLen).CopyTo(head.AsSpan(w));
            w += fieldsLen;
            extra[..e].CopyTo(head.AsSpan(w));
            w += e;
        }
        else
        {
            w += Varint.Write(head.AsSpan(w), FrameHeaders);
            w += Varint.Write(head.AsSpan(w), fieldsLen);
            fields.AsSpan(0, fieldsLen).CopyTo(head.AsSpan(w));
            w += fieldsLen;
        }
        ArrayPool<byte>.Shared.Return(fields);

        if (resp.Body.Length > 0)
        {
            w += Varint.Write(head.AsSpan(w), FrameData);
            w += Varint.Write(head.AsSpan(w), resp.Body.Length);
        }

        // Keep it: this exact byte sequence is what every later request with this response needs.
        // Not pooled - it outlives the call by design.
        resp.EncodedHead = head.AsSpan(0, w).ToArray();
        resp.EncodedHeadLen = w;
        resp.EncodedForStatus = resp.Status;
        resp.EncodedForHeaderCount = resp.Headers.Count;
        resp.EncodedForBodyLength = resp.Body.Length;
        ArrayPool<byte>.Shared.Return(head);

        SendSubmitted(streamId, resp, resp.EncodedHead, w);
    }

    // Small bodies ride WITH the head in one send. Two SendStream calls cost two trips through
    // the QUIC send path per response, which on a short response is a large share of the work;
    // one extra copy of a few hundred bytes is cheaper. Large bodies still go on their own,
    // because copying them would cost more than the second call saves.
    private const int InlineBodyLimit = 4 * 1024;

    private void SendSubmitted(long streamId, Http3Response resp, byte[] head, int headLen)
    {
        if (resp.Body.Length == 0)
        {
            _quicConnection.SendStream(streamId, head.AsSpan(0, headLen), fin: true);
            return;
        }

        if (resp.Body.Length <= InlineBodyLimit)
        {
            int total = headLen + resp.Body.Length;
            byte[] one = ArrayPool<byte>.Shared.Rent(total);
            head.AsSpan(0, headLen).CopyTo(one);
            resp.Body.Span.CopyTo(one.AsSpan(headLen));
            _quicConnection.SendStream(streamId, one.AsSpan(0, total), fin: true);
            ArrayPool<byte>.Shared.Return(one);
            return;
        }

        _quicConnection.SendStream(streamId, head.AsSpan(0, headLen), fin: false);
        _quicConnection.SendStream(streamId, resp.Body.Span, fin: true);
    }

    // --- streaming plumbing --------------------------------------------------------------------

    internal void CreditBody(long streamId, int bytes) => _quicConnection.ConsumeStreamData(streamId, bytes);

    internal void NoteBodyWake(Http3BodyReader sink)
    {
        if (!_bodyWakes.Contains(sink))
        {
            _bodyWakes.Add(sink);
        }
    }

    private void FireBodyWakes()
    {
        for (int i = 0; i < _bodyWakes.Count; i++)
        {
            _bodyWakes[i].FireIfReady();
        }
        _bodyWakes.Clear();
    }

    private void Fatal(string reason, ulong code = H3GeneralProtocolError)
    {
        Console.Error.WriteLine($"[ioxide.http3] protocol error: {reason}");
        _fatal = true;
        _fatalCode = code;
    }

    private static void ReleaseParseBuffers(ReqStream rs)
    {
        if (rs.HeadersBuf is not null)
        {
            ArrayPool<byte>.Shared.Return(rs.HeadersBuf);
            rs.HeadersBuf = null;
        }
    }
}
