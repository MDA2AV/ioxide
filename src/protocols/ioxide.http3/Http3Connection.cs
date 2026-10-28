using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using ioxide;

namespace ioxide.http3;

/// <summary>
/// HTTP/3 over any <see cref="QuicConnection"/>, implemented entirely in C# - frame parsing,
/// QPACK (static table + Huffman) and request dispatch, no native dependencies. The public
/// surface mirrors ioxide.nghttp3's Nghttp3Connection: <c>RunBufferedAsync</c> answers with a whole
/// response and <c>RunStreamedResponseAsync</c> through a writer, while
/// <see cref="Http3Options.StreamRequestBodies"/> decides how the request body arrives - assembled
/// before dispatch at end-of-stream, or pulled through <see cref="Http3Request.BodyReader"/> from
/// end-of-headers while the request stream is flow-control paced.
///
/// Our SETTINGS advertise QPACK dynamic-table capacity 0, which pins conforming peers to
/// static-table references and literals - the entire decoder surface this library implements.
/// Everything runs on the reactor thread; wakes for parked body reads are deferred to the end of
/// each drain pass (the same fire-after-unwind discipline the engine uses).
/// </summary>
public sealed partial class Http3Connection
{
    private readonly QuicConnection _quicConnection;
    private readonly Http3Options _options;
    private bool _fatal;

    // RFC 9114 section 8.1. The code a protocol error closes the connection with.
    private const ulong H3GeneralProtocolError = 0x0101;
    private const ulong H3ClosedCriticalStream = 0x0104;
    // RFC 9114 8.1 draws the line by WHY the frame is wrong, and the two are not interchangeable:
    // UNEXPECTED is a frame that is not permitted in this state or on this stream, ERROR is one
    // whose layout or size is invalid. A peer debugging its own framing is told different things.
    private const ulong H3FrameUnexpected = 0x0105;
    private const ulong H3FrameError = 0x0106;
    private const ulong H3ExcessiveLoad = 0x0107;
    private const ulong H3RequestIncomplete = 0x010d;
    private const ulong H3MessageError = 0x010e;
    private const ulong QpackDecompressionFailed = 0x0200;

    private ulong _fatalCode = H3GeneralProtocolError;

    // The transport reported the connection closed. Tracked here because the run loop is where it
    // is observable - QuicConnection keeps its own closed flag private - and because IsBroken has
    // to include it: a streamed writer parked on send capacity is released by nothing else.
    private bool _peerGone;

    // ALPN is settled once, and only once the handshake has finished.
    private bool _alpnChecked;
    private bool _streamBodies;
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
        Refused,         // reset as malformed: the rest of the stream is dropped
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

        // The stream was paced, so the engine credited none of what arrived since: the parser
        // credits whatever it does not hand to the reader. That includes what it drops after
        // RetireBody unpaced the stream, because bytes delivered while it was still paced can be
        // in the ring then - over-crediting the ones that arrived after is harmless.
        public bool Paced;
    }

    private sealed class UniStream
    {
        public bool TypeKnown;
        public bool IsControl;
        public bool IsCritical;   // control or QPACK encoder/decoder: the peer may never close one
        public readonly byte[] Carry = new byte[16];
        public int CarryLen;
        // Control-stream frame walk (SETTINGS and friends are parsed-and-ignored, but must be
        // framed correctly); non-control uni streams are drained wholesale.
        public ParseState State = ParseState.FrameHeader;
        public long Remaining;
    }

    public Http3Connection(QuicConnection quicConnection, Http3Options? options = null)
    {
        _quicConnection = quicConnection;
        _options = options ?? Http3Options.Default;
    }

    /// <summary>Answer each request with a whole response from a synchronous handler, dispatched at
    /// end-of-stream with the whole body in <see cref="Http3Request.Body"/> - a handler that cannot
    /// await cannot read a body still arriving, so <see cref="Http3Options.StreamRequestBodies"/>
    /// does not apply. Owns the handler's connection ref (DecRef on exit).</summary>
    public Task RunBufferedAsync(Func<Http3Request, Http3Response> handler)
        => RunCoreAsync(() => DispatchReady(handler));

    /// <summary>Answer each request with a whole response from a handler that may await. Dispatched
    /// at end-of-stream with the whole body in <see cref="Http3Request.Body"/>, or with
    /// <see cref="Http3Options.StreamRequestBodies"/> at END-OF-HEADERS, the body pulled through
    /// <see cref="Http3Request.BodyReader"/> while the stream's flow-control window paces the peer.
    /// The handler must resume on the reactor (every ioxide await does). Owns the handler's
    /// connection ref (DecRef on exit).</summary>
    public Task RunBufferedAsync(Func<Http3Request, ValueTask<Http3Response>> handler)
    {
        _streamBodies = _options.StreamRequestBodies;
        return RunCoreAsync(() => DispatchReadyAsync(handler));
    }

    // The one serving loop. Each entry point hands it the dispatch for its response mode, run once
    // per pass.
    private async Task RunCoreAsync(Action dispatch)
    {
        _quicConnection.OnSendCapacityAvailable ??= SendPendingBodies;   // a streamed connection has its own
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
                    dispatch();
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
            _pendingBodies.Clear();

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
            if (_unis.Remove(item.StreamId, out UniStream? uni) && uni.IsCritical)
            {
                Fatal("critical stream closed", H3ClosedCriticalStream);
            }

            // A response in flight whose peer will read no more of it: its handler learns at the next
            // flush, and one parked on send capacity wakes to find that out.
            if (item.Kind is QuicStreamEvent.StopSending or QuicStreamEvent.Closed
                && _writers.TryGetValue(item.StreamId, out Http3ResponseWriter? stopped))
            {
                stopped.OnPeerGone();
                ReleaseCapacityWaiters();
            }
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
                // Empty: nothing ever to answer, so abort it rather than leave it owed (RFC 9114 4.1).
                _quicConnection.ResetStream(item.StreamId, H3RequestIncomplete);
                return;
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
        // payload, trailers, grease, a body its handler is done with) credit the flow-control window
        // immediately once the stream is paced; sink bytes credit as the handler pulls them.
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
                        if (rs.Paced)
                        {
                            immediateCredit += take;
                        }
                        data = data[take..];
                        continue;
                    }

                    int headerBytes = c1 + c2;
                    int fromData = headerBytes - rs.CarryLen;   // header bytes consumed from THIS chunk
                    rs.CarryLen = 0;
                    if (rs.Paced)
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
                        if (rs.Request.ContentLengthLeft >= 0)
                        {
                            if (len > rs.Request.ContentLengthLeft)
                            {
                                RefuseMalformed(sid, rs, "the request body runs past its content-length");
                                break;
                            }
                            rs.Request.ContentLengthLeft -= len;
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
                    if (rs.Paced)
                    {
                        immediateCredit += take;
                    }
                    data = data[take..];

                    if (rs.Remaining == 0)
                    {
                        rs.State = ParseState.FrameHeader;   // first: the decode may refuse the stream
                        OnHeadersComplete(sid, rs);
                        ArrayPool<byte>.Shared.Return(rs.HeadersBuf!);
                        rs.HeadersBuf = null;
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
                    else if (rs.Paced)
                    {
                        immediateCredit += take;   // its handler is done with the body: dropped, credit returned
                    }
                    else if (!_streamBodies)
                    {
                        rs.Request.BodyBuffer ??= new MemoryStream();
                        if (rs.Request.BodyBuffer.Length + take > _options.MaxRequestBytes)
                        {
                            Refuse(sid, rs, H3ExcessiveLoad, "the request body passed MaxRequestBytes");
                            break;
                        }
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
                    if (rs.Paced)
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

                case ParseState.Refused:
                {
                    if (rs.Paced)
                    {
                        immediateCredit += data.Length;
                    }
                    data = default;
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

            // Nothing more arrives on this stream, so nothing more needs pacing. The reader's queued
            // chunks still credit as they are read, and the shim's small fixed set of paced streams
            // gets the slot back now rather than when the response ends - which, streamed, can be
            // never: every GET is paced from its HEADERS, and its FIN rides with them.
            if (rs.Paced)
            {
                _quicConnection.SetStreamPaced(sid, false);
            }

            if (!rs.HeadersDone)
            {
                // Ended without a request (grease, say): nothing will answer it (RFC 9114 4.1).
                _requests.Remove(sid);
                ReleaseParseBuffers(rs);
                _quicConnection.ResetStream(sid, H3RequestIncomplete);
                return;
            }

            if (rs.Request.ContentLengthLeft > 0)
            {
                RefuseMalformed(sid, rs, $"the request body ended {rs.Request.ContentLengthLeft} bytes short of its content-length");
                return;
            }

            if (_streamBodies)
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

        if (rs.Request.ContentLengthLeft < -1)
        {
            RefuseMalformed(sid, rs, "the request's content-length is invalid or repeated");
            return;
        }

        if (_streamBodies && !rs.Dispatched)
        {
            rs.Dispatched = true;
            var sink = new Http3BodyReader(this, sid, ended: false);
            rs.Sink = sink;
            rs.Request.BodyReader = sink;
            _quicConnection.SetStreamPaced(sid, true);
            rs.Paced = true;
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
            us.IsCritical = type is 0x00 or 0x02 or 0x03;
            int fromData = consumed - us.CarryLen;
            us.CarryLen = 0;
            data = data[fromData..];
        }

        // RFC 9114 6.2.1 and RFC 9204 4.2.
        if (fin && us.IsCritical)
        {
            Fatal("critical stream closed", H3ClosedCriticalStream);
            return;
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

    // A streamed body is still arriving after dispatch, so its stream stays in _requests until it
    // ends; an assembled one already has, and leaves the table here as a synchronous dispatch does.
    private bool TakeReady(long sid, [NotNullWhen(true)] out ReqStream? rs)
        => _streamBodies ? _requests.TryGetValue(sid, out rs) : _requests.Remove(sid, out rs);

    private void DispatchReadyAsync(Func<Http3Request, ValueTask<Http3Response>> handler)
    {
        for (int i = 0; i < _ready.Count && !_fatal; i++)
        {
            long sid = _ready[i];
            if (!TakeReady(sid, out ReqStream? rs))
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
                RetireBody(rs);
                Submit(sid, new Http3Response { Status = 500 });
                continue;
            }

            if (pending.IsCompletedSuccessfully)
            {
                RetireBody(rs);
                Submit(sid, pending.Result);
            }
            else
            {
                _ = CompleteBufferedAsync(pending, rs);
            }
        }
        _ready.Clear();
    }

    private async Task CompleteBufferedAsync(ValueTask<Http3Response> pending, ReqStream rs)
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

        RetireBody(rs);
        if (_fatal)
        {
            return;
        }
        Submit(rs.Request.StreamId, resp);
    }

    // The handler is done with the body: credit what it left unread and let the engine credit the
    // rest - all but what is already in the ring, which FeedRequest credits as it drops it.
    private void RetireBody(ReqStream rs)
    {
        if (rs.Sink is null)
        {
            return;
        }
        rs.Sink.Drop();
        rs.Sink = null;
        if (!rs.Finished)
        {
            _quicConnection.SetStreamPaced(rs.Request.StreamId, false);
        }
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
        SendBody(streamId, resp.Body);
    }

    // A large body goes in pieces while the connection takes them, and the rest as acks free
    // retention: handed over whole, 32 one-MiB responses on one connection crossed the backstop and
    // lost the connection. A piece overshoots the high-water by at most its own size.
    private const int BodyPiece = 64 * 1024;

    private sealed class PendingBody(long streamId, ReadOnlyMemory<byte> rest)
    {
        public readonly long StreamId = streamId;
        public ReadOnlyMemory<byte> Rest = rest;
    }

    private readonly Queue<PendingBody> _pendingBodies = new();

    private void SendBody(long streamId, ReadOnlyMemory<byte> body)
    {
        if (_pendingBodies.Count == 0)
        {
            body = SendWhileCapacity(streamId, body);
            if (body.IsEmpty)
            {
                return;
            }
        }
        _pendingBodies.Enqueue(new PendingBody(streamId, body));   // after the ones already waiting
    }

    private ReadOnlyMemory<byte> SendWhileCapacity(long streamId, ReadOnlyMemory<byte> body)
    {
        while (!body.IsEmpty && _quicConnection.CanQueueSend)
        {
            int n = Math.Min(body.Length, BodyPiece);
            _quicConnection.SendStream(streamId, body.Span[..n], fin: n == body.Length);
            body = body[n..];
        }
        return body;
    }

    private void SendPendingBodies()
    {
        while (_pendingBodies.TryPeek(out PendingBody? next) && !IsBroken)
        {
            next.Rest = SendWhileCapacity(next.StreamId, next.Rest);
            if (!next.Rest.IsEmpty)
            {
                return;   // at the high-water again: the next capacity signal carries on
            }
            _pendingBodies.Dequeue();
        }
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

    // RFC 9114 4.1.2: a malformed request is a stream error, not a connection one. A handler already
    // reading the body is told by its next read; nothing else on the stream is parsed.
    private void RefuseMalformed(long sid, ReqStream rs, string reason)
        => Refuse(sid, rs, H3MessageError, reason);

    // A stream error: the stream is reset with code, and a request refused before its FIN is never
    // dispatched, so an assembled body is dropped here.
    private void Refuse(long sid, ReqStream rs, ulong code, string reason)
    {
        rs.State = ParseState.Refused;
        rs.Finished = true;
        rs.Sink?.Fail(new IOException(reason));
        rs.Request.BodyBuffer = null;
        _quicConnection.ResetStream(sid, code);

        // The reset ends a streamed response on this stream too, and its writer has to be told: a
        // send on a reset stream is dropped without ever filling the connection, so a writer that
        // is not keeps flushing into nothing and never parks.
        if (_writers.TryGetValue(sid, out Http3ResponseWriter? writer))
        {
            writer.OnPeerGone();
            ReleaseCapacityWaiters();
        }
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
