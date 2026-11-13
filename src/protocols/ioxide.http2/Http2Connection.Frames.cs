using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;

namespace ioxide.http2;

/// <summary>
/// Frame parsing. Consumes as many complete frames as the accumulator holds, leaving any partial
/// tail for the next recv.
/// </summary>
public sealed partial class Http2Connection
{
    private void ParseAvailable()
    {
        int position = 0;

        // The client preface comes before any frame and is not one.
        if (!_prefaceSeen)
        {
            if (_inboundUsed - position < FrameHeader.ClientPreface.Length)
            {
                Compact(position);
                return;
            }

            if (!_inbound.AsSpan(position, FrameHeader.ClientPreface.Length)
                    .SequenceEqual(FrameHeader.ClientPreface))
            {
                _failed = true;   // not an HTTP/2 peer; nothing to say back that it would understand
                return;
            }

            position += FrameHeader.ClientPreface.Length;
            _prefaceSeen = true;
        }

        while (!_failed)
        {
            if (!FrameHeader.TryRead(_inbound.AsSpan(position, _inboundUsed - position), out FrameHeader header))
            {
                break;   // not even a header yet
            }

            if (header.Length > _options.MaxFrameSize)
            {
                GoAway(Http2Error.FrameSizeError);
                return;
            }

            int total = FrameHeader.Size + header.Length;
            if (_inboundUsed - position < total)
            {
                break;   // header is in, payload is not
            }

            ReadOnlySpan<byte> payload = _inbound.AsSpan(position + FrameHeader.Size, header.Length);
            Handle(header, payload);
            position += total;
        }

        Compact(position);
    }

    // Drop what has been consumed and move any partial frame to the front, so the accumulator does
    // not grow without bound on a long-lived connection.
    private void Compact(int consumed)
    {
        if (consumed == 0)
        {
            return;
        }

        int remaining = _inboundUsed - consumed;
        if (remaining > 0)
        {
            _inbound.AsSpan(consumed, remaining).CopyTo(_inbound);
        }
        _inboundUsed = remaining;
    }

    private void Handle(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        // RFC 9113 6.2, 6.10: a CONTINUATION comes only inside its header block, and nothing else does.
        bool continuation = header.Type == FrameType.Continuation;
        if (continuation != (_headerBlockStream != 0)
            || (_headerBlockStream != 0 && header.StreamId != _headerBlockStream))
        {
            GoAway(Http2Error.ProtocolError);
            return;
        }
        if (continuation || header.Type == FrameType.Headers)
        {
            _headerBlockStream = (header.Flags & FrameFlags.EndHeaders) != 0 ? 0 : header.StreamId;
        }

        switch (header.Type)
        {
            case FrameType.Headers:      HandleHeaders(header, payload); break;
            case FrameType.Continuation: HandleContinuation(header, payload); break;
            case FrameType.Data:         HandleData(header, payload); break;
            case FrameType.Settings:     HandleSettings(header, payload); break;
            case FrameType.WindowUpdate: HandleWindowUpdate(header, payload); break;
            case FrameType.Ping:         HandlePing(header, payload); break;
            case FrameType.RstStream:    HandleRstStream(header); break;
            case FrameType.GoAway:       _failed = true; break;

            // PRIORITY carries no obligation, and PUSH_PROMISE cannot arrive at a server. Both are
            // ignored rather than treated as errors, which is what the RFC asks of a receiver.
            case FrameType.Priority:
            case FrameType.PushPromise:
            default:
                break;
        }
    }

    private void HandleHeaders(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (header.StreamId == 0)
        {
            GoAway(Http2Error.ProtocolError);
            return;
        }

        ReadOnlySpan<byte> block = payload;

        // Padding and priority sit in front of the header block and are not part of it.
        if ((header.Flags & FrameFlags.Padded) != 0)
        {
            if (block.Length < 1)
            {
                GoAway(Http2Error.FrameSizeError);
                return;
            }
            int padding = block[0];
            block = block[1..];
            if (padding > block.Length)
            {
                GoAway(Http2Error.ProtocolError);
                return;
            }
            block = block[..^padding];
        }

        if ((header.Flags & FrameFlags.Priority) != 0)
        {
            if (block.Length < 5)
            {
                GoAway(Http2Error.FrameSizeError);
                return;
            }
            block = block[5..];
        }

        if (!_streams.TryGetValue(header.StreamId, out PendingRequest? pending))
        {
            // An id at or below one already opened opens nothing (RFC 9113 5.1.1) - it is trailers
            // for a request already answered - so it is decoded like a refused block, but not reset.
            if (header.StreamId <= _highestStream || _streams.Count >= _options.MaxConcurrentStreams)
            {
                // Past the limit we advertised. The block still has to be DECODED - HPACK is one
                // stream across the whole connection, so skipping it would desynchronise every
                // later request - but it decodes into a scratch that is thrown away, and the peer
                // is told REFUSED_STREAM, which RFC 9113 8.7 makes safe for it to retry elsewhere.
                _discardBlock.StreamId = header.StreamId;
                DiscardHeaderBlock(header, block);
                return;
            }

            pending = RentPending(header.StreamId);
            _streams[header.StreamId] = pending;
            _highestStream = header.StreamId;
        }
        else if (pending.BodyReader is { } reader)
        {
            // Trailers for a request already being served: its arena backs what the handler holds,
            // so the block is decoded aside and dropped, and only its END_STREAM is kept.
            _discardBlock.StreamId = header.StreamId;
            DiscardHeaderBlock(header, block);
            if ((header.Flags & FrameFlags.EndStream) != 0)
            {
                if (!pending.BodyFits(ended: true))
                {
                    RefuseBody(pending);
                    return;
                }
                pending.RequestEnded = true;
                reader.End();
            }
            return;
        }
        else if ((header.Flags & FrameFlags.EndStream) == 0)
        {
            // RFC 9113 8.1: after the block that opens a request come only trailers, which end its stream.
            _discardBlock.StreamId = header.StreamId;
            DiscardHeaderBlock(header, block);
            ResetStream(header.StreamId, Http2Error.ProtocolError);
            return;
        }

        // A header block can span HEADERS + CONTINUATION frames, and HPACK cannot be decoded
        // piecewise - the whole block has to be in hand first.
        pending.HeadersDone = false;   // trailers open a block of their own, and the request waits for its END_HEADERS
        pending.AppendHeaderBlock(block);

        if (pending.HeaderBlock.Length > _options.MaxHeaderListSize)
        {
            GoAway(Http2Error.EnhanceYourCalm);
            return;
        }

        if ((header.Flags & FrameFlags.EndHeaders) != 0)
        {
            if (!DecodeHeaderBlock(pending, endsStream: (header.Flags & FrameFlags.EndStream) != 0))
            {
                return;
            }
            BeginStreamedBody(pending, ended: (header.Flags & FrameFlags.EndStream) != 0);
        }

        if ((header.Flags & FrameFlags.EndStream) != 0)
        {
            pending.RequestEnded = true;
            pending.BodyReader?.End();
            TryComplete(pending);
        }
    }

    /// <summary>
    /// A header block that opens no request - a refused stream's, or trailers: decoded to keep the
    /// HPACK table in step with the peer, and thrown away. Bounded like any other block, so refusing
    /// a stream cannot itself be the way in.
    /// </summary>
    private void DiscardHeaderBlock(in FrameHeader header, ReadOnlySpan<byte> block)
    {
        _discardBlock.AppendHeaderBlock(block);

        if (_discardBlock.HeaderBlock.Length > _options.MaxHeaderListSize)
        {
            GoAway(Http2Error.EnhanceYourCalm);
            return;
        }

        if ((header.Flags & FrameFlags.EndHeaders) == 0)
        {
            return;   // more CONTINUATION to come
        }

        int streamId = _discardBlock.StreamId;
        _discardBlock.StreamId = 0;

        // Only a new id was refused; nothing of another stream can arrive mid-block to move the
        // highest. Trailers are not reset: REFUSED_STREAM says the request went unprocessed.
        if (DecodeHeaderBlock(_discardBlock, discard: true) && streamId > _highestStream)
        {
            ResetStream(streamId, Http2Error.RefusedStream);
            _highestStream = streamId;   // refused, but used
        }
    }

    /// <summary>
    /// Hand this request over the moment its headers are in, with the body still to come. The
    /// stream stays in <c>_streams</c> - unlike the buffered path, later DATA frames still have
    /// somewhere to go - and is retired when the handler finishes instead.
    /// </summary>
    private void BeginStreamedBody(PendingRequest pending, bool ended)
    {
        if (!_streamBodies || pending.BodyReader is not null)
        {
            return;
        }

        pending.BodyReader = new Http2BodyReader(this, pending.StreamId, ended);
        _responseWindows[pending.StreamId] = pending.SendWindow;
        _ready.Enqueue(pending);
    }

    private void HandleContinuation(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (header.StreamId == _discardBlock.StreamId)
        {
            DiscardHeaderBlock(header, payload);
            return;
        }

        if (!_streams.TryGetValue(header.StreamId, out PendingRequest? pending))
        {
            GoAway(Http2Error.ProtocolError);
            return;
        }

        pending.AppendHeaderBlock(payload);

        if (pending.HeaderBlock.Length > _options.MaxHeaderListSize)
        {
            GoAway(Http2Error.EnhanceYourCalm);
            return;
        }

        if ((header.Flags & FrameFlags.EndHeaders) != 0)
        {
            // END_STREAM rode the HEADERS that opened this block, not the CONTINUATION closing it.
            if (!DecodeHeaderBlock(pending, endsStream: pending.RequestEnded))
            {
                return;
            }
            BeginStreamedBody(pending, ended: pending.RequestEnded);
            TryComplete(pending);
        }
    }

    private bool DecodeHeaderBlock(PendingRequest pending, bool endsStream = false, bool discard = false)
    {
        try
        {
            ReadOnlySpan<byte> block = pending.HeaderBlock;

            // Huffman can expand a literal well past its encoded length, so the scratch has to be
            // able to hold the worst case for the whole block.
            int needed = Huffman.MaxDecodedLength(block.Length) + block.Length;
            if (_headerScratch.Length < needed)
            {
                _headerScratch = new byte[needed];
            }

            // The request rides as state, so the sink is a static lambda and no closure is made per block.
            int limit = _options.MaxHeaderListSize;
            _decoder.Decode(block, _headerScratch, (Pending: pending, Limit: limit),
                discard ? static (_, _, _) => { } : static (state, name, value) => state.Pending.AddHeader(name, value, state.Limit));

            if (pending.HeaderListSize > limit)
            {
                ResetStream(pending.StreamId, Http2Error.EnhanceYourCalm);   // decoded whole, so HPACK is in step and only this request ends
                return false;
            }

            pending.ClearHeaderBlock();
            pending.HeadersDone = true;
            pending.ClosePseudoHeaders();

            // A block that ends the stream ends the body with it, so the DATA before it - none, for
            // the block that opens the request - has to be all the content-length declared.
            if (pending.Malformed || !pending.BodyFits(endsStream))
            {
                ResetStream(pending.StreamId, Http2Error.ProtocolError);   // decoded whole, so HPACK is in step and only this request ends
                return false;
            }
            return true;
        }
        catch (HpackDecoder.HpackException)
        {
            // The dynamic tables have diverged; every later block on this connection would decode
            // to nonsense, so the connection - not the stream - is what has to end.
            GoAway(Http2Error.CompressionError);
            return false;
        }
    }

    private void HandleData(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (header.StreamId == 0 || header.StreamId > _highestStream)
        {
            GoAway(Http2Error.ProtocolError);   // RFC 9113 6.1: DATA always belongs to a stream, and 5.1: never an idle one
            return;
        }

        ReadOnlySpan<byte> body = payload;

        if ((header.Flags & FrameFlags.Padded) != 0)
        {
            if (body.Length < 1)
            {
                GoAway(Http2Error.FrameSizeError);
                return;
            }
            int padding = body[0];
            body = body[1..];
            if (padding > body.Length)
            {
                GoAway(Http2Error.ProtocolError);
                return;
            }
            body = body[..^padding];
        }

        _streams.TryGetValue(header.StreamId, out PendingRequest? pending);

        // Counted before the payload is taken: a frame that runs past the content-length is refused at
        // once rather than at the end, so neither a handler nor the arena holds a byte of it, and an
        // END_STREAM short of it is refused where it lands.
        if (pending is not null)
        {
            pending.BodyReceived += body.Length;
            if (!pending.BodyFits(ended: (header.Flags & FrameFlags.EndStream) != 0))
            {
                RefuseBody(pending);

                // The stream is gone; the connection is still owed this frame. An empty one, a common way
                // to end a body, is owed nothing, and a WINDOW_UPDATE of 0 would end the connection.
                if (payload.Length > 0)
                {
                    WriteWindowUpdate(0, payload.Length);
                }
                return;
            }
        }

        if (pending?.BodyReader is { } reader)
        {
            reader.Push(body);
        }
        else if (pending is not null)
        {
            if (pending.BodyLength + body.Length > _options.MaxRequestBytes)
            {
                ResetStream(header.StreamId, Http2Error.EnhanceYourCalm);
                WriteWindowUpdate(0, payload.Length);   // the stream is gone; the connection is still owed this frame
                return;
            }
            pending.AppendBody(body);
        }

        // The whole payload counts against the window, padding included, so the peer's accounting
        // and ours agree. Replenished immediately here because this server buffers the request
        // anyway, so holding the window back would only stall the peer for nothing.
        //
        // A STREAMED body is the exception, and the reason to stream one at all: its credit is
        // returned as the handler reads (Http2BodyReader.ReadAsync), so a consumer that falls
        // behind stops replenishing and the peer stops sending. Crediting here as well would hand
        // the window back before the bytes were consumed and put the bound back on memory. Its
        // padding never reaches the handler, though, so that much is still credited here.
        int credit = pending?.BodyReader is null ? payload.Length : payload.Length - body.Length;
        if (credit > 0)
        {
            WriteWindowUpdate(0, credit);
            WriteWindowUpdate(header.StreamId, credit);
        }

        if ((header.Flags & FrameFlags.EndStream) != 0 && pending is not null)
        {
            pending.RequestEnded = true;
            pending.BodyReader?.End();
            TryComplete(pending);
        }
    }

    /// <summary>
    /// RFC 9113 8.1.1: a request whose DATA does not come to its content-length is malformed, a stream
    /// error of PROTOCOL_ERROR. A buffered one is refused before it is dispatched. A streamed one was
    /// handed over at its HEADERS, so its handler hears of it at its body's next read, and its response
    /// finds the stream gone as after the peer's own reset: a reset stream takes no more frames
    /// (RFC 9113 5.1), and a writer nobody told would keep sending into it.
    /// </summary>
    private void RefuseBody(PendingRequest pending)
    {
        int streamId = pending.StreamId;   // read first: the reset recycles a request no handler holds
        pending.BodyReader?.Abort(pending.BodyReceived > pending.ContentLength
            ? "the request body ran past its content-length"
            : $"the request body ended {pending.ContentLength - pending.BodyReceived} bytes short of its content-length");

        _responseWindows.Remove(streamId);
        ResetStream(streamId, Http2Error.ProtocolError);
        ReleaseCreditWaiters(streamId);   // a writer parked on credit wakes to find the stream gone
    }

    private void TryComplete(PendingRequest pending)
    {
        // A streamed request was handed over at its headers and is being served right now; its
        // stream is retired by whoever is serving it, not here.
        if (pending.BodyReader is not null)
        {
            return;
        }

        if (!pending.HeadersDone || !pending.RequestEnded)
        {
            return;
        }

        // Its window moves with it: a WINDOW_UPDATE finds a stream by _streams only until here.
        _streams.Remove(pending.StreamId);
        _responseWindows[pending.StreamId] = pending.SendWindow;
        _ready.Enqueue(pending);
    }

    private void HandleSettings(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if ((header.Flags & FrameFlags.Ack) != 0)
        {
            return;   // our own SETTINGS acknowledged
        }

        if (payload.Length % 6 != 0)
        {
            GoAway(Http2Error.FrameSizeError);
            return;
        }

        bool windowGrew = false;

        for (int offset = 0; offset + 6 <= payload.Length; offset += 6)
        {
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(payload[offset..]);
            uint value = BinaryPrimitives.ReadUInt32BigEndian(payload[(offset + 2)..]);

            switch (id)
            {
                case Http2Setting.InitialWindowSize:
                    if (value > int.MaxValue)
                    {
                        GoAway(Http2Error.FlowControlError);
                        return;
                    }
                    // Applies retroactively to every open stream, per RFC 9113 section 6.9.2.
                    int delta = (int)value - _peerInitialStreamWindow;
                    _peerInitialStreamWindow = (int)value;

                    if (_responseWindows.Count > 0)
                    {
                        foreach (int streamId in _responseWindows.Keys.ToArray())
                        {
                            _responseWindows[streamId] += delta;
                        }
                    }
                    foreach (PendingRequest stream in _streams.Values)
                    {
                        stream.SendWindow += delta;
                    }
                    windowGrew |= delta > 0;
                    break;

                case Http2Setting.MaxFrameSize:
                    if (value is < 16384 or > 16777215)
                    {
                        GoAway(Http2Error.ProtocolError);
                        return;
                    }
                    _peerMaxFrameSize = (int)value;
                    break;
            }
        }

        // A larger window is credit like a WINDOW_UPDATE, and parked writers wake on nothing else.
        // Released after the loop, so a woken writer sees every setting in this frame applied.
        if (windowGrew)
        {
            ReleaseCreditWaiters(0);
        }

        WriteSettingsAck();
    }

    private void HandleWindowUpdate(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 4)
        {
            GoAway(Http2Error.FrameSizeError);
            return;
        }

        int increment = (int)(BinaryPrimitives.ReadUInt32BigEndian(payload) & 0x7FFFFFFF);
        if (increment == 0)
        {
            GoAway(Http2Error.ProtocolError);
            return;
        }

        // RFC 9113 6.9.1: a window past 2^31-1 is the peer's error, not a sum to wrap negative.
        if (header.StreamId == 0)
        {
            if ((long)_peerConnectionWindow + increment > int.MaxValue)
            {
                GoAway(Http2Error.FlowControlError);
                return;
            }
            _peerConnectionWindow += increment;
        }
        else if (_responseWindows.TryGetValue(header.StreamId, out int window))
        {
            if ((long)window + increment > int.MaxValue)
            {
                _responseWindows.Remove(header.StreamId);   // its writer, once woken, must find the stream gone
                ResetStream(header.StreamId, Http2Error.FlowControlError);
            }
            else
            {
                _responseWindows[header.StreamId] = window + increment;
            }
        }
        else if (_streams.TryGetValue(header.StreamId, out PendingRequest? pending))
        {
            if ((long)pending.SendWindow + increment > int.MaxValue)
            {
                ResetStream(header.StreamId, Http2Error.FlowControlError);
            }
            else
            {
                pending.SendWindow += increment;
            }
        }

        // Credit arrived, so a streamed response parked on it can carry on.
        ReleaseCreditWaiters(header.StreamId);
    }

    private void HandlePing(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 8)
        {
            GoAway(Http2Error.FrameSizeError);
            return;
        }
        if ((header.Flags & FrameFlags.Ack) != 0)
        {
            return;
        }

        // Echo the opaque data back with ACK set - the peer is measuring the round trip.
        Span<byte> frame = stackalloc byte[FrameHeader.Size + 8];
        new FrameHeader(8, FrameType.Ping, FrameFlags.Ack, 0).Write(frame);
        payload.CopyTo(frame[FrameHeader.Size..]);
        Stage(frame);
    }

    private void HandleRstStream(in FrameHeader header)
    {
        if (_streams.Remove(header.StreamId, out PendingRequest? pending))
        {
            Discard(pending);   // the peer gave up; there is nobody to answer
        }

        // A response in flight may send nothing more on the stream (RFC 9113 5.1), and a writer parked
        // on its credit has to wake to learn that - the WINDOW_UPDATE it waits for will never come.
        if (_responseWindows.Remove(header.StreamId))
        {
            ReleaseCreditWaiters(header.StreamId);
        }
    }

    /// <summary>
    /// One request being assembled: the raw header block until it is complete, then decoded fields
    /// and body bytes in a pooled arena described by ranges. Reused for later streams once retired,
    /// with its request, header list and field ranges.
    /// </summary>
    private sealed class PendingRequest : IDisposable
    {
        private byte[] _arena = [];
        private int _used;
        private byte[] _block = [];
        private int _blockUsed;
        private readonly List<(int NameOffset, int NameLength, int ValueOffset, int ValueLength)> _fields = [];
        private (int Offset, int Length) _body;
        private readonly Http2Request _request = new();

        public int StreamId;
        public bool HeadersDone;
        public bool RequestEnded;

        // What this request's header blocks have decoded to so far.
        public long HeaderListSize;

        /// <summary>Set only when the body is being streamed; the arena stays empty then.</summary>
        public Http2BodyReader? BodyReader;

        /// <summary>What the peer will still accept on this stream. Starts at its advertised default.</summary>
        public int SendWindow = 65535;

        public int BodyLength => _body.Length;

        // Grew nothing a pooled request should keep: a field list past this was a peer's thousands of header lines.
        public bool IsSmall => _fields.Capacity <= 64;

        public (int Offset, int Length) Method;
        public (int Offset, int Length) Path;
        public (int Offset, int Length) Scheme;
        public (int Offset, int Length) Authority;

        // A pseudo-header out of place, or a content-length that is no number or comes twice: the
        // stream is reset once the block is decoded, never dispatched.
        public bool Malformed;

        // What the content-length says the DATA comes to, -1 without one, and what it has come to so
        // far, padding aside: RFC 9113 8.1.1 counts the body, and padding is no part of it.
        public long ContentLength = -1;
        public long BodyReceived;

        /// <summary>
        /// Whether the DATA so far can still be the body the content-length declares: never past it,
        /// and all of it once the request has <paramref name="ended"/> (RFC 9113 8.1.1).
        /// </summary>
        public bool BodyFits(bool ended)
            => ContentLength < 0 || (ended ? BodyReceived == ContentLength : BodyReceived <= ContentLength);

        // One bit for each pseudo-header seen, and one once a regular field or the end of a block closes them.
        private int _pseudoSeen;
        private const int PseudoClosed = 16;

        public ReadOnlySpan<byte> HeaderBlock => _block.AsSpan(0, _blockUsed);

        public void AppendHeaderBlock(ReadOnlySpan<byte> data)
        {
            if (_block.Length - _blockUsed < data.Length)
            {
                byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(4096, (_blockUsed + data.Length) * 2));
                _block.AsSpan(0, _blockUsed).CopyTo(grown);
                if (_block.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(_block);
                }
                _block = grown;
            }
            data.CopyTo(_block.AsSpan(_blockUsed));
            _blockUsed += data.Length;
        }

        public void ClearHeaderBlock()
        {
            if (_block.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_block);
                _block = [];
            }
            _blockUsed = 0;
        }

        public void AddHeader(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, int limit)
        {
            HeaderListSize += name.Length + value.Length + 32;   // RFC 9113 6.5.2's measure
            if (HeaderListSize > limit)
            {
                return;   // the stream is reset once the block is decoded, so there is nothing to keep it for
            }

            if (name.Length > 0 && name[0] == (byte)':')
            {
                if (name.SequenceEqual(":method"u8))         Method = Pseudo(1, value);
                else if (name.SequenceEqual(":path"u8))      Path = Pseudo(2, value);
                else if (name.SequenceEqual(":scheme"u8))    Scheme = Pseudo(4, value);
                else if (name.SequenceEqual(":authority"u8)) Authority = Pseudo(8, value);
                else Malformed = true;
                return;
            }

            ClosePseudoHeaders();
            (int Offset, int Length) nameRange = Append(name);
            (int Offset, int Length) valueRange = Append(value);
            _fields.Add((nameRange.Offset, nameRange.Length, valueRange.Offset, valueRange.Length));

            if (name.SequenceEqual("content-length"u8))
            {
                // Digits only (RFC 9110 8.6), each byte checked since TryParse lets a trailing NUL through,
                // and once: two that disagree leave whoever reads the request to pick a length, and a
                // repeat is refused even when the values agree, as nghttp2 refuses it.
                if (ContentLength >= 0
                    || value.IndexOfAnyExceptInRange((byte)'0', (byte)'9') >= 0
                    || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long length))
                {
                    Malformed = true;
                }
                else
                {
                    ContentLength = length;
                }
            }
        }

        // RFC 9113 8.3: each at most once and ahead of every regular field; 8.1: none in trailers.
        private (int Offset, int Length) Pseudo(int seen, ReadOnlySpan<byte> value)
        {
            Malformed |= (_pseudoSeen & (seen | PseudoClosed)) != 0;
            _pseudoSeen |= seen;
            return Append(value);
        }

        public void ClosePseudoHeaders() => _pseudoSeen |= PseudoClosed;

        public void AppendBody(ReadOnlySpan<byte> data)
        {
            (int Offset, int Length) range = Append(data);
            if (_body.Length == 0)
            {
                _body = range;
            }
            else
            {
                _body.Length += range.Length;
            }
        }

        private (int Offset, int Length) Append(ReadOnlySpan<byte> data)
        {
            if (_arena.Length - _used < data.Length)
            {
                long size = Math.Max(4096, (long)_arena.Length * 2);
                while (size < (long)_used + data.Length)
                {
                    size *= 2;
                }
                byte[] grown = ArrayPool<byte>.Shared.Rent((int)Math.Min(size, Array.MaxLength));
                _arena.AsSpan(0, _used).CopyTo(grown);
                if (_arena.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(_arena);
                }
                _arena = grown;
            }

            data.CopyTo(_arena.AsSpan(_used));
            (int Offset, int Length) range = (_used, data.Length);
            _used += data.Length;
            return range;
        }

        public Http2Request Freeze()
        {
            Http2Request request = _request;
            request.StreamId   = StreamId;
            request.Method     = Slice(Method);
            request.Path       = Slice(Path);
            request.Scheme     = Slice(Scheme);
            request.Authority  = Slice(Authority);
            request.Body       = Slice(_body);
            request.BodyReader = BodyReader;

            foreach ((int nameOffset, int nameLength, int valueOffset, int valueLength) in _fields)
            {
                request.Headers.Add(_arena.AsMemory(nameOffset, nameLength),
                                    _arena.AsMemory(valueOffset, valueLength));
            }

            return request;
        }

        private ReadOnlyMemory<byte> Slice((int Offset, int Length) range)
            => range.Length == 0 ? default : _arena.AsMemory(range.Offset, range.Length);

        /// <summary>
        /// The stream is gone - reset, or its connection with it. A streamed request's handler may
        /// still be running on the arena and the chunk it holds, so only its body ends here; its
        /// retire disposes the rest.
        /// </summary>
        public void Abort()
        {
            if (BodyReader is { } reader)
            {
                reader.Abort();
            }
            else
            {
                Dispose();
            }
        }

        public void Dispose()
        {
            // Never under a running handler (see Abort), so the chunk it held goes back too.
            BodyReader?.Drop();
            BodyReader = null;

            Malformed = false;
            _pseudoSeen = 0;
            ContentLength = -1;
            BodyReceived = 0;
            ClearHeaderBlock();
            _fields.Clear();
            HeaderListSize = 0;
            if (_arena.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_arena);
                _arena = [];
            }
            _used = 0;

            // Its request still points into the arena that just went back, which the pool must not pin.
            _request.Headers.Clear();
            _request.Method = _request.Path = _request.Scheme = _request.Authority = _request.Body = default;
            _request.BodyReader = null;

            StreamId = 0;
            HeadersDone = false;
            RequestEnded = false;
            SendWindow = 65535;
            Method = Path = Scheme = Authority = _body = default;
        }
    }
}
