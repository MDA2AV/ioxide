using System.Buffers;
using System.Buffers.Binary;

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
            if (_streams.Count >= _options.MaxConcurrentStreams)
            {
                // Past the limit we advertised. The block still has to be DECODED - HPACK is one
                // stream across the whole connection, so skipping it would desynchronise every
                // later request - but it decodes into a scratch that is thrown away, and the peer
                // is told REFUSED_STREAM, which RFC 9113 8.7 makes safe for it to retry elsewhere.
                _discardingStream = header.StreamId;
                DiscardHeaderBlock(header, block);
                return;
            }

            // Opens at what the peer's SETTINGS advertised, not at the RFC default. Streams are
            // created long after those SETTINGS arrive, so starting at 65535 and waiting for a
            // WINDOW_UPDATE means waiting for one the peer has no reason to send - it believes we
            // still have its whole window. That stalls any response longer than 65535 bytes.
            pending = new PendingRequest
            {
                Owner = this,
                StreamId = header.StreamId,
                SendWindow = _peerInitialStreamWindow,
            };
            _streams[header.StreamId] = pending;
        }

        // A header block can span HEADERS + CONTINUATION frames, and HPACK cannot be decoded
        // piecewise - the whole block has to be in hand first.
        pending.AppendHeaderBlock(block);

        if (pending.HeaderBlock.Length > _options.MaxHeaderListSize)
        {
            GoAway(Http2Error.EnhanceYourCalm);
            return;
        }

        if ((header.Flags & FrameFlags.EndHeaders) != 0)
        {
            if (!DecodeHeaderBlock(pending))
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
    /// A refused stream's header block: decoded to keep the HPACK table in step with the peer, and
    /// thrown away. Bounded like any other block, so refusing a stream cannot itself be the way in.
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

        int streamId = _discardingStream;
        _discardingStream = 0;

        if (DecodeHeaderBlock(_discardBlock, discard: true))
        {
            ResetStream(streamId, Http2Error.RefusedStream);
        }
    }

    /// <summary>
    /// Hand this request over the moment its headers are in, with the body still to come. The
    /// stream stays in <c>_streams</c> - unlike the buffered path, later DATA frames still have
    /// somewhere to go - and is retired when the handler finishes instead.
    /// </summary>
    private void BeginStreamedBody(PendingRequest pending, bool ended)
    {
        if (!_options.StreamRequestBodies || pending.BodyReader is not null)
        {
            return;
        }

        pending.BodyReader = new Http2BodyReader(this, pending.StreamId, ended);
        _ready.Add(pending);
    }

    private void HandleContinuation(in FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (header.StreamId == _discardingStream)
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
            if (!DecodeHeaderBlock(pending))
            {
                return;
            }
            // END_STREAM rode the HEADERS that opened this block, not the CONTINUATION closing it.
            BeginStreamedBody(pending, ended: pending.RequestEnded);
            TryComplete(pending);
        }
    }

    private bool DecodeHeaderBlock(PendingRequest pending, bool discard = false)
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

            PendingRequest target = pending;
            _decoder.Decode(block, _headerScratch,
                discard ? static (_, _) => { } : (name, value) => target.AddHeader(name, value));
            pending.ClearHeaderBlock();
            pending.HeadersDone = true;
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

        if (pending?.BodyReader is { } reader)
        {
            reader.Push(body);
        }
        else if (pending is not null)
        {
            if (pending.BodyLength + body.Length > _options.MaxRequestBytes)
            {
                ResetStream(header.StreamId, Http2Error.EnhanceYourCalm);
                return;
            }
            pending.AppendBody(body);
        }

        // The whole payload counts against the window, padding included, so the peer's accounting
        // and ours agree. Replenished immediately here because this server buffers the request
        // anyway, so holding the window back would only stall the peer for nothing.
        //
        // A STREAMED body is the exception, and the reason the option exists: its credit is
        // returned as the handler reads (Http2BodyReader.ReadAsync), so a consumer that falls
        // behind stops replenishing and the peer stops sending. Crediting here as well would hand
        // the window back before the bytes were consumed and put the bound back on memory.
        if (payload.Length > 0 && pending?.BodyReader is null)
        {
            WriteWindowUpdate(0, payload.Length);
            if (header.StreamId != 0)
            {
                WriteWindowUpdate(header.StreamId, payload.Length);
            }
        }

        if ((header.Flags & FrameFlags.EndStream) != 0 && pending is not null)
        {
            pending.RequestEnded = true;
            pending.BodyReader?.End();
            TryComplete(pending);
        }
    }

    private void TryComplete(PendingRequest pending)
    {
        if (pending.HeadersDone && pending.RequestEnded)
        {
            Owe(pending);
        }

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

        _streams.Remove(pending.StreamId);
        _ready.Add(pending);
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

        if (header.StreamId == 0)
        {
            _peerConnectionWindow += increment;
        }
        else if (_responseWindows.TryGetValue(header.StreamId, out int window))
        {
            _responseWindows[header.StreamId] = window + increment;
        }
        else if (_streams.TryGetValue(header.StreamId, out PendingRequest? pending))
        {
            pending.SendWindow += increment;
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
            pending.Dispose();   // the peer gave up; there is nobody to answer
        }
    }

    /// <summary>
    /// One request being assembled: the raw header block until it is complete, then decoded fields
    /// and body bytes in a pooled arena described by ranges.
    /// </summary>
    private sealed class PendingRequest : IDisposable
    {
        private byte[] _arena = [];
        private int _used;
        private byte[] _block = [];
        private int _blockUsed;
        private readonly List<(int NameOffset, int NameLength, int ValueOffset, int ValueLength)> _fields = [];
        private (int Offset, int Length) _body;

        public int StreamId;
        public bool HeadersDone;
        public bool RequestEnded;

        public Http2Connection? Owner;   // null for the discard block, which is never owed
        public bool Owed;

        /// <summary>Set only when the body is being streamed; the arena stays empty then.</summary>
        public Http2BodyReader? BodyReader;

        /// <summary>What the peer will still accept on this stream. Starts at its advertised default.</summary>
        public int SendWindow = 65535;

        public int BodyLength => _body.Length;

        public (int Offset, int Length) Method;
        public (int Offset, int Length) Path;
        public (int Offset, int Length) Scheme;
        public (int Offset, int Length) Authority;

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

        public void AddHeader(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
        {
            if (name.Length > 0 && name[0] == (byte)':')
            {
                (int Offset, int Length) pseudo = Append(value);
                if (name.SequenceEqual(":method"u8))         Method = pseudo;
                else if (name.SequenceEqual(":path"u8))      Path = pseudo;
                else if (name.SequenceEqual(":scheme"u8))    Scheme = pseudo;
                else if (name.SequenceEqual(":authority"u8)) Authority = pseudo;
                return;
            }

            (int Offset, int Length) nameRange = Append(name);
            (int Offset, int Length) valueRange = Append(value);
            _fields.Add((nameRange.Offset, nameRange.Length, valueRange.Offset, valueRange.Length));
        }

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
            var request = new Http2Request
            {
                StreamId   = StreamId,
                Method     = Slice(Method),
                Path       = Slice(Path),
                Scheme     = Slice(Scheme),
                Authority  = Slice(Authority),
                Body       = Slice(_body),
                BodyReader = BodyReader,
            };

            foreach ((int nameOffset, int nameLength, int valueOffset, int valueLength) in _fields)
            {
                request.Headers.Add(_arena.AsMemory(nameOffset, nameLength),
                                    _arena.AsMemory(valueOffset, valueLength));
            }

            return request;
        }

        private ReadOnlyMemory<byte> Slice((int Offset, int Length) range)
            => range.Length == 0 ? default : _arena.AsMemory(range.Offset, range.Length);

        public void Dispose()
        {
            Owner?.Settle(this);

            // Recycles any chunk still queued and wakes a handler parked on a body that will
            // never finish arriving.
            BodyReader?.Drop();
            BodyReader = null;

            ClearHeaderBlock();
            _fields.Clear();
            if (_arena.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_arena);
                _arena = [];
            }
            _used = 0;
        }
    }
}
