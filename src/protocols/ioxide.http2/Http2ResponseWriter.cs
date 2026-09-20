using System.Buffers;

namespace ioxide.http2;

/// <summary>
/// The write half of a STREAMED response: the handler pushes body bytes as it produces them and
/// each flush becomes a DATA frame, instead of the whole body being handed over at once.
///
/// It is an <see cref="IBufferWriter{T}"/> on purpose - that is the shape a serializer, a file
/// copy or a framework's response sink already writes into, so streaming through it needs no
/// adapter.
///
/// The difference from the HTTP/3 writer is flow control. QUIC gives each stream its own
/// transport-level credit; HTTP/2 multiplexes every stream onto one TCP connection and tracks
/// TWO windows - one per stream, one for the connection - so a flush can be blocked by either.
/// <see cref="FlushAsync"/> waits for a WINDOW_UPDATE rather than failing, which is what makes a
/// response longer than the peer's window possible at all. The buffered path resets the stream
/// instead, because a whole body was always in hand and running out of credit could only mean the
/// peer had stopped reading entirely.
/// </summary>
/// <remarks>Reactor thread only, like everything else on the connection.</remarks>
public sealed class Http2ResponseWriter : IBufferWriter<byte>
{
    private const int DefaultChunk = 16 * 1024;

    private readonly Http2Connection _connection;
    private int _streamId;

    private byte[] _staging = [];
    private int _staged;

    // Bytes THIS response has staged since its last real flush. Inside a pass a writer normally
    // rides the pass flush, but past Http2Connection.CoalesceLimit it flushes for real anyway.
    private int _sinceRealFlush;

    private bool _headersSent;
    private bool _completed;

    internal Http2ResponseWriter(Http2Connection connection, int streamId)
    {
        _connection = connection;
        _streamId = streamId;
    }

    /// <summary>The stream this response belongs to.</summary>
    public int StreamId => _streamId;

    /// <summary>True once the body has been finished and END_STREAM sent.</summary>
    public bool IsCompleted => _completed;

    /// <summary>
    /// Send the response headers. Exactly once, before any body byte - HTTP/2 puts HEADERS ahead
    /// of DATA and there is no correcting it later.
    ///
    /// No content-length is written: a streamed response does not know its length yet, and an
    /// endless one never will. HTTP/2 needs none - each DATA frame carries its own, and
    /// END_STREAM marks the end.
    /// </summary>
    public void WriteHeaders(Http2Response response)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (_headersSent)
        {
            throw new InvalidOperationException("Response headers have already been written for this stream.");
        }
        if (!response.Body.IsEmpty)
        {
            throw new ArgumentException(
                "A streamed response carries its body through the writer; leave Response.Body empty.",
                nameof(response));
        }

        _headersSent = true;
        _connection.SendStreamedHeaders(_streamId, response);
    }

    /// <inheritdoc />
    public Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureStaging(sizeHint <= 0 ? 1 : sizeHint);
        return _staging.AsSpan(_staged);
    }

    /// <inheritdoc />
    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        EnsureStaging(sizeHint <= 0 ? 1 : sizeHint);
        return _staging.AsMemory(_staged);
    }

    /// <inheritdoc />
    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (_staged + count > _staging.Length)
        {
            throw new InvalidOperationException("Advanced past the end of the span handed out by GetSpan.");
        }
        _staged += count;
    }

    /// <summary>
    /// Send everything staged so far as DATA frames, waiting on flow-control credit as needed.
    /// That wait is the backpressure: a peer that stops reading stops the producer rather than
    /// growing a queue behind it.
    /// </summary>
    public ValueTask FlushAsync() => FlushCore(endStream: false);

    /// <summary>
    /// Send what is left and mark END_STREAM. A handler that returns without calling this gets it
    /// called for it - the peer is owed an end either way.
    /// </summary>
    public async ValueTask CompleteAsync()
    {
        if (_completed)
        {
            return;
        }

        if (!_headersSent)
        {
            WriteHeaders(new Http2Response { Status = 500 });
        }

        await FlushCore(endStream: true);
        _completed = true;

        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
            _staging = [];
        }
    }

    private async ValueTask FlushCore(bool endStream)
    {
        if (!_headersSent)
        {
            throw new InvalidOperationException("Write the response headers before flushing a body chunk.");
        }

        int sent = 0;
        while (sent < _staged)
        {
            // Bounded by the frame size AND by both windows: exceeding either is a connection
            // error the peer would be right to hang up over.
            int credit = _connection.SendCredit(_streamId);
            if (credit <= 0)
            {
                if (_connection.IsBroken)
                {
                    return;
                }

                // Take the wait BEFORE flushing. The flush below is an await, and the WINDOW_UPDATE
                // it exists to provoke can arrive while this writer is still inside it - at which
                // point a release has no waiter to find, is dropped, and the writer then parks on a
                // message that has already been and gone. Registering first means that credit
                // completes this task instead, and the await below returns at once.
                Task credited = _connection.WaitForSendCreditAsync(_streamId);

                // Everything staged so far has to REACH the peer before waiting on it to open the
                // window. WINDOW_UPDATE is what a peer sends once it has consumed DATA, so parking
                // with those bytes still in the connection's buffer waits for a message that the
                // wait itself prevents - and any body larger than the initial 65535-byte window
                // deadlocks until the client times out. The flush is unconditional because inside a
                // pass the pass flush would otherwise carry them, and this stream is about to stop
                // making progress rather than return to it.
                _sinceRealFlush = 0;
                await _connection.FlushOutboundAsync();

                await credited;
                continue;
            }

            int chunk = Math.Min(credit, _staged - sent);
            bool last = endStream && sent + chunk == _staged;

            _connection.SendStreamedData(_streamId, _staging.AsSpan(sent, chunk), last);
            sent += chunk;
        }

        _staged = 0;
        _sinceRealFlush += sent;

        if (endStream && sent == 0)
        {
            // Nothing left to send, but the stream still needs its end.
            _connection.SendStreamedData(_streamId, ReadOnlySpan<byte>.Empty, endStream: true);
        }

        // Inside a pass the pass flush carries these frames with every other response's, so the
        // writer stays out of the way - unless this one response has already staged past the
        // limit, where it must write for real to yield. Outside a pass the flush is always real.
        if (_connection.InDispatchPass && _sinceRealFlush < Http2Connection.CoalesceLimit)
        {
            return;
        }

        _sinceRealFlush = 0;
        await _connection.FlushOutboundAsync();
    }

    private void EnsureStaging(int sizeHint)
    {
        int needed = _staged + sizeHint;
        if (_staging.Length >= needed)
        {
            return;
        }

        byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(needed, DefaultChunk));
        if (_staged > 0)
        {
            _staging.AsSpan(0, _staged).CopyTo(grown);
        }
        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
        }
        _staging = grown;
    }

    /// <summary>Take this writer for another stream, keeping its buffer.</summary>
    internal void Reset(int streamId)
    {
        _streamId = streamId;
        _staged = 0;
        _sinceRealFlush = 0;
        _headersSent = false;
        _completed = false;
    }
}
