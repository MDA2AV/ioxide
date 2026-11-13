using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;

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
/// response longer than the peer's window possible at all. The buffered path hands whatever its
/// windows cannot take yet to one of these, so it waits the same way.
/// </summary>
/// <remarks>One caller at a time, on any thread: what reaches the connection runs on its reactor.</remarks>
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

    // Headers written off the reactor, staged by the next flush or the completion, which run on it.
    private Http2Response? _unsent;

    // The names and values of _unsent: the caller's memories are its own again once WriteHeaders returns.
    private byte[] _unsentFields = [];

    // What a flush waits on while its bytes are queued behind the write pump's flush in flight.
    private readonly TurnWaiter _turn = new();

    internal Http2ResponseWriter(Http2Connection connection, int streamId)
    {
        _connection = connection;
        _streamId = streamId;
    }

    /// <summary>The stream this response belongs to.</summary>
    public int StreamId => _streamId;

    /// <summary>True once the response has ended: its body finished and END_STREAM sent, or its stream reset by <see cref="AbortAsync"/>.</summary>
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
        if (_connection.OffReactor)
        {
            _unsent = Copy(response);
            return;
        }
        SendHeaders(response);
    }

    private void SendHeaders(Http2Response response)
    {
        if (_connection.IsResponseLive(_streamId))
        {
            _connection.SendStreamedHeaders(_streamId, response);
        }
    }

    // Sent later, so kept in memory of our own: the caller's may be pooled or static.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private Http2Response Copy(Http2Response response)
    {
        int length = 0;
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in response.Headers.AsSpan())
        {
            length += field.Key.Length + field.Value.Length;
        }
        if (_unsentFields.Length < length)
        {
            _unsentFields = new byte[length];
        }

        var copy = new Http2Response { Status = response.Status };
        int used = 0;
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in response.Headers.AsSpan())
        {
            copy.Headers.Add(Keep(field.Key.Span, ref used), Keep(field.Value.Span, ref used));
        }
        return copy;
    }

    private ReadOnlyMemory<byte> Keep(ReadOnlySpan<byte> bytes, ref int used)
    {
        ReadOnlyMemory<byte> kept = _unsentFields.AsMemory(used, bytes.Length);
        bytes.CopyTo(_unsentFields.AsSpan(used));
        used += bytes.Length;
        return kept;
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
    /// <returns>
    /// <see cref="FlushResult.IsCompleted"/> once the peer has reset the stream or the connection is
    /// gone, as a TCP pipe writer reports a closed peer: nothing written from then on reaches anyone.
    /// </returns>
    /// <remarks>Each call has to complete before the next one is made.</remarks>
    public ValueTask<FlushResult> FlushAsync() => FlushCore(endStream: false);

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

    /// <summary>
    /// End the response with RST_STREAM instead of END_STREAM, for a handler that cannot finish it:
    /// an upstream that dropped, a read that failed. A streamed response carries no content-length,
    /// so completing it would pass the truncated body off as whole; reset, the peer knows it failed.
    /// What is staged is dropped, and so are headers not sent yet.
    /// </summary>
    /// <param name="errorCode">
    /// The RFC 9113 section 7 code the peer is told: INTERNAL_ERROR (0x2) unless another is given,
    /// such as CANCEL (0x8) for a response that is no longer wanted rather than one that failed.
    /// </param>
    /// <remarks>
    /// Once the response has completed, the peer has reset the stream or the connection is gone, it
    /// sends nothing. Either way the response has ended: <see cref="IsCompleted"/> is true,
    /// <see cref="FlushAsync"/> reports the peer gone, and nothing more is sent when the handler
    /// returns. The request body ends with the stream: a read on it, parked or still to come, raises
    /// as for a body cut off. Before the headers it resets the stream too; a handler that wants a
    /// 500 writes one. Like <see cref="FlushAsync"/>, it may be called from any thread and runs on
    /// the connection's reactor, once the call before it has completed.
    /// </remarks>
    public async ValueTask AbortAsync(uint errorCode = Http2Error.InternalError)
    {
        if (_completed)
        {
            return;
        }

        await new ReactorSwitch(_connection.Reactor);

        _completed = true;
        _unsent = null;
        _staged = 0;
        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
            _staging = [];
        }

        // Not in answer to the peer's own reset (RFC 9113 5.4.2), and not on a connection that is gone.
        if (!_connection.IsResponseLive(_streamId))
        {
            return;
        }

        try
        {
            await _connection.ResetStreamedAsync(_streamId, errorCode, _turn);
        }
        catch
        {
            // The transport refused the write, which has marked the connection broken: the peer
            // loses the stream with it, and the read loop sees it.
        }
    }

    /// <summary>
    /// End a response its handler failed to finish. Before the headers a 500 is still an honest
    /// answer; after them only RST_STREAM is - END_STREAM would pass a truncated body off as whole.
    /// </summary>
    internal ValueTask FailAsync()
        => _completed || !_headersSent ? CompleteAsync() : AbortAsync(Http2Error.InternalError);

    private static readonly FlushResult PeerGone = new(isCanceled: false, isCompleted: true);

    // Not async on the reactor: a flush that only waits for the pump's turn returns that wait, on this writer's waiter.
    private ValueTask<FlushResult> FlushCore(bool endStream)
    {
        var onReactor = new ReactorSwitch(_connection.Reactor);
        if (!_headersSent || !onReactor.IsCompleted)
        {
            return FlushCoreAsync(endStream);
        }

        try
        {
            onReactor.GetResult();   // throws once the reactor has stopped, as awaiting it does
            SendUnsentHeaders();
            return Send(endStream);
        }
        catch (Exception exception)
        {
            return ValueTask.FromException<FlushResult>(exception);   // through the task, as an async method would
        }
    }

    private async ValueTask<FlushResult> FlushCoreAsync(bool endStream)
    {
        if (!_headersSent)
        {
            throw new InvalidOperationException("Write the response headers before flushing a body chunk.");
        }

        await new ReactorSwitch(_connection.Reactor);

        SendUnsentHeaders();
        return await Send(endStream);
    }

    private void SendUnsentHeaders()
    {
        if (_unsent is Http2Response unsent)
        {
            _unsent = null;
            SendHeaders(unsent);
        }
    }

    private enum Progress : byte { Sent, Stalled, Gone }

    private ValueTask<FlushResult> Send(bool endStream)
    {
        int sent = 0;
        return SendStaged(endStream, ref sent) switch
        {
            Progress.Sent => Finish(endStream, sent),
            Progress.Stalled => SendAfterCreditAsync(endStream, sent),
            _ => new ValueTask<FlushResult>(PeerGone),
        };
    }

    // Everything staged from `sent` on, as far as credit allows.
    private Progress SendStaged(bool endStream, ref int sent)
    {
        while (sent < _staged)
        {
            // Bounded by the frame size AND by both windows: exceeding either is a connection
            // error the peer would be right to hang up over.
            int credit = _connection.SendCredit(_streamId);
            if (credit < 0)
            {
                _staged = 0;   // reset by the peer, or the connection is gone: nobody to send it to
                return Progress.Gone;
            }
            if (credit == 0)
            {
                return Progress.Stalled;
            }

            int chunk = Math.Min(credit, _staged - sent);
            bool last = endStream && sent + chunk == _staged;

            _connection.SendStreamedData(_streamId, _staging.AsSpan(sent, chunk), last);
            sent += chunk;
        }
        return Progress.Sent;
    }

    // The staged bytes are out: the stream's end if it is owed one, then the flush.
    private ValueTask<FlushResult> Finish(bool endStream, int sent)
    {
        _staged = 0;
        _sinceRealFlush += sent;

        // Sending proved the stream live; with nothing sent it still has to be asked.
        if (sent == 0 && !_connection.IsResponseLive(_streamId))
        {
            return new ValueTask<FlushResult>(PeerGone);
        }

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
            return default;
        }

        _sinceRealFlush = 0;
        return _connection.FlushOutboundAsync(_turn);
    }

    // Out of credit: one loop, so one async frame, however many times the peer opens the window by a byte.
    private async ValueTask<FlushResult> SendAfterCreditAsync(bool endStream, int sent)
    {
        while (true)
        {
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
            if ((await _connection.FlushOutboundAsync(_turn)).IsCompleted)
            {
                _staged = 0;   // the write side is gone, so no credit is coming either
                return PeerGone;
            }

            await credited;

            Progress progress = SendStaged(endStream, ref sent);
            if (progress == Progress.Gone)
            {
                return PeerGone;
            }
            if (progress == Progress.Sent)
            {
                return await Finish(endStream, sent);
            }
        }
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

    /// <summary>Carry on a buffered response whose headers are already out, for the body its windows could not take.</summary>
    internal void ContinueBody() => _headersSent = true;

    /// <summary>Take this writer for another stream, keeping its buffer.</summary>
    internal void Reset(int streamId)
    {
        _streamId = streamId;
        _staged = 0;
        _sinceRealFlush = 0;
        _headersSent = false;
        _completed = false;
        _unsent = null;
    }
}
