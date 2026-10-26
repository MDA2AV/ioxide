using System.Buffers;
using System.IO.Pipelines;
using System.Threading.Tasks.Sources;

namespace ioxide.nghttp2;

/// <summary>
/// Push surface for a streamed response body: the handler writes chunks as it produces them and
/// each flush hands them to nghttp2, which frames them as DATA.
///
/// It reads as a push and is a PULL underneath. nghttp2 owns the framing, so it asks for body bytes
/// when it is ready rather than accepting them when you have them; its read callback defers while
/// nothing is buffered, and every write resumes the stream.
///
/// The practical consequence: a flush here means "handed over", not "on the wire". nghttp2 decides
/// frame boundaries and when to emit, and the connection's drain is what puts bytes on the socket. A
/// flush waits only once nghttp2 holds more than 64 KiB of the stream it has not framed, so a writer
/// runs no further ahead of its peer than that.
/// </summary>
/// <remarks>
/// Reactor thread only, one writer per stream. <see cref="WriteHeaders"/> must come first and only
/// once; the connection completes the writer when the handler returns.
/// </remarks>
public sealed class Nghttp2ResponseWriter : IBufferWriter<byte>, IValueTaskSource
{
    private readonly Nghttp2Connection _connection;

    private byte[] _staging = [];
    private int _staged;

    private bool _headersSent;
    private bool _completed;
    private bool _gone;   // the peer reset the stream; nghttp2 has forgotten it

    // At least what nghttp2 holds of this stream unframed: grows by every chunk handed over, and is checked against
    // nghttp2 only once it passes MaxUnframed, so a flush of a few small chunks makes no extra native call.
    private long _unframedBound;

    // What FlushAsync waits on while nghttp2 has not caught up with this stream.
    private ManualResetValueTaskSourceCore<bool> _caughtUp = new()
    {
        RunContinuationsAsynchronously = false,
    };

    internal Nghttp2ResponseWriter(Nghttp2Connection connection, int streamId)
    {
        _connection = connection;
        StreamId = streamId;
    }

    public int StreamId { get; private set; }

    /// <summary>
    /// Send the status and headers. No content-length is implied: a streamed body has no length
    /// known up front, and for an endless one there never will be - END_STREAM marks the end.
    /// </summary>
    public void WriteHeaders(Nghttp2Response response)
    {
        if (_headersSent)
        {
            throw new InvalidOperationException("Headers have already been sent on this stream.");
        }

        _headersSent = true;
        if (!_gone)
        {
            _connection.SendStreamedHeaders(StreamId, response);
        }
    }

    // --- IBufferWriter<byte> ---------------------------------------------------------------

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        EnsureStaging(sizeHint);
        return _staging.AsMemory(_staged);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureStaging(sizeHint);
        return _staging.AsSpan(_staged);
    }

    public void Advance(int count) => _staged += count;

    /// <summary>
    /// Hand everything staged to nghttp2 and let the connection drain, waiting if nghttp2 has fallen behind.
    /// </summary>
    /// <remarks>
    /// Headers are sent for you if the handler never called <see cref="WriteHeaders"/>, because a
    /// body cannot precede them and a 200 is what the buffered path would have sent.
    /// </remarks>
    /// <returns>
    /// <see cref="FlushResult.IsCompleted"/> once the peer has reset the stream or the connection is
    /// gone, as a TCP pipe writer reports a closed peer: nothing written from then on reaches anyone.
    /// </returns>
    public async ValueTask<FlushResult> FlushAsync()
    {
        if (!_headersSent)
        {
            WriteHeaders(new Nghttp2Response { Status = 200 });
        }

        HandOverStaged();

        if (_gone || _connection.IsBroken)
        {
            return PeerGone;
        }

        await _connection.FlushStreamedAsync();

        // nghttp2 has fallen behind: another stream's drain holds the session, or the peer's window is shut. A
        // loop that went on regardless would never give its reactor back, and nghttp2 would buffer without bound (#409).
        if (!_gone && _unframedBound > Nghttp2Connection.MaxUnframed)
        {
            _unframedBound = _connection.Unframed(StreamId);
            if (_unframedBound > Nghttp2Connection.MaxUnframed)
            {
                _caughtUp.Reset();
                _connection.ParkWriter(this);
                await new ValueTask(this, _caughtUp.Version);
                _unframedBound = Nghttp2Connection.MaxUnframed;   // the most a wake lets through
            }
        }

        return _gone || _connection.IsBroken ? PeerGone : default;
    }

    private static readonly FlushResult PeerGone = new(isCanceled: false, isCompleted: true);

    private void HandOverStaged()
    {
        if (_staged > 0 && !_gone)
        {
            _unframedBound += _staged;
            if (!_connection.SendStreamedData(StreamId, _staging.AsSpan(0, _staged)))
            {
                _gone = true;
            }
        }
        _staged = 0;
    }

    /// <summary>The peer reset this stream: from here on nothing is sent on it.</summary>
    internal void OnPeerReset() => _gone = true;

    internal bool Gone => _gone;

    /// <summary>A drain caught nghttp2 up with this stream, or the stream or its connection ended.</summary>
    internal void WakeParked() => _caughtUp.SetResult(true);

    /// <summary>End the response: whatever is staged goes out, then END_STREAM. Idempotent.</summary>
    internal async ValueTask CompleteAsync()
    {
        if (_completed)
        {
            return;
        }
        _completed = true;

        // A handler that returned without writing anything still owes the peer a response, and a
        // stream left open is one the peer waits on until it gives up.
        if (!_headersSent)
        {
            WriteHeaders(new Nghttp2Response { Status = 200 });
        }

        HandOverStaged();
        if (_gone)
        {
            return;   // reset by the peer: there is no end left to send
        }

        _connection.EndStreamedBody(StreamId);
        await _connection.FlushStreamedAsync();
    }

    /// <summary>
    /// End a response its handler failed to finish. Before the headers that is a 500 - not the 200
    /// a handler that merely wrote nothing gets; after them only RST_STREAM is honest, since
    /// END_STREAM would pass a truncated body off as whole.
    /// </summary>
    internal async ValueTask FailAsync()
    {
        if (_completed)
        {
            return;
        }

        if (!_headersSent)
        {
            WriteHeaders(new Nghttp2Response { Status = 500 });
            await CompleteAsync();
            return;
        }

        _completed = true;
        _staged = 0;
        if (_gone)
        {
            return;   // never in answer to the peer's own reset (RFC 9113 5.4.2)
        }
        _connection.ResetStreamed(StreamId);
        await _connection.FlushStreamedAsync();
    }

    private void EnsureStaging(int sizeHint)
    {
        int needed = _staged + Math.Max(sizeHint, 1);
        if (_staging.Length >= needed)
        {
            return;
        }

        int size = Math.Max(needed, Math.Max(4096, _staging.Length * 2));
        byte[] grown = ArrayPool<byte>.Shared.Rent(size);
        _staging.AsSpan(0, _staged).CopyTo(grown);
        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
        }
        _staging = grown;
    }

    internal void Reset(int streamId)
    {
        StreamId = streamId;
        _staged = 0;
        _unframedBound = 0;
        _headersSent = false;
        _completed = false;
        _gone = false;
    }

    internal void Release()
    {
        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
            _staging = [];
        }
        _staged = 0;
    }

    void IValueTaskSource.GetResult(short token) => _caughtUp.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource.GetStatus(short token) => _caughtUp.GetStatus(token);

    // Woken on the reactor thread, at the end of a drain: resume there rather than post.
    void IValueTaskSource.OnCompleted(Action<object?> continuation, object? state, short token,
        ValueTaskSourceOnCompletedFlags flags)
        => _caughtUp.OnCompleted(continuation, state, token, flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
}
