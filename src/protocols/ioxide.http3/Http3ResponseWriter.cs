using System.Buffers;
using System.IO.Pipelines;

namespace ioxide.http3;

/// <summary>
/// The write half of a STREAMED response: the handler pushes body bytes as it produces them, and
/// each flush becomes a DATA frame on the wire.
///
/// This is a push, not a pull. Owning the framing means a chunk can simply be sent - build
/// <c>[0x00][varint length][payload]</c> and hand it to the QUIC stream - with no data-reader
/// callback to answer, nothing to defer, and no buffer whose lifetime a library dictates. QUIC
/// streams are independent, so nothing has to be interleaved with other responses either.
///
/// It is an <see cref="IBufferWriter{T}"/> on purpose: that is the shape a serializer, a file
/// copy or a framework's response sink already writes into, so streaming through it needs no
/// adapter.
///
/// Backpressure is the connection's send retention. <see cref="FlushAsync"/> returns once the
/// chunk is queued, and waits when the connection is at its high-water, so a producer cannot
/// outrun a peer that has stopped reading.
/// </summary>
/// <remarks>Reactor thread only, like everything else on the connection.</remarks>
public sealed class Http3ResponseWriter : IBufferWriter<byte>
{
    private const int DefaultChunk = 16 * 1024;
    private const long FrameData = 0x0;
    private const ulong H3InternalError = 0x0102;

    private readonly Http3Connection _connection;
    private readonly QuicConnection _quic;
    private long _streamId;

    private byte[] _staging = [];
    private int _staged;

    private bool _headersSent;
    private bool _completed;
    private bool _gone;   // the peer stopped reading, or the stream closed under the handler

    internal Http3ResponseWriter(Http3Connection connection, QuicConnection quic, long streamId)
    {
        _connection = connection;
        _quic = quic;
        _streamId = streamId;
    }

    /// <summary>The stream this response belongs to.</summary>
    public long StreamId => _streamId;

    /// <summary>True once the body has been finished and the stream closed.</summary>
    public bool IsCompleted => _completed;

    /// <summary>
    /// Send the response headers. Exactly once, before any body byte - HTTP/3 puts HEADERS ahead
    /// of DATA and there is no correcting that later.
    ///
    /// No content-length is written: a streamed response does not know its length yet, and for an
    /// endless one there is no length to know. HTTP/3 needs none - each DATA frame carries its own.
    /// </summary>
    public void WriteHeaders(Http3Response response)
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
        if (!_gone)
        {
            _connection.SendStreamedHeaders(_streamId, response);
        }
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
    /// Send everything staged so far as one DATA frame. Waits first when the connection is at its
    /// send-retention high-water: that wait is the backpressure, and it is what keeps memory bound
    /// to one chunk rather than to the whole response.
    /// </summary>
    /// <returns>
    /// <see cref="FlushResult.IsCompleted"/> once the peer has stopped reading the stream or the
    /// connection is gone, as a TCP pipe writer reports a closed peer: nothing written from then on
    /// reaches anyone.
    /// </returns>
    public ValueTask<FlushResult> FlushAsync() => FlushCore(fin: false);

    /// <summary>The peer will read no more of this stream: from here on nothing is sent on it.</summary>
    internal void OnPeerGone() => _gone = true;

    private static readonly FlushResult PeerGone = new(isCanceled: false, isCompleted: true);

    /// <summary>
    /// Send what is left and close the stream. A handler that returns without calling this still
    /// gets it called for it - the peer is owed an end either way.
    /// </summary>
    public async ValueTask CompleteAsync()
    {
        if (_completed)
        {
            return;
        }

        if (!_headersSent)
        {
            WriteHeaders(new Http3Response { Status = 500 });
        }

        await FlushCore(fin: true);
        _completed = true;

        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
            _staging = [];
        }
    }

    /// <summary>
    /// End a response its handler failed to finish. Before the headers a 500 is still an honest
    /// answer; after them only a reset is - a clean end would pass a truncated body off as whole.
    /// </summary>
    internal ValueTask FailAsync()
    {
        if (_completed || !_headersSent)
        {
            return CompleteAsync();
        }

        _completed = true;
        _staged = 0;
        if (!_gone)
        {
            _quic.ResetStream(_streamId, H3InternalError);   // never on a stream the peer already stopped
        }

        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
            _staging = [];
        }
        return ValueTask.CompletedTask;
    }

    private async ValueTask<FlushResult> FlushCore(bool fin)
    {
        if (!_headersSent)
        {
            throw new InvalidOperationException("Write the response headers before flushing a body chunk.");
        }

        if (_staged == 0 && !fin)
        {
            return _gone || _connection.IsBroken ? PeerGone : default;
        }

        // The peer has stopped reading and the connection is holding all it is willing to. Wait
        // rather than queue: unbounded queueing here is exactly what streaming exists to avoid.
        while (!_quic.CanQueueSend && !_connection.IsBroken && !_gone)
        {
            await _connection.WaitForSendCapacityAsync();
        }

        if (_connection.IsBroken || _gone)
        {
            _staged = 0;   // nobody to send it to
            return PeerGone;
        }

        if (_staged == 0)
        {
            _quic.SendStream(_streamId, ReadOnlySpan<byte>.Empty, fin: true);
            return default;
        }

        // [0x00][varint length][payload], sent as one call - the header is tiny and splitting it
        // from its payload would cost a second trip through the QUIC send path per chunk.
        Span<byte> header = stackalloc byte[16];
        int h = Varint.Write(header, FrameData);
        h += Varint.Write(header[h..], _staged);

        byte[] frame = ArrayPool<byte>.Shared.Rent(h + _staged);
        header[..h].CopyTo(frame);
        _staging.AsSpan(0, _staged).CopyTo(frame.AsSpan(h));

        _quic.SendStream(_streamId, frame.AsSpan(0, h + _staged), fin);
        ArrayPool<byte>.Shared.Return(frame);

        _staged = 0;
        return default;
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

    /// <summary>
    /// Take this writer for another stream, keeping its buffer. A writer and its staging block
    /// carry nothing stream-specific once reset, and allocating both per response is what made the
    /// nghttp3 streamed path heavier than its buffered one.
    /// </summary>
    internal void Reset(long streamId)
    {
        _streamId = streamId;
        _staged = 0;
        _headersSent = false;
        _completed = false;
        _gone = false;
    }
}
