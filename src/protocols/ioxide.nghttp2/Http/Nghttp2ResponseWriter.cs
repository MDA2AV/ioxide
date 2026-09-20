using System.Buffers;

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
/// frame boundaries and when to emit, and the connection's drain is what puts bytes on the socket.
/// </summary>
/// <remarks>
/// Reactor thread only, one writer per stream. <see cref="WriteHeaders"/> must come first and only
/// once; the connection completes the writer when the handler returns.
/// </remarks>
public sealed class Nghttp2ResponseWriter : IBufferWriter<byte>
{
    private readonly Nghttp2Connection _connection;

    private byte[] _staging = [];
    private int _staged;

    private bool _headersSent;
    private bool _completed;

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
        _connection.SendStreamedHeaders(StreamId, response);
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
    /// Hand everything staged to nghttp2 and let the connection drain.
    /// </summary>
    /// <remarks>
    /// Headers are sent for you if the handler never called <see cref="WriteHeaders"/>, because a
    /// body cannot precede them and a 200 is what the buffered path would have sent.
    /// </remarks>
    public async ValueTask FlushAsync()
    {
        if (!_headersSent)
        {
            WriteHeaders(new Nghttp2Response { Status = 200 });
        }

        if (_staged > 0)
        {
            _connection.SendStreamedData(StreamId, _staging.AsSpan(0, _staged));
            _staged = 0;
        }

        await _connection.FlushStreamedAsync();
    }

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

        if (_staged > 0)
        {
            _connection.SendStreamedData(StreamId, _staging.AsSpan(0, _staged));
            _staged = 0;
        }

        _connection.EndStreamedBody(StreamId);
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
        _headersSent = false;
        _completed = false;
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
}
