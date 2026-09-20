using System.Buffers;

using System.Runtime.InteropServices;

namespace ioxide.nghttp3;

/// <summary>
/// The write half of a STREAMED response: the handler pushes body bytes as it produces them and
/// nghttp3 pulls them out when it has room to send, instead of the whole body being handed over
/// at once.
///
/// It is an <see cref="IBufferWriter{T}"/> on purpose. That is the shape a serializer, a file
/// copy or a framework's response sink already writes into, so a caller streaming a response
/// needs no adapter - <c>GetSpan</c>/<c>Advance</c>/<c>FlushAsync</c> and nothing else.
///
/// Chunks live in NATIVE memory. nghttp3 keeps the pointer it is handed until the bytes are
/// copied into the egress buffer, so a managed array could be moved by a GC in between; native
/// blocks cannot. They are recycled as soon as nghttp3 reports them written, which is what keeps
/// memory bounded by the flush size rather than by the response.
/// </summary>
/// <remarks>Reactor thread only, like everything else on the connection.</remarks>
public sealed class Nghttp3ResponseWriter : IBufferWriter<byte>
{
    // One in-flight chunk is enough to keep the pump fed: nghttp3 copies a chunk out on the write
    // it is offered in, so the next flush's buffer is free again by the time it is needed.
    private const int DefaultChunk = 16 * 1024;

    private readonly Nghttp3Connection _connection;
    private long _streamId;

    // Staged but not yet offered to nghttp3.
    private unsafe byte* _staging;
    private int _stagingCapacity;
    private int _staged;

    // Managed backing for GetMemory, copied into the staging block on Advance.
    //
    // GetSpan can hand out the native block directly, because a Span cannot cross an await. A
    // Memory can - and awaiting a read into one is the only reason a caller asks for a Memory at
    // all. The native block is not stable across that await: a flush swaps it with the in-flight
    // block, and connection teardown frees every writer's block without waiting for handlers that
    // are still parked. A read completing afterwards would land in memory that had moved or been
    // freed. A pooled array cannot be pulled out from under an outstanding Memory - the GC keeps
    // it alive for as long as the Memory refers to it - and the copy costs one memcpy on a path
    // that is copying already.
    private byte[]? _memoryScratch;
    private bool _memoryOutstanding;

    // Offered to nghttp3 and not yet known to be written. Kept separate from the staging block so
    // the handler can carry on filling the next chunk while this one is in flight.
    private unsafe byte* _inFlight;
    private int _inFlightCapacity;
    private int _inFlightLength;

    private int _offered;      // handed to nghttp3 on the last pull, not yet known consumed

    private bool _headersSent;
    private bool _completed;   // the handler has finished producing
    private bool _finReported; // nghttp3 has been told this is the end

    internal Nghttp3ResponseWriter(Nghttp3Connection connection, long streamId)
    {
        _connection = connection;
        _streamId = streamId;
    }

    /// <summary>
    /// Take this writer for another stream, keeping its buffers. A response costs a writer and a
    /// staging block; allocating both per request is what made the streamed path heavier than the
    /// buffered one, and neither depends on the stream they were used for.
    /// </summary>
    internal void Reset(long streamId)
    {
        _streamId = streamId;
        _staged = 0;
        _inFlightLength = 0;
        _offered = 0;
        _headersSent = false;
        _completed = false;
        _finReported = false;

        // The scratch buffer survives - that is the point of pooling the writer - but a hand-out
        // from the previous stream must not be mistaken for one from this one.
        _memoryOutstanding = false;
    }

    /// <summary>The stream this response belongs to.</summary>
    public long StreamId => _streamId;

    /// <summary>True once the body has been fully produced and handed over.</summary>
    public bool IsCompleted => _completed;

    /// <summary>
    /// Send the response headers. Must be called exactly once, before any body byte - HTTP/3 puts
    /// HEADERS ahead of DATA and there is no way to correct that afterwards.
    /// </summary>
    public void WriteHeaders(Nghttp3Response response)
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
        _connection.SubmitStreamedHeaders(_streamId, response, this);
    }

    /// <inheritdoc />
    public unsafe Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureStaging(sizeHint <= 0 ? 1 : sizeHint);
        return new Span<byte>(_staging + _staged, _stagingCapacity - _staged);
    }

    /// <summary>
    /// A buffer to fill, as <see cref="Memory{T}"/>. <see cref="Advance"/> copies what was written
    /// into the staging block.
    /// </summary>
    /// <remarks>
    /// This used to throw, which made the writer a non-conforming IBufferWriter, and the callers it
    /// broke are not exotic: a Stream reads into a Memory&lt;byte&gt; and cannot read into a
    /// Span&lt;byte&gt;, so every "copy this stream to the response" helper reaches for GetMemory -
    /// which is exactly how a framework serves a static file.
    /// </remarks>
    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        int want = sizeHint <= 0 ? 1 : sizeHint;

        if (_memoryScratch is null || _memoryScratch.Length < want)
        {
            ReleaseScratch();
            _memoryScratch = ArrayPool<byte>.Shared.Rent(want);
        }

        _memoryOutstanding = true;
        return _memoryScratch;
    }

    /// <inheritdoc />
    public unsafe void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        if (_memoryOutstanding)
        {
            _memoryOutstanding = false;

            // Released while the caller was awaiting a read into it: the connection is gone and
            // there is nowhere to put these bytes, so drop them rather than resurrect the block.
            if (_memoryScratch is null || count == 0)
            {
                return;
            }

            EnsureStaging(count);
            _memoryScratch.AsSpan(0, count).CopyTo(new Span<byte>(_staging + _staged, count));
            _staged += count;
            return;
        }

        if (_staged + count > _stagingCapacity)
        {
            throw new InvalidOperationException("Advanced past the end of the span handed out by GetSpan.");
        }
        _staged += count;
    }

    /// <summary>
    /// Hand everything staged so far to nghttp3 and let it send. Completes once the chunk has been
    /// taken, which is the backpressure: a peer that stops reading stops this returning, so a
    /// producer cannot outrun the connection.
    /// </summary>
    public async ValueTask FlushAsync()
    {
        if (!_headersSent)
        {
            throw new InvalidOperationException("Write the response headers before flushing a body chunk.");
        }
        if (_staged == 0)
        {
            return;
        }

        // Wait for the previous chunk to be taken before replacing it - one is in flight at a time.
        while (_inFlightLength > 0 && !_connection.IsFailed)
        {
            _connection.ResumeStreamedResponse(_streamId);
            await _connection.PumpAsync();
        }

        if (_connection.IsFailed)
        {
            return;
        }

        PromoteStagedChunk();

        _connection.ResumeStreamedResponse(_streamId);
        _connection.PumpIfOutsidePass();
    }

    /// <summary>
    /// Flush what is left and mark the end of the body.
    /// </summary>
    public async ValueTask CompleteAsync()
    {
        if (_completed)
        {
            return;
        }

        if (!_headersSent)
        {
            // A handler that returned without writing anything still owes the peer a response.
            WriteHeaders(new Nghttp3Response { Status = 500 });
        }

        if (_staged > 0)
        {
            await FlushAsync();
        }

        // Mark the end and hand back. Waiting here for nghttp3 to actually take the last chunk
        // would cost a reactor round trip on every response - including the one-chunk responses
        // that need no waiting at all, which is what made a 13-byte streamed response slower than
        // a 13-byte buffered one. The buffered path does not wait either: it submits, and the
        // pass pumps it out. The staged buffer stays alive until the stream closes, so there is
        // nothing to keep the handler around for.
        _completed = true;
        _connection.ResumeStreamedResponse(_streamId);
        _connection.PumpIfOutsidePass();
    }

    /// <summary>
    /// The pull side: hand nghttp3 the chunk in flight, or report nothing so the stream defers.
    /// Called from inside nghttp3's writev, so it must not call back into nghttp3.
    /// </summary>
    internal unsafe void OnPull(out byte* buffer, out nuint length, out bool fin)
    {
        // A pull only comes round again once nghttp3 has advanced its write offset past what it
        // was last handed, so whatever was offered is now copied out and the block is free.
        if (_offered > 0)
        {
            _inFlightLength = 0;
            _offered = 0;
        }

        if (_inFlightLength == 0)
        {
            if (_completed && _staged == 0)
            {
                buffer = null;
                length = 0;
                fin = true;
                _finReported = true;
                return;
            }

            buffer = null;
            length = 0;
            fin = false;   // nothing yet: defer until the next resume
            return;
        }

        buffer = _inFlight;
        length = (nuint)_inFlightLength;
        _offered = _inFlightLength;
        fin = _completed && _staged == 0;
        _finReported = fin;
    }

    // Swapping raw pointers needs an unsafe context, and an async method cannot be one.
    private unsafe void PromoteStagedChunk()
    {
        // Plain temporaries: a tuple swap would need ValueTuple<byte*, byte*>, and a pointer
        // cannot be a type argument.
        byte* previousInFlight = _inFlight;
        _inFlight = _staging;
        _staging = previousInFlight;

        (_inFlightCapacity, _stagingCapacity) = (_stagingCapacity, _inFlightCapacity);
        _inFlightLength = _staged;
        _staged = 0;
    }

    // Hand the scratch back, unless a caller may still be writing into it: a handler parked in a
    // read holds this array, and giving it to another renter while that read lands would corrupt
    // both. Dropping the reference is enough - the GC frees it once the read is done with it.
    private void ReleaseScratch()
    {
        if (_memoryScratch is not null && !_memoryOutstanding)
        {
            ArrayPool<byte>.Shared.Return(_memoryScratch);
        }
        _memoryScratch = null;
    }

    private unsafe void EnsureStaging(int sizeHint)
    {
        int needed = _staged + sizeHint;
        if (_staging != null && _stagingCapacity >= needed)
        {
            return;
        }

        int capacity = Math.Max(needed, DefaultChunk);
        byte* grown = (byte*)NativeMemory.Alloc((nuint)capacity);

        if (_staging != null)
        {
            if (_staged > 0)
            {
                Buffer.MemoryCopy(_staging, grown, capacity, _staged);
            }
            NativeMemory.Free(_staging);
        }

        _staging = grown;
        _stagingCapacity = capacity;
    }

    /// <summary>Release both blocks. Called when the stream closes, never before.</summary>
    internal unsafe void Release()
    {
        ReleaseScratch();

        if (_staging != null)
        {
            NativeMemory.Free(_staging);
            _staging = null;
            _stagingCapacity = 0;
            _staged = 0;
        }
        if (_inFlight != null)
        {
            NativeMemory.Free(_inFlight);
            _inFlight = null;
            _inFlightCapacity = 0;
            _inFlightLength = 0;
        }
    }
}
