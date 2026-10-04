using System.Buffers;

namespace ioxide.nghttp2;

/// <summary>
/// The STREAMED-RESPONSE half: headers first, then the body pushed through an
/// <see cref="Nghttp2ResponseWriter"/> as the handler produces it.
///
/// nghttp2 pulls rather than accepts pushes, so what looks like a flush here is really "buffered
/// natively, stream resumed" - the shim's read callback defers while nothing is queued and wakes on
/// every write. That is the whole difference from <c>ioxide.http2</c>, which owns its framing and
/// writes a DATA frame the moment a chunk is staged.
/// </summary>
public sealed partial class Nghttp2Connection
{
    private readonly Stack<Nghttp2ResponseWriter> _writerPool = new();

    // Streamed responses in flight, so a RST_STREAM from the peer can reach the one it ends.
    private readonly Dictionary<int, Nghttp2ResponseWriter> _writers = new();
    private Func<Nghttp2Request, Nghttp2ResponseWriter, ValueTask>? _streamedHandler;

    /// <summary>
    /// Serve this connection with each response body produced through a writer rather than
    /// returned whole. The handler owns its stream until it returns.
    /// </summary>
    public Task RunAsync(Func<Nghttp2Request, Nghttp2ResponseWriter, ValueTask> handler)
    {
        _streamedHandler = handler;
        return RunBufferedAsync(NoBufferedHandler);
    }

    // Never invoked: a streamed connection hands every ready request to a writer before the
    // buffered path would reach this. It exists only because RunBufferedAsync needs a handler.
    private static Nghttp2Response NoBufferedHandler(Nghttp2Request _)
        => throw new InvalidOperationException("A streamed connection dispatches through its writer.");

    /// <summary>
    /// Hand a ready request to the streamed path, if this connection has one. Called from the
    /// dispatch that made it ready, so the writer's first frames ride that same drain.
    /// </summary>
    private bool TryDispatchStreamed(Nghttp2Request request, PendingRequest pending)
    {
        if (_streamedHandler is null)
        {
            return false;
        }

        Nghttp2ResponseWriter writer = RentWriter(request.StreamId);
        _writers[request.StreamId] = writer;
        _ = ServeStreamedAsync(_streamedHandler, request, writer, pending);
        return true;
    }

    private async Task ServeStreamedAsync(Func<Nghttp2Request, Nghttp2ResponseWriter, ValueTask> handler,
        Nghttp2Request request, Nghttp2ResponseWriter writer, PendingRequest pending)
    {
        try
        {
            await handler(request, writer);
            await writer.CompleteAsync();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"[ioxide.nghttp2] request handler faulted: {exception.GetBaseException().Message}");
            try
            {
                await writer.FailAsync();
            }
            catch
            {
                // The stream is already unusable; nothing more to say to this peer.
            }
        }
        finally
        {
            // Nothing awaits this task, so the retirement the dispatch loop would have done has to
            // happen here - the arena backs the request's memories and the writer holds a pooled
            // staging buffer.
            pending.Dispose();
            _writers.Remove(writer.StreamId);
            writer.Release();
            _writerPool.Push(writer);
        }
    }

    private Nghttp2ResponseWriter RentWriter(int streamId)
    {
        if (_writerPool.TryPop(out Nghttp2ResponseWriter? pooled))
        {
            pooled.Reset(streamId);
            return pooled;
        }
        return new Nghttp2ResponseWriter(this, streamId);
    }

    /// <summary>Headers of a streamed response - no END_STREAM, the body follows.</summary>
    internal unsafe void SendStreamedHeaders(int streamId, Nghttp2Response response)
    {
        if (_handle == 0)
        {
            return;
        }

        byte[] headers = PackHeaders(response, out int headersLength);
        try
        {
            int result;
            fixed (byte* headerBytes = headers)
            {
                result = Nghttp2.ih2_submit_response_stream(_handle, streamId, headerBytes, (nuint)headersLength);
            }

            if (result != 0)
            {
                _failed = true;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(headers);
        }
    }

    /// <summary>Hand a chunk to nghttp2 and wake the deferred stream. Copied natively.</summary>
    /// <returns>False when nghttp2 no longer knows the stream: the peer reset it.</returns>
    internal unsafe bool SendStreamedData(int streamId, ReadOnlySpan<byte> body)
    {
        if (_handle == 0 || body.IsEmpty)
        {
            return true;
        }

        fixed (byte* bodyBytes = body)
        {
            int result = Nghttp2.ih2_stream_write(_handle, streamId, bodyBytes, (nuint)body.Length);

            // A stream closed by the peer is dropped natively, so the write finds nothing - one
            // stream's end, not a fault in the connection every other stream is riding.
            if (result == ErrInvalidArgument)
            {
                return false;
            }
            if (result != 0)
            {
                _failed = true;
            }
        }
        return true;
    }

    /// <summary>A streamed response its handler could not finish: RST_STREAM INTERNAL_ERROR.</summary>
    internal void ResetStreamed(int streamId)
    {
        if (_handle != 0 && Nghttp2.ih2_submit_rst_stream(_handle, streamId, InternalError) != 0)
        {
            _failed = true;
        }
    }

    /// <summary>No more body on this stream; END_STREAM follows what is already queued.</summary>
    internal void EndStreamedBody(int streamId)
    {
        if (_handle != 0)
        {
            Nghttp2.ih2_stream_close(_handle, streamId);
        }
    }

    /// <summary>
    /// Put whatever nghttp2 has queued on the wire. A writer that finished inside the read pass
    /// rides that pass's drain; one that resumed later drains for itself, which the drain guard in
    /// the egress path makes safe.
    /// </summary>
    internal ValueTask FlushStreamedAsync() => FlushEgressAsync();
}
