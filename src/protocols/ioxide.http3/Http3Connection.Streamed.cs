using System.Buffers;

namespace ioxide.http3;

/// <summary>
/// The STREAMED-RESPONSE half of the pure-C# HTTP/3 server: headers go out first and the body
/// follows as DATA frames, pushed by the handler through an <see cref="Http3ResponseWriter"/>.
/// </summary>
public sealed partial class Http3Connection
{
    private readonly Stack<Http3ResponseWriter> _writerPool = new();
    private readonly List<TaskCompletionSource> _capacityWaiters = [];

    /// <summary>True once the connection can no longer make progress; a parked writer gives up.</summary>
    // Includes the connection going away, not just an h3 protocol error. A streamed response
    // parks on this when the peer stops reading - and _fatal alone is never set by a teardown, so
    // after the connection died CanQueueSend was permanently false, IsBroken permanently false, and
    // the writer re-added a capacity waiter nothing would ever release. One leaked handler task,
    // writer, staging buffer and connection graph per abandoned download.
    internal bool IsBroken => _fatal || _peerGone;

    /// <summary>
    /// Serve this connection with each response body produced through a writer rather than
    /// returned whole. The handler owns its stream until it completes the writer.
    /// </summary>
    public async Task RunStreamedResponseAsync(Func<Http3Request, Http3ResponseWriter, ValueTask> handler)
    {
        _quicConnection.OnSendCapacityAvailable = ReleaseCapacityWaiters;

        try
        {
            // Its own dispatch, rather than tunnelling through the buffered one: a streamed
            // response has no Http3Response to return, and pretending otherwise meant handing
            // back a sentinel that Submit then had to recognise and skip.
            _streamedResponseHandler = handler;
            await RunAsync(NoBufferedHandler);
        }
        finally
        {
            ReleaseCapacityWaiters();
            while (_writerPool.TryPop(out _)) { }
        }
    }

    private Func<Http3Request, Http3ResponseWriter, ValueTask>? _streamedResponseHandler;

    // Never invoked: DispatchReady hands streamed requests to the writer path before it would be
    // reached. It exists only because RunAsync's signature demands a handler.
    private static Http3Response NoBufferedHandler(Http3Request _)
        => throw new InvalidOperationException("A streamed connection dispatches through its writer.");

    /// <summary>
    /// The streamed dispatch, called from the pass that made the request ready - so the writer's
    /// sends happen inside that pass, like a buffered Submit does.
    /// </summary>
    private bool TryDispatchStreamedResponse(Http3Request request)
    {
        if (_streamedResponseHandler is null)
        {
            return false;
        }

        Http3ResponseWriter writer = RentWriter(request.StreamId);
        _ = ServeAsync(_streamedResponseHandler, request, writer);
        return true;
    }

    private async Task ServeAsync(Func<Http3Request, Http3ResponseWriter, ValueTask> handler,
        Http3Request request, Http3ResponseWriter writer)
    {
        try
        {
            await handler(request, writer);
            await writer.CompleteAsync();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[ioxide.http3] request handler faulted: {exception.GetBaseException().Message}");
            await writer.CompleteAsync();
        }
        finally
        {
            _writerPool.Push(writer);
        }
    }

    private Http3ResponseWriter RentWriter(long streamId)
    {
        if (_writerPool.TryPop(out Http3ResponseWriter? pooled))
        {
            pooled.Reset(streamId);
            return pooled;
        }
        return new Http3ResponseWriter(this, _quicConnection, streamId);
    }

    /// <summary>Encode and send the HEADERS frame of a streamed response - no content-length.</summary>
    internal void SendStreamedHeaders(long streamId, Http3Response response)
    {
        byte[] fields = Qpack.EncodeResponseFields(response, out int fieldsLen);
        byte[] head = ArrayPool<byte>.Shared.Rent(fieldsLen + 16);

        int w = Varint.Write(head.AsSpan(), 0x1);           // HEADERS
        w += Varint.Write(head.AsSpan(w), fieldsLen);
        fields.AsSpan(0, fieldsLen).CopyTo(head.AsSpan(w));
        w += fieldsLen;

        _quicConnection.SendStream(streamId, head.AsSpan(0, w), fin: false);

        ArrayPool<byte>.Shared.Return(fields);
        ArrayPool<byte>.Shared.Return(head);
    }

    /// <summary>Completes when the connection can accept more sends.</summary>
    internal Task WaitForSendCapacityAsync()
    {
        if (IsBroken)
        {
            return Task.CompletedTask;
        }

        var waiter = new TaskCompletionSource();
        _capacityWaiters.Add(waiter);
        return waiter.Task;
    }

    private void ReleaseCapacityWaiters()
    {
        if (_capacityWaiters.Count == 0)
        {
            return;
        }

        TaskCompletionSource[] waiting = _capacityWaiters.ToArray();
        _capacityWaiters.Clear();

        foreach (TaskCompletionSource waiter in waiting)
        {
            waiter.TrySetResult();
        }
    }
}
