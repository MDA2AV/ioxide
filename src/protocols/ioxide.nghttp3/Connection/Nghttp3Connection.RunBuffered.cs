namespace ioxide.nghttp3;

/// <summary>
/// The BUFFERED response, both handler shapes. With the body assembled, dispatch is at end-of-stream
/// and requests recycle the moment their valid-until-return contract ends - right after a handler
/// that never awaited returns, or when its task completes (sole owner: the request left _requests at
/// dispatch). A streamed body dispatches through <see cref="DispatchStreaming"/> instead.
/// </summary>
public sealed partial class Nghttp3Connection
{
    /// <summary>Serve until the peer goes away, answering each request with <paramref name="handler"/>,
    /// which computes and returns - it must not wait for anything (blocking would stall the
    /// reactor). Owns the handler's connection ref.</summary>
    public Task RunBufferedAsync(Func<Nghttp3Request, Nghttp3Response> handler)
        => RunBufferedAsync(request => new ValueTask<Nghttp3Response>(handler(request)));

    /// <summary>Serve until the peer goes away, with a handler that may await (a database, a cache -
    /// any ioxide-native awaitable resumes inline on the reactor). Owns the handler's connection ref.</summary>
    public Task RunBufferedAsync(Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
        => RunCoreAsync(_streamBodies ? () => DispatchStreaming(handler) : () => DispatchBufferedAsync(handler));

    private void DispatchBufferedAsync(Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
    {
        for (int i = 0; i < _readyStreamIds.Count && !_protocolFailed; i++)
        {
            if (!_requests.Remove(_readyStreamIds[i], out Nghttp3Request? request))
            {
                continue;
            }
            request.Dispatched = true;
            request.Freeze();   // arena is final - materialize the public memories

            ValueTask<Nghttp3Response> pending;
            try
            {
                pending = handler(request);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"[ioxide.nghttp3] request handler faulted: {exception.GetBaseException().Message}");
                QueueResponse(request.StreamId, new Nghttp3Response { Status = 500 });
                ReleaseRequest(request);
                continue;
            }

            if (pending.IsCompletedSuccessfully)
            {
                QueueResponse(request.StreamId, pending.Result);   // fast path: the handler never awaited
                ReleaseRequest(request);
            }
            else
            {
                _ = CompleteBufferedAsync(pending, request);
            }
        }
        _readyStreamIds.Clear();
    }

    // Continuation for a buffered-async handler that awaited: the request left _requests at
    // dispatch, so once the handler's task completes we are the sole owner - submit and recycle.
    private async Task CompleteBufferedAsync(ValueTask<Nghttp3Response> pending, Nghttp3Request request)
    {
        Nghttp3Response response;
        try
        {
            response = await pending;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[ioxide.nghttp3] request handler faulted: {exception.GetBaseException().Message}");
            response = new Nghttp3Response { Status = 500 };
        }

        if (_nghttp3Handle != 0 && !_protocolFailed)
        {
            QueueResponse(request.StreamId, response);
            PumpEgress();
        }
        ReleaseRequest(request);
    }
}
