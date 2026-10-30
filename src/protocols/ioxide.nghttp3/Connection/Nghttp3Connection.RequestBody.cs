namespace ioxide.nghttp3;

/// <summary>
/// The STREAMED request body, for a handler that takes a body reader: dispatch at end-of-headers,
/// body pulled through its <see cref="Nghttp3BodyReader"/> under flow-control
/// pacing, plus all the machinery only this mode uses - the body-wake deferral and window crediting.
/// The dispatch here answers with a buffered response; a streamed one dispatches in Streamed.
/// Requests recycle when the handler's task has completed AND the stream has left the tables
/// (whichever happens last owns the release; the Pooled flag makes it race-free).
/// </summary>
public sealed partial class Nghttp3Connection
{
    private void DispatchStreaming(Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
    {
        for (int i = 0; i < _readyStreamIds.Count && !_protocolFailed; i++)
        {
            long streamId = _readyStreamIds[i];
            // The request STAYS in _requests until the stream closes: trailers and lifecycle
            // events for this stream must keep resolving to it (their fields are dropped, but
            // resolving to a recycled object would corrupt another stream's request).
            if (!_requests.TryGetValue(streamId, out Nghttp3Request? request))
            {
                continue;
            }
            request.Dispatched = true;
            request.Freeze();   // headers are final; the body streams through BodyReader

            ValueTask<Nghttp3Response> pending;
            try
            {
                pending = handler(request);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"[ioxide.nghttp3] request handler faulted: {exception.GetBaseException().Message}");
                RetireBody(request);
                QueueResponse(streamId, new Nghttp3Response { Status = 500 });
                request.HandlerDone = true;
                continue;
            }

            if (pending.IsCompletedSuccessfully)
            {
                RetireBody(request);
                QueueResponse(streamId, pending.Result);   // fast path: no body awaited (GETs)
                request.HandlerDone = true;
            }
            else
            {
                _ = CompleteStreamingAsync(pending, request);
            }
        }
        _readyStreamIds.Clear();
    }

    // Continuation for a handler that awaited (body chunks, a db call): resumes inline on the
    // reactor; submit + pump unless the connection died underneath it.
    private async Task CompleteStreamingAsync(ValueTask<Nghttp3Response> pending, Nghttp3Request request)
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

        await new ReactorSwitch(Reactor);   // back on the reactor, wherever the handler finished
        long streamId = request.StreamId;
        request.HandlerDone = true;
        RetireBody(request);

        if (_nghttp3Handle != 0 && !_protocolFailed)
        {
            QueueResponse(streamId, response);
            PumpEgress();
        }

        if (request.Detached)
        {
            ReleaseRequest(request);   // the stream already closed - we are the last owner
        }
    }

    // Credit consumed bytes of a paced request stream back to the peer's flow-control window.
    internal void CreditBody(long streamId, int bytes) => _quicConnection.ConsumeStreamData(streamId, bytes);

    internal Reactor Reactor => _quicConnection.Reactor;

    // The handler is done with the body: credit what it left unread and let the engine credit the rest.
    private void RetireBody(Nghttp3Request request)
    {
        request.BodyReader?.Drop();
        if (_sinks.Remove(request.StreamId))
        {
            _quicConnection.SetStreamPaced(request.StreamId, false);
        }
    }

    // A sink with a parked reader became ready mid-PushToEngine; the wake is deferred to FireBodyWakes.
    internal void NoteBodyWake(Nghttp3BodyReader sink)
    {
        if (!_bodyWakes.Contains(sink))
        {
            _bodyWakes.Add(sink);
        }
    }

    private void FireBodyWakes()
    {
        for (int i = 0; i < _bodyWakes.Count; i++)
        {
            _bodyWakes[i].FireIfReady();
        }
        _bodyWakes.Clear();
    }
}
