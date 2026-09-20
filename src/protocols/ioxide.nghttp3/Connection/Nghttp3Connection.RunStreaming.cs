namespace ioxide.nghttp3;

/// <summary>
/// The STREAMING flavor: dispatch at end-of-headers, body pulled through
/// <see cref="Nghttp3Request.BodyReader"/> under flow-control pacing, plus all the machinery only
/// this flavor uses - the body-wake deferral and window crediting. Requests recycle when the
/// handler's task has completed AND the stream has left the tables (whichever happens last owns
/// the release; the Pooled flag makes it race-free).
/// </summary>
public sealed partial class Nghttp3Connection
{
    /// <summary>Streaming: dispatch at END-OF-HEADERS, body pulled through
    /// <see cref="Nghttp3Request.BodyReader"/> while the request stream is flow-control paced - a slow
    /// consumer freezes the peer's window instead of buffering (memory bound = one window, not the
    /// body size). The handler must resume on the reactor (every ioxide await does). Owns the
    /// handler's connection ref.</summary>
    public async Task RunStreamingAsync(Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
    {
        _streaming = true;
        try
        {
            while (true)
            {
                QuicRecvSnapshot snapshot = await _quicConnection.ReadAsync();

                if (_nghttp3Handle == 0 && !_protocolFailed && !TrySetup())
                {
                    FailInternal();
                }

                while (_quicConnection.TryGetDelivery(in snapshot, out QuicRecvRing.Delivery item))
                {
                    if (!_protocolFailed)
                    {
                        PushToEngine(in item);
                    }
                    _quicConnection.ReturnBuffer(in item);
                }

                if (!_protocolFailed)
                {
                    // Deferred body wakes first: a resumed body-await may complete its request and
                    // its Submit/Drain rides this same pass. nghttp3 has fully unwound here.
                    FireBodyWakes();
                    DispatchStreaming(handler);
                    PumpEgress();
                    CloseIfShutdownComplete();
                }

                if (snapshot.IsClosed || _protocolFailed)
                {
                    break;
                }
                _quicConnection.ResetRead();
            }
        }
        finally
        {
            // Unpark any handler still awaiting a body: reads return empty, its response submit
            // no-ops against the disposed engine. In-flight requests die with the connection.
            foreach (Nghttp3BodyReader sink in _sinks.Values)
            {
                sink.Drop();
            }
            FireBodyWakes();
            _sinks.Clear();

            // Before letting go, because letting go is all the transport sees: DecRef neither
            // closes nor unregisters.
            CloseWithPeerCode();

            _quicConnection.DecRef();
            Dispose();
        }
    }

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
                QueueResponse(streamId, new Nghttp3Response { Status = 500 });
                request.HandlerDone = true;
                continue;
            }

            if (pending.IsCompletedSuccessfully)
            {
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

        long streamId = request.StreamId;
        request.HandlerDone = true;

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
