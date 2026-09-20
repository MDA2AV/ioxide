namespace ioxide.nghttp3;

/// <summary>
/// The BUFFERED flavor, both handler shapes: dispatch at end-of-stream with the whole body
/// pre-assembled into <see cref="Nghttp3Request.Body"/>. Requests recycle the moment their
/// valid-until-return contract ends - right after a sync handler returns, or when an async
/// handler's task completes (sole owner: the request left _requests at dispatch).
/// </summary>
public sealed partial class Nghttp3Connection
{
    /// <summary>Buffered, synchronous: dispatch at end-of-stream with the whole body pre-assembled
    /// into <see cref="Nghttp3Request.Body"/>; the handler computes and returns - it must not wait
    /// for anything (blocking would stall the reactor). Owns the handler's connection ref.</summary>
    public async Task RunBufferedAsync(Func<Nghttp3Request, Nghttp3Response> handler)
    {
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
                    DispatchBufferedSync(handler);
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
            // Before letting go, because letting go is all the transport sees: DecRef neither
            // closes nor unregisters.
            CloseWithPeerCode();

            _quicConnection.DecRef();
            Dispose();
        }
    }

    /// <summary>Buffered, asynchronous: same end-of-stream dispatch and pre-assembled
    /// <see cref="Nghttp3Request.Body"/>, but the handler may await (a database, a cache - any
    /// ioxide-native awaitable resumes inline on the reactor). Owns the handler's connection ref.</summary>
    public async Task RunBufferedAsync(Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
    {
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
                    DispatchBufferedAsync(handler);
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
            // Before letting go, because letting go is all the transport sees: DecRef neither
            // closes nor unregisters.
            CloseWithPeerCode();

            _quicConnection.DecRef();
            Dispose();
        }
    }

    private void DispatchBufferedSync(Func<Nghttp3Request, Nghttp3Response> handler)
    {
        for (int i = 0; i < _readyStreamIds.Count && !_protocolFailed; i++)
        {
            if (!_requests.Remove(_readyStreamIds[i], out Nghttp3Request? request))
            {
                continue;
            }
            request.Dispatched = true;
            request.Freeze();   // arena is final - materialize the public memories

            Nghttp3Response response;
            try
            {
                response = handler(request);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"[ioxide.nghttp3] request handler faulted: {exception.GetBaseException().Message}");
                response = new Nghttp3Response { Status = 500 };
            }

            QueueResponse(request.StreamId, response);
            ReleaseRequest(request);   // sync handler returned - the contract just ended
        }
        _readyStreamIds.Clear();
    }

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
