namespace ioxide.nghttp3;

/// <summary>
/// The BUFFERED response, both handler shapes. With the body assembled, dispatch is at end-of-stream
/// with all of it in <see cref="Nghttp3Request.Body"/>, and requests recycle the moment their
/// valid-until-return contract ends - right after a sync handler returns, or when an async
/// handler's task completes (sole owner: the request left _requests at dispatch). A handler that
/// takes a body reader dispatches as RequestBody does.
/// </summary>
public sealed partial class Nghttp3Connection
{
    /// <summary>Buffered, synchronous: dispatch at end-of-stream with the whole body pre-assembled
    /// into <see cref="Nghttp3Request.Body"/>; the handler computes and returns - it must not wait
    /// for anything (blocking would stall the reactor). Owns the handler's connection ref.</summary>
    public Task RunAsync(Func<Nghttp3Request, Nghttp3Response> handler)
        => RunCoreAsync(() =>
        {
            DispatchBufferedSync(handler);
            PumpEgress();
        });

    /// <summary>Buffered, asynchronous: same end-of-stream dispatch and pre-assembled
    /// <see cref="Nghttp3Request.Body"/>, but the handler may await (a database, a cache - any
    /// ioxide-native awaitable resumes inline on the reactor). Owns the handler's connection ref.</summary>
    public Task RunAsync(Func<Nghttp3Request, ValueTask<Nghttp3Response>> handler)
        => RunCoreAsync(() =>
        {
            DispatchBufferedAsync(handler);
            PumpEgress();
        });

    /// <summary>Streamed request body: dispatch at END-OF-HEADERS, the body pulled through the
    /// handler's <see cref="Nghttp3BodyReader"/> while the request stream is flow-control paced - a
    /// slow consumer freezes the peer's window instead of buffering (memory bound = one window, not
    /// the body size). The handler must resume on the reactor (every ioxide await does). Owns the
    /// handler's connection ref.</summary>
    public Task RunAsync(Func<Nghttp3Request, Nghttp3BodyReader, ValueTask<Nghttp3Response>> handler)
    {
        _streamBodies = true;
        Func<Nghttp3Request, ValueTask<Nghttp3Response>> buffered = request => handler(request, request.BodyReader!);
        return RunCoreAsync(() =>
        {
            DispatchStreaming(buffered);
            PumpEgress();
        });
    }

    // An assembled body past MaxRequestBytes, from CallbackData: the request is reset and never
    // dispatched, and the rest of its body is dropped as it arrives. Only the QUIC stream is reset -
    // this runs inside nghttp3, which must not be re-entered - and nghttp3 lets the stream go when
    // the transport reports it closed.
    private void RefuseOverflowed(Nghttp3Request request)
    {
        request.Overflowed = true;
        request.DropBody();
        _quicConnection.ResetStream(request.StreamId, H3ExcessiveLoad);
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

        await new ReactorSwitch(Reactor);   // back on the reactor, wherever the handler finished
        if (_nghttp3Handle != 0 && !_protocolFailed)
        {
            QueueResponse(request.StreamId, response);
            PumpEgress();
        }
        ReleaseRequest(request);
    }
}
