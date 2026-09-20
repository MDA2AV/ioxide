using System.Buffers;
using System.Runtime.InteropServices;

namespace ioxide.nghttp3;

/// <summary>
/// The STREAMED-RESPONSE half: headers go out first and the body is pulled from a
/// <see cref="Nghttp3ResponseWriter"/> as nghttp3 finds room for it, so a response never has to
/// exist in memory all at once.
///
/// nghttp3 already worked this way - it takes a data reader and calls back for body bytes - the
/// native shim simply pre-copied the whole body and served slices of it. Streaming is that
/// callback asking the application instead, with WOULDBLOCK as the "nothing yet" answer and
/// resume_stream as the wake.
/// </summary>
public sealed partial class Nghttp3Connection
{
    /// <summary>True once the connection can no longer make progress; parked writers give up on it.</summary>
    internal bool IsFailed => _protocolFailed || _nghttp3Handle == 0;

    private readonly Dictionary<long, Nghttp3ResponseWriter> _writers = new();

    // Streams told nghttp3 "nothing yet" that have data now. Resumes are DEFERRED to here rather
    // than applied where they are asked for: the pull runs inside nghttp3's writev, and resuming
    // from there would re-enter it mid-call.
    private readonly List<long> _pendingResumes = [];

    // Handlers parked in FlushAsync/CompleteAsync, woken once per reactor pass so they can see
    // whether their chunk was taken.
    private readonly List<TaskCompletionSource> _passWaiters = [];

    // Writers outlive the stream they served: their buffers are the expensive part and carry no
    // per-stream state once reset.
    private readonly Stack<Nghttp3ResponseWriter> _writerPool = new();

    private Nghttp3ResponseWriter RentWriter(long streamId)
    {
        if (_writerPool.TryPop(out Nghttp3ResponseWriter? pooled))
        {
            pooled.Reset(streamId);
            return pooled;
        }
        return new Nghttp3ResponseWriter(this, streamId);
    }

    /// <summary>
    /// Serve this connection with the body of each response produced through a writer rather than
    /// returned whole. The handler owns the stream until it completes the writer: write headers,
    /// push body, complete.
    /// </summary>
    public async Task RunStreamedResponseAsync(Func<Nghttp3Request, Nghttp3ResponseWriter, ValueTask> handler)
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
                    FireBodyWakes();
                    DispatchStreamedResponse(handler);
                    DrainStreamed();
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
            foreach (Nghttp3BodyReader sink in _sinks.Values)
            {
                sink.Drop();
            }
            FireBodyWakes();
            _sinks.Clear();

            // Unpark anything still waiting on a pass; IsBroken makes them return rather than loop.
            // Deliberately the bare flag and NOT FailInternal(): this runs on a response that
            // completed perfectly well, and giving it a peer code would close every successful
            // streamed connection with an error.
            _protocolFailed = true;
            ReleasePassWaiters();

            foreach (Nghttp3ResponseWriter writer in _writers.Values)
            {
                writer.Release();
            }
            _writers.Clear();

            while (_writerPool.TryPop(out Nghttp3ResponseWriter? pooled))
            {
                pooled.Release();   // the native blocks die with the connection, not the stream
            }

            // Before letting go, because letting go is all the transport sees: DecRef neither
            // closes nor unregisters.
            CloseWithPeerCode();

            _quicConnection.DecRef();
            Dispose();
        }
    }

    /// <summary>
    /// Pump until the streamed responses stop making progress.
    ///
    /// This is the difference between a streamed response and a buffered one. A buffered response
    /// is submitted whole inside the pass that dispatched it, so the loop can go straight back to
    /// waiting for the peer. A streamed one produces a chunk, waits for it to be taken, then
    /// produces the next - and the peer is silent throughout, because it is waiting for us. Going
    /// back to ReadAsync between chunks would wait for a packet that only our own output will
    /// provoke, so the response would stall after its first chunk.
    /// </summary>
    // True while DrainStreamed is on the stack. A writer that flushes from inside it may park and
    // be resumed by the loop; one that flushes from anywhere else has to drive the drain itself,
    // because no loop is running to do it.
    private bool _inStreamedDrain;

    private void DrainStreamed()
    {
        if (_inStreamedDrain)
        {
            return;   // already draining; the loop below picks up whatever was just staged
        }

        _inStreamedDrain = true;
        try
        {
            DrainStreamedCore();
        }
        finally
        {
            _inStreamedDrain = false;
        }
    }

    /// <summary>
    /// Drive egress for a writer that resumed OUTSIDE the read pass - after a file read, a database
    /// call, an upstream response. Inside the pass this does nothing, because the drain loop is
    /// already running and will pump what was just staged; that path stays exactly as it was, which
    /// is what keeps a one-chunk response from paying a reactor round trip it does not need.
    /// </summary>
    internal void PumpIfOutsidePass()
    {
        if (!_inStreamedDrain && !_protocolFailed)
        {
            DrainStreamed();
        }
    }

    private void DrainStreamedCore()
    {
        while (!_protocolFailed)
        {
            ApplyPendingResumes();
            bool produced = PumpEgress();

            bool parked = _passWaiters.Count > 0;

            // Resumes the handlers inline: each runs on to its next flush, stages a chunk and
            // parks again, all before this returns. So by the time the loop comes round there is
            // either new work to pump or nothing left to do.
            ReleasePassWaiters();

            if (!parked && _pendingResumes.Count == 0)
            {
                return;   // nothing streaming: back to waiting on the peer
            }

            // A pump that moved nothing means the next step needs the PEER - an ack to free send
            // retention, or a window update. Spinning here would hold the reactor thread against a
            // client that has gone away, which is exactly what an endless response does when its
            // reader disconnects: the parked writer waits forever and nothing else gets served.
            // Hand the thread back; the outer loop wakes this again on the next datagram.
            if (!produced)
            {
                return;
            }
        }
    }

    private void DispatchStreamedResponse(Func<Nghttp3Request, Nghttp3ResponseWriter, ValueTask> handler)
    {
        for (int i = 0; i < _readyStreamIds.Count && !_protocolFailed; i++)
        {
            long streamId = _readyStreamIds[i];

            if (!_requests.TryGetValue(streamId, out Nghttp3Request? request))
            {
                continue;
            }

            request.Dispatched = true;
            request.Freeze();

            Nghttp3ResponseWriter writer = RentWriter(streamId);
            _writers[streamId] = writer;

            ValueTask pending;
            try
            {
                pending = handler(request, writer);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"[ioxide.nghttp3] request handler faulted: {exception.GetBaseException().Message}");
                FailStreamed(streamId, writer, request);
                continue;
            }

            _ = CompleteStreamedAsync(pending, request, writer);
        }
        _readyStreamIds.Clear();
    }

    // The handler's tail: whatever it did, the stream owes the peer an end. Completing the writer
    // is what produces it, so a handler that forgot cannot leave a stream hanging.
    private async Task CompleteStreamedAsync(ValueTask pending, Nghttp3Request request, Nghttp3ResponseWriter writer)
    {
        try
        {
            await pending;
            await writer.CompleteAsync();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[ioxide.nghttp3] request handler faulted: {exception.GetBaseException().Message}");
            FailStreamed(writer.StreamId, writer, request);
            return;
        }

        request.HandlerDone = true;
    }

    private void FailStreamed(long streamId, Nghttp3ResponseWriter writer, Nghttp3Request request)
    {
        // Headers may already be on the wire, in which case the only honest ending is a reset -
        // a 500 after a 200 would be a lie the peer cannot detect.
        if (writer.IsCompleted)
        {
            return;
        }

        _writers.Remove(streamId);
        writer.Release();
        QueueResponse(streamId, new Nghttp3Response { Status = 500 });
        request.HandlerDone = true;
    }

    /// <summary>Submit the headers of a streamed response; the body follows through the writer.</summary>
    internal unsafe void SubmitStreamedHeaders(long streamId, Nghttp3Response response, Nghttp3ResponseWriter writer)
    {
        if (_nghttp3Handle == 0)
        {
            return;
        }

        _writers[streamId] = writer;

        byte[] headers = PackHeaders(response, out int headersLength);
        int result;
        fixed (byte* headersPointer = headers)
        {
            result = Nghttp3.ih3_submit_response_stream(_nghttp3Handle, streamId, headersPointer, (nuint)headersLength);
        }
        ArrayPool<byte>.Shared.Return(headers);

        if (result != 0)
        {
            Console.Error.WriteLine($"[ioxide.nghttp3] submit_response_stream failed: {Nghttp3.StrError(result)}");
            FailProtocol(result);
        }
    }

    /// <summary>A writer has more body. Deferred, because a resume must not run inside a pull.</summary>
    internal void ResumeStreamedResponse(long streamId)
    {
        if (!_pendingResumes.Contains(streamId))
        {
            _pendingResumes.Add(streamId);
        }
    }

    private void ApplyPendingResumes()
    {
        for (int i = 0; i < _pendingResumes.Count; i++)
        {
            if (_nghttp3Handle != 0)
            {
                Nghttp3.ih3_resume_stream(_nghttp3Handle, _pendingResumes[i]);
            }
        }
        _pendingResumes.Clear();
    }

    /// <summary>
    /// Completes on the next reactor pass. A parked writer awaits this rather than spinning, so
    /// the connection keeps reading and pumping while a handler waits for its chunk to be taken.
    /// </summary>
    internal Task PumpAsync()
    {
        if (IsFailed)
        {
            return Task.CompletedTask;
        }

        // Outside the drain loop there is nobody to release a pass waiter: the loop only runs while
        // the peer is sending, and a peer waiting for our response sends nothing. Parking here is
        // what made a handler that awaits anything - a file read, a query, an upstream - stall on
        // its first chunk and hang on its second. Drive the drain instead and carry on.
        if (!_inStreamedDrain)
        {
            DrainStreamed();
            return Task.CompletedTask;
        }

        // NOT RunContinuationsAsynchronously: everything on a reactor resumes inline on the
        // reactor thread, and a parked writer is no different. Completing this runs the handler
        // to its next park right there, so the drain loop needs no scheduler round trip to let it
        // make progress.
        var waiter = new TaskCompletionSource();
        _passWaiters.Add(waiter);
        return waiter.Task;
    }

    private void ReleasePassWaiters()
    {
        if (_passWaiters.Count == 0)
        {
            return;
        }

        // Snapshot: a woken writer may park again, and that belongs to the NEXT pass.
        TaskCompletionSource[] waiting = _passWaiters.ToArray();
        _passWaiters.Clear();

        foreach (TaskCompletionSource waiter in waiting)
        {
            waiter.TrySetResult();
        }
    }

    /// <summary>The pull, from inside nghttp3's writev. Resolves the writer and asks it.</summary>
    internal unsafe void PullStreamedBody(long streamId, byte** buffer, nuint* length, int* fin)
    {
        *buffer = null;
        *length = 0;
        *fin = 0;

        if (!_writers.TryGetValue(streamId, out Nghttp3ResponseWriter? writer))
        {
            *fin = 1;   // no writer: end the stream rather than defer it forever
            return;
        }

        writer.OnPull(out byte* chunk, out nuint chunkLength, out bool finished);

        *buffer = chunk;
        *length = chunkLength;
        *fin = finished ? 1 : 0;
    }

    /// <summary>Release a streamed response's buffers once its stream is gone.</summary>
    private void ReleaseWriter(long streamId)
    {
        if (_writers.Remove(streamId, out Nghttp3ResponseWriter? writer))
        {
            _writerPool.Push(writer);   // buffers stay; freed with the connection
        }
    }
}
