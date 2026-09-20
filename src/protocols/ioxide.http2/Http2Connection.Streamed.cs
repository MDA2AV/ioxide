using System.Buffers;

namespace ioxide.http2;

/// <summary>
/// The STREAMED-RESPONSE half: headers first, then the body as DATA frames pushed by the handler
/// through an <see cref="Http2ResponseWriter"/> as it produces them.
///
/// Owning the framing keeps this a push - a chunk is written the moment it exists rather than
/// when a library asks for it. What HTTP/2 adds over HTTP/3 is that credit is shared: every
/// stream rides one TCP connection and both a per-stream and a connection window must allow a
/// write, so a flush can block on either and is woken by a WINDOW_UPDATE for either.
/// </summary>
public sealed partial class Http2Connection
{
    private readonly Stack<Http2ResponseWriter> _writerPool = new();

    /// <summary>
    /// The peer's per-stream send window for each RESPONSE in flight.
    ///
    /// It cannot live on the PendingRequest, which is where the buffered path keeps it: a request
    /// that arrived complete - every GET, so every static file - is taken out of <c>_streams</c>
    /// the moment it becomes ready, which is BEFORE its handler runs. From then on a streamed
    /// response could find no window at all, and both halves of per-stream flow control went
    /// silently inert - nothing was charged when sending, and a stream-level WINDOW_UPDATE
    /// credited nothing. Only the connection window was left, so any response past the peer's
    /// 65535-byte stream window overran it and was killed with FLOW_CONTROL_ERROR.
    /// </summary>
    private readonly Dictionary<int, int> _responseWindows = new();
    private readonly Dictionary<int, List<TaskCompletionSource>> _creditWaiters = new();
    private Func<Http2Request, Http2ResponseWriter, ValueTask>? _streamedHandler;

    /// <summary>
    /// Serve this connection with each response body produced through a writer rather than
    /// returned whole. The handler owns its stream until it completes the writer.
    /// </summary>
    public Task RunAsync(Func<Http2Request, Http2ResponseWriter, ValueTask> handler)
    {
        _streamedHandler = handler;
        return RunBufferedAsync(NoBufferedHandler);
    }

    // Never invoked: a streamed connection hands every ready request to a writer before the
    // buffered path would reach this. It exists only because RunBufferedAsync needs a handler.
    private static Http2Response NoBufferedHandler(Http2Request _)
        => throw new InvalidOperationException("A streamed connection dispatches through its writer.");

    /// <summary>
    /// Hand a ready request to the streamed path, if this connection has one. Called from the
    /// dispatch that made it ready, so the writer's first frames ride that same pass.
    /// </summary>
    private bool TryDispatchStreamed(Http2Request request, PendingRequest pending)
    {
        if (_streamedHandler is null)
        {
            return false;
        }

        _responseWindows[request.StreamId] = _peerInitialStreamWindow;

        Http2ResponseWriter writer = RentWriter(request.StreamId);
        _ = ServeStreamedAsync(_streamedHandler, request, writer, pending);
        return true;
    }

    private async Task ServeStreamedAsync(Func<Http2Request, Http2ResponseWriter, ValueTask> handler,
        Http2Request request, Http2ResponseWriter writer, PendingRequest pending)
    {
        try
        {
            await handler(request, writer);
            await writer.CompleteAsync();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[ioxide.http2] request handler faulted: {exception.GetBaseException().Message}");
            try
            {
                await writer.CompleteAsync();
            }
            catch
            {
                // The stream is already unusable; nothing more to say to this peer.
            }
        }
        finally
        {
            // The buffered dispatch retires the stream in its own finally; the streamed one skips
            // that path, so it has to do it here. Without this every response leaks its arena and
            // the connection grows without bound - 20 GB over eight seconds of load, measured.
            _creditWaiters.Remove(writer.StreamId);
            _responseWindows.Remove(writer.StreamId);
            _streams.Remove(writer.StreamId);
            pending.Dispose();
            _writerPool.Push(writer);
        }
    }

    private Http2ResponseWriter RentWriter(int streamId)
    {
        if (_writerPool.TryPop(out Http2ResponseWriter? pooled))
        {
            pooled.Reset(streamId);
            return pooled;
        }
        return new Http2ResponseWriter(this, streamId);
    }

    /// <summary>Headers of a streamed response - no END_STREAM, the body follows.</summary>
    internal void SendStreamedHeaders(int streamId, Http2Response response)
        => WriteHeaders(streamId, response, endStream: false);

    /// <summary>
    /// How many body bytes may be sent on this stream right now: the smaller of the connection
    /// window, the stream window and the peer's maximum frame size. Zero means wait.
    /// </summary>
    internal int SendCredit(int streamId)
    {
        if (IsBroken)
        {
            return 0;
        }

        int credit = Math.Min(_peerConnectionWindow, _peerMaxFrameSize);

        if (_responseWindows.TryGetValue(streamId, out int window))
        {
            credit = Math.Min(credit, window);
        }
        else if (_streams.TryGetValue(streamId, out PendingRequest? pending))
        {
            credit = Math.Min(credit, pending.SendWindow);
        }

        return Math.Max(credit, 0);
    }

    /// <summary>One DATA frame, already known to fit both windows.</summary>
    internal void SendStreamedData(int streamId, ReadOnlySpan<byte> body, bool endStream)
    {
        Span<byte> header = stackalloc byte[FrameHeader.Size];
        new FrameHeader(body.Length, FrameType.Data,
            endStream ? FrameFlags.EndStream : FrameFlags.None, streamId).Write(header);

        Stage(header);
        if (!body.IsEmpty)
        {
            Stage(body);
        }

        _peerConnectionWindow -= body.Length;

        if (_responseWindows.TryGetValue(streamId, out int window))
        {
            _responseWindows[streamId] = window - body.Length;
        }
        else if (_streams.TryGetValue(streamId, out PendingRequest? pending))
        {
            pending.SendWindow -= body.Length;
        }
    }

    // True while the read loop still owes a flush. Inside a pass a writer skips its own write and
    // rides that one, which is what lets many responses leave on ONE transport write. The cost here
    // is per-write, not per-byte - a streamed response measured the same whether it carried 2 bytes
    // or 8 KiB - and buffered spreading one write across every stream in flight was the 12.8x.
    private bool _passFlushPending;

    /// <summary>True while the dispatch that owes the pass flush is still running.</summary>
    internal bool InDispatchPass => _passFlushPending;

    /// <summary>
    /// Write only when nothing else will. A handler that parked - on credit, on a timer, on a
    /// database - resumes after the pass flush has gone by, so its bytes would otherwise sit staged
    /// until the peer happened to send something, which for an endless response is never. When it
    /// resumes mid-flush instead, the bytes join the write queue and this await is the turn of the
    /// pump that carries them (Http2Connection.Write.cs) - so completions sharing a reactor turn
    /// still share a write.
    /// </summary>
    internal ValueTask MaybeFlushAsync()
        => _passFlushPending ? ValueTask.CompletedTask : FlushAsync();

    /// <summary>A streamed writer's flush: out to the transport, or the write queue's next turn.</summary>
    internal ValueTask FlushOutboundAsync() => FlushAsync();

    /// <summary>
    /// How much ONE response may stage before its writer flushes for real even inside a pass. The
    /// bound is per writer, never per pass - many responses coalescing into one large pass write
    /// is the point of the design, and an earlier per-pass version of this limit split those
    /// writes and cost a third of streamed throughput. What it exists for is the single producer
    /// that loops without awaiting anything of its own: that loop has no yield but this write, so
    /// skipping it unconditionally would spin the reactor with the response never moving at all.
    /// Past the limit the write happens for real, which both drains the staging and hands the
    /// thread back.
    ///
    /// A PACED producer (an SSE feed waiting on an event) never reaches the limit: it parks, the
    /// pass flush carries its chunk out immediately, and it resumes outside the pass where the
    /// flush is real. So latency stays tight where it matters, and only a bandwidth-bound producer
    /// trades a little of it for throughput.
    /// </summary>
    internal const int CoalesceLimit = 16 * 1024;

    /// <summary>Completes when this stream has credit again, or the connection gives up.</summary>
    internal Task WaitForSendCreditAsync(int streamId)
    {
        if (IsBroken)
        {
            return Task.CompletedTask;
        }

        if (!_creditWaiters.TryGetValue(streamId, out List<TaskCompletionSource>? waiters))
        {
            waiters = [];
            _creditWaiters[streamId] = waiters;
        }

        var waiter = new TaskCompletionSource();
        waiters.Add(waiter);
        return waiter.Task;
    }

    /// <summary>
    /// A WINDOW_UPDATE arrived. Stream 0 credits the connection, so it can unblock every parked
    /// writer; anything else unblocks only its own.
    /// </summary>
    private void ReleaseCreditWaiters(int streamId)
    {
        if (_creditWaiters.Count == 0)
        {
            return;
        }

        if (streamId == 0)
        {
            // Take the waiters OUT before waking any of them. These complete inline, so a resumed
            // writer that still has no credit re-registers immediately - and clearing afterwards
            // threw that new waiter away, leaving the writer parked on a wake that never comes,
            // while the enumeration it was added during threw "collection was modified".
            List<TaskCompletionSource>[] all = [.. _creditWaiters.Values];
            _creditWaiters.Clear();

            foreach (List<TaskCompletionSource> waiters in all)
            {
                Release(waiters);
            }
            return;
        }

        if (_creditWaiters.Remove(streamId, out List<TaskCompletionSource>? forStream))
        {
            Release(forStream);
        }

        static void Release(List<TaskCompletionSource> waiters)
        {
            foreach (TaskCompletionSource waiter in waiters)
            {
                waiter.TrySetResult();
            }
        }
    }

    private void ReleaseAllCreditWaiters()
    {
        if (_creditWaiters.Count == 0)
        {
            return;
        }

        // Same discipline as above, and it matters more here: this runs in the teardown finally, so
        // an exception escaping it bypasses the catch that exists to keep a malformed peer from
        // looking like a server fault.
        List<TaskCompletionSource>[] all = [.. _creditWaiters.Values];
        _creditWaiters.Clear();

        foreach (List<TaskCompletionSource> waiters in all)
        {
            foreach (TaskCompletionSource waiter in waiters)
            {
                waiter.TrySetResult();
            }
        }
    }
}
