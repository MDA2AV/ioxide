using System.Buffers;
using System.IO.Pipelines;

namespace ioxide.nghttp2;

/// <summary>
/// The serving loop: read ciphertext-free bytes off the ring, feed them to nghttp2, dispatch
/// whatever requests completed, drain the egress. One pass per recv batch, so a batch carrying
/// several requests answers them all before a single send goes out.
/// </summary>
public sealed partial class Nghttp2Connection
{
    /// <summary>Serve until the peer goes away, answering each request with <paramref name="handler"/>
    /// once it has arrived whole, body in <see cref="Nghttp2Request.Body"/>.</summary>
    public Task RunAsync(Func<Nghttp2Request, Nghttp2Response> handler)
        => RunAsync(request => new ValueTask<Nghttp2Response>(handler(request)));

    /// <summary>Serve until the peer goes away, with an asynchronous handler.</summary>
    public Task RunAsync(Func<Nghttp2Request, ValueTask<Nghttp2Response>> handler)
        => RunCoreAsync(() => DispatchBuffered(handler));

    /// <summary>
    /// Serve until the peer goes away, dispatching each request as soon as its HEADERS are in: the
    /// handler pulls the body through its <see cref="Nghttp2BodyReader"/> while it still arrives,
    /// instead of finding it assembled in <see cref="Nghttp2Request.Body"/>.
    ///
    /// The trade is what memory is bound by. A whole body is held whole, which suits ordinary
    /// requests and not hostile uploads; a streamed one holds one flow-control window, because
    /// credit is only returned to the peer as the handler reads.
    /// </summary>
    public Task RunAsync(Func<Nghttp2Request, Nghttp2BodyReader, ValueTask<Nghttp2Response>> handler)
    {
        _streamBodies = true;
        Func<Nghttp2Request, ValueTask<Nghttp2Response>> buffered = request => handler(request, request.BodyReader!);
        return RunCoreAsync(() => DispatchBuffered(buffered));
    }

    // The one serving loop. Each entry point hands it the dispatch for its response mode, run once
    // per read pass.
    private async Task RunCoreAsync(Action dispatch)
    {
        _reactor = (SynchronizationContext.Current as ReactorSynchronizationContext)?.Reactor;

        try
        {
            Setup();

            // SETTINGS go out before anything is read: a peer that opens with the preface and a
            // request immediately expects ours to be on the way.
            await FlushEgressAsync();

            while (!IsBroken)
            {
                ReadResult read = await _pipe.Input.ReadAsync();

                _inPass = true;
                Feed(read.Buffer);
                _pipe.Input.AdvanceTo(read.Buffer.End);

                // Handlers run HERE, after ih2_read has unwound - see the callbacks file.
                dispatch();

                // Body chunks reach parked readers inside the pass, so the credit they return rides
                // this pass's drain rather than a write of its own.
                FireBodyWakes();
                _inPass = false;
                await FlushEgressAsync();

                // A stream nghttp2 reset itself closes as the drain sends the RST_STREAM; its reader ends now.
                FireBodyWakes();

                if (read.IsCompleted || read.IsCanceled || Nghttp2.ih2_is_dead(_handle) != 0)
                {
                    return;
                }
            }
        }
        catch (Exception)
        {
            // A broken peer is not a server fault. The connection is torn down in the caller's
            // finally; nothing here is recoverable.
            _failed = true;
        }
        finally
        {
            Dispose();
        }
    }

    // Feed each segment straight to nghttp2. The segments are the ring's own memory when the pipe
    // is a TcpConnectionDualPipe, so nothing is copied; a frame split across two of them is fine,
    // because nghttp2 carries partial frames between calls.
    private unsafe void Feed(in ReadOnlySequence<byte> buffer)
    {
        foreach (ReadOnlyMemory<byte> segment in buffer)
        {
            if (segment.Length == 0)
            {
                continue;
            }

            using System.Buffers.MemoryHandle handle = segment.Pin();
            nint consumed = Nghttp2.ih2_read(_handle, (byte*)handle.Pointer, (nuint)segment.Length);
            if (consumed < 0)
            {
                _failed = true;   // protocol error; the drain still sends GOAWAY
                return;
            }
        }
    }

    // Snapshot and clear first: a handler that awaits can let another read pass land more
    // requests here, and the list must not be mutated while it is walked.
    private PendingRequest[] TakeReady()
    {
        if (_readyThisPass.Count == 0)
        {
            return [];
        }

        PendingRequest[] ready = _readyThisPass.ToArray();
        _readyThisPass.Clear();
        return ready;
    }

    // A request that outgrew MaxRequestBytes is reset instead of dispatched, whichever the response mode.
    private bool RefuseOverflowed(PendingRequest pending)
    {
        if (!pending.Overflowed)
        {
            return false;
        }

        // A queued reset closes the stream inside nghttp2, so none of its later frames call back.
        if (Nghttp2.ih2_submit_rst_stream(_handle, pending.StreamId, EnhanceYourCalm) != 0)
        {
            _failed = true;
        }
        _pending.Remove(pending.StreamId);
        pending.Dispose();
        return true;
    }

    private void DispatchBuffered(Func<Nghttp2Request, ValueTask<Nghttp2Response>> handler)
    {
        foreach (PendingRequest pending in TakeReady())
        {
            if (RefuseOverflowed(pending))
            {
                continue;
            }

            ValueTask<Nghttp2Response> inFlight;

            try
            {
                Nghttp2Request request = pending.Freeze();
                inFlight = handler(request);
            }
            catch (Exception exception)
            {
                // A synchronous handler throws before there is a task. It gets what a faulted task
                // gets, a 500 on its own stream, rather than taking the connection down.
                inFlight = ValueTask.FromException<Nghttp2Response>(exception);
            }

            // Answered synchronously, which nearly every handler does. Stay inline: the response is
            // submitted in time for this pass's drain, so it still leaves with every other one, and
            // there is no Task to allocate.
            if (inFlight.IsCompletedSuccessfully)
            {
                try
                {
                    SubmitResponse(pending.StreamId, inFlight.Result);
                }
                finally
                {
                    // The arena backs the request's memories, so it can only go back once the
                    // handler has returned and the response is submitted (which copies).
                    pending.Dispose();
                }
                continue;
            }

            // It parked - a database, an upstream, a disk. Awaiting here would hold every OTHER
            // stream on this connection behind it, including responses already submitted and
            // waiting to go, because they all share this one dispatch loop and one TCP connection.
            _ = CompleteAsync(inFlight, pending);
        }
    }

    /// <summary>
    /// The tail of a handler that parked. Nothing awaits this, so everything the dispatch loop
    /// would have done afterwards has to happen here: submitting, retiring the request, and
    /// draining, since this pass's drain has long gone by.
    /// </summary>
    private async Task CompleteAsync(ValueTask<Nghttp2Response> inFlight, PendingRequest pending)
    {
        try
        {
            SubmitResponse(pending.StreamId, await inFlight);
        }
        catch (Exception exception)
        {
            // Nobody can observe this task, so an escaping exception would vanish silently and the
            // peer would wait on a stream that is never coming.
            Console.Error.WriteLine(
                $"[ioxide.nghttp2] request handler faulted: {exception.GetBaseException().Message}");

            if (!IsBroken)
            {
                SubmitResponse(pending.StreamId, new Nghttp2Response { Status = 500 });
            }
        }
        finally
        {
            pending.Dispose();
            await FlushEgressAsync();
        }
    }
}
