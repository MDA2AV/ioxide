using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;

namespace ioxide.http2;

/// <summary>
/// The write side: everything is staged into the connection's write slab and flushed once per pass,
/// so a batch of multiplexed responses leaves in one send rather than one each.
///
/// Staging and flushing take TURNS, because the transport permits neither a write during a flush
/// nor a second flush - and with non-blocking dispatch a handler finishes whenever its database
/// answers, which is as likely as not to be mid-flush. So while a flush is in flight, frames land
/// in a queue instead of the pipe; when it completes, the whole queue moves into the pipe and goes
/// out as the next flush. Every response that completed during one transport write leaves on the
/// single write after it, which is what extends the pass coalescing to handlers that finish
/// outside the pass.
/// </summary>
public sealed partial class Http2Connection
{
    private bool _staged;      // bytes sit in the pipe writer, awaiting a flush
    private bool _flushing;    // a transport flush is in flight; the pipe writer is untouchable
    private bool _writeDead;   // a flush faulted or reported the peer closed; the transport takes no more bytes, ever

    // Frames produced while a flush was in flight, in stage order. Drained into the pipe the
    // moment the flush completes, so wire order is exactly stage order.
    private byte[] _queued = [];
    private int _queuedUsed;

    // Callers parked on the pump's next turn, in the order they parked: woken when the flush AFTER the
    // current one finishes - the one that carries the queue. Callers who staged into the queue wait for
    // it, which keeps the two things a real flush provided: backpressure, and the yield that hands the
    // reactor back. Linked through the waiters themselves, so parking allocates nothing.
    private TurnWaiter? _turnHead;
    private TurnWaiter? _turnTail;

    // What a waiter woken by a turn that will never carry its bytes is told: as a TCP pipe writer reports a closed peer.
    private static readonly FlushResult PeerGone = new(isCanceled: false, isCompleted: true);

    private void Stage(ReadOnlySpan<byte> bytes)
    {
        if (_disposed || _writeDead)
        {
            return;   // a detached tail outlived the connection; there is nobody to send to
        }

        if (_flushing)
        {
            Enqueue(bytes);
        }
        else
        {
            _pipe.Output.Write(bytes);
            _staged = true;
        }
    }

    // Not async: a wait for the pump's next turn is returned as it is, on the caller's own waiter if it keeps one.
    private ValueTask<FlushResult> FlushAsync(TurnWaiter? waiter = null)
    {
        if (_disposed || _writeDead)
        {
            return default;
        }

        if (_flushing)
        {
            // The pump owns the pipe. If this caller queued bytes they leave on the pump's next
            // turn - wait for it, so the caller keeps real backpressure. With nothing queued there
            // is nothing to wait for.
            return _queuedUsed > 0 ? AwaitTurn(waiter ?? new TurnWaiter()) : default;
        }

        return _staged ? PumpAsync() : default;
    }

    // This caller becomes the pump: it drives turn after turn until a flush completes with the
    // queue empty. Everyone else who staged meanwhile waits for their turn.
    private async ValueTask<FlushResult> PumpAsync()
    {
        _flushing = true;
        TurnWaiter? turn = null;
        try
        {
            while (true)
            {
                _staged = false;

                // Waiters taken BEFORE the flush are the ones whose bytes are in it; anyone
                // arriving during the await parks for the turn after.
                turn = TakeTurn();

                FlushResult flushed = await _pipe.Output.FlushAsync();
                await new ReactorSwitch(_reactor);   // a pipe may complete its flush elsewhere: a default Pipe on the thread pool

                // Over TCP a dead peer never makes a flush throw: this is the only word of it before the read sees the
                // close. Everyone waiting is told as the turn ends.
                if (flushed.IsCompleted)
                {
                    _writeDead = true;
                    _failed = true;
                    return PeerGone;
                }

                // May resume writers inline; _flushing is still true, so anything they stage
                // lands in the queue and is picked up by the check just below.
                Wake(turn, default);
                turn = null;

                if (_queuedUsed == 0 || _disposed)
                {
                    return default;
                }

                _pipe.Output.Write(_queued.AsSpan(0, _queuedUsed));
                _queuedUsed = 0;
            }
        }
        catch
        {
            // The transport refused a write. Nothing staged can ever leave now, so later stages
            // must drop rather than throw from detached tails nobody observes.
            _writeDead = true;
            _failed = true;
            throw;
        }
        finally
        {
            if (_writeDead && OffReactor)
            {
                _ = EndTurnOnReactorAsync(turn);   // a faulted flush can end the pump on the thread that completed it
            }
            else
            {
                EndTurn(turn);
            }
        }
    }

    // Never strand a waiter: on a fault the turn it is waiting for will not come, and it has to wake to see
    // the connection is broken rather than hang forever - the turn whose own flush faulted included. Out of
    // line: a loop in a hot async method's finally costs it its optimized code.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private void EndTurn(TurnWaiter? faulted)
    {
        _flushing = false;
        FlushResult result = _writeDead || _disposed ? PeerGone : default;
        Wake(faulted, result);
        Wake(TakeTurn(), result);
        if (_writeDead)
        {
            ReleaseAllCreditWaiters();   // the fault reached a writer, so no teardown is on its way to them
        }
    }

    private async Task EndTurnOnReactorAsync(TurnWaiter? faulted)
    {
        try
        {
            await new ReactorSwitch(_reactor);
        }
        catch (ObjectDisposedException)
        {
            // The reactor has stopped, so nothing races the wake: it goes on here.
        }
        EndTurn(faulted);
    }

    private ValueTask<FlushResult> AwaitTurn(TurnWaiter waiter)
    {
        ValueTask<FlushResult> turn = waiter.Arm();
        if (!waiter.Enlisted)
        {
            waiter.Enlisted = true;
            if (_turnTail is null)
            {
                _turnHead = waiter;
            }
            else
            {
                _turnTail.Next = waiter;
            }
            _turnTail = waiter;
        }
        return turn;
    }

    // Taken out before any is woken: one resumed inline that parks again belongs to the next turn.
    private TurnWaiter? TakeTurn()
    {
        TurnWaiter? turn = _turnHead;
        _turnHead = null;
        _turnTail = null;
        return turn;
    }

    // Each link is read before its waiter wakes: one resumed inline may park again, relinking itself.
    private static void Wake(TurnWaiter? turn, FlushResult result)
    {
        while (turn is not null)
        {
            TurnWaiter? next = turn.Next;
            turn.Next = null;
            turn.Enlisted = false;
            turn.Release(result);
            turn = next;
        }
    }

    private void Enqueue(ReadOnlySpan<byte> bytes)
    {
        if (_queued.Length - _queuedUsed < bytes.Length)
        {
            long size = Math.Max(16 * 1024, (long)_queued.Length * 2);
            while (size < (long)_queuedUsed + bytes.Length)
            {
                size *= 2;
            }

            byte[] grown = ArrayPool<byte>.Shared.Rent((int)Math.Min(size, Array.MaxLength));
            _queued.AsSpan(0, _queuedUsed).CopyTo(grown);
            if (_queued.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_queued);
            }
            _queued = grown;
        }

        bytes.CopyTo(_queued.AsSpan(_queuedUsed));
        _queuedUsed += bytes.Length;
    }

    private void WriteSettings()
    {
        Span<byte> frame = stackalloc byte[FrameHeader.Size + (6 * 4)];
        new FrameHeader(6 * 4, FrameType.Settings, FrameFlags.None, 0).Write(frame);

        Span<byte> body = frame[FrameHeader.Size..];
        WriteSetting(body, 0, Http2Setting.EnablePush, 0);                                   // nothing routes a push
        WriteSetting(body, 1, Http2Setting.MaxConcurrentStreams, (uint)_options.MaxConcurrentStreams);
        WriteSetting(body, 2, Http2Setting.InitialWindowSize, (uint)_options.InitialWindowSize);
        WriteSetting(body, 3, Http2Setting.MaxFrameSize, (uint)_options.MaxFrameSize);

        Stage(frame);
    }

    private static void WriteSetting(Span<byte> body, int slot, ushort id, uint value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(body[(slot * 6)..], id);
        BinaryPrimitives.WriteUInt32BigEndian(body[((slot * 6) + 2)..], value);
    }

    private void WriteSettingsAck()
    {
        Span<byte> frame = stackalloc byte[FrameHeader.Size];
        new FrameHeader(0, FrameType.Settings, FrameFlags.Ack, 0).Write(frame);
        Stage(frame);
    }

    private void WriteWindowUpdate(int streamId, int increment)
    {
        // RFC 9113 6.9: the peer must treat an increment of 0 as a PROTOCOL_ERROR, on stream 0 by ending
        // the connection, so a caller left with nothing to credit sends nothing.
        if (increment <= 0)
        {
            return;
        }

        Span<byte> frame = stackalloc byte[FrameHeader.Size + 4];
        new FrameHeader(4, FrameType.WindowUpdate, FrameFlags.None, streamId).Write(frame);
        BinaryPrimitives.WriteUInt32BigEndian(frame[FrameHeader.Size..], (uint)increment);
        Stage(frame);
    }

    private void ResetStream(int streamId, uint errorCode)
    {
        if (_streams.Remove(streamId, out PendingRequest? pending))
        {
            Discard(pending);
        }

        Span<byte> frame = stackalloc byte[FrameHeader.Size + 4];
        new FrameHeader(4, FrameType.RstStream, FrameFlags.None, streamId).Write(frame);
        BinaryPrimitives.WriteUInt32BigEndian(frame[FrameHeader.Size..], errorCode);
        Stage(frame);
    }

    private void GoAway(uint errorCode)
    {
        Span<byte> frame = stackalloc byte[FrameHeader.Size + 8];
        new FrameHeader(8, FrameType.GoAway, FrameFlags.None, 0).Write(frame);
        BinaryPrimitives.WriteUInt32BigEndian(frame[FrameHeader.Size..], 0);       // last stream id
        BinaryPrimitives.WriteUInt32BigEndian(frame[(FrameHeader.Size + 4)..], errorCode);
        Stage(frame);
        _failed = true;
    }

    private static readonly byte[] StatusName = ":status"u8.ToArray();

    private void WriteResponse(int streamId, Http2Response response)
    {
        // Gone once the peer has reset the stream, and nothing may follow a reset (RFC 9113 5.1).
        if (!_responseWindows.Remove(streamId, out int window))
        {
            return;
        }

        WriteHeaders(streamId, response, endStream: response.Body.Length == 0);

        if (response.Body.Length > 0)
        {
            WriteData(streamId, response.Body.Span, window);
        }
    }

    private void WriteHeaders(int streamId, Http2Response response, bool endStream)
    {
        int capacity = HpackEncoder.MaxEncodedLength(StatusName.Length, 3);
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in response.Headers.AsSpan())
        {
            capacity += HpackEncoder.MaxEncodedLength(field.Key.Length, field.Value.Length);
        }

        byte[] block = ArrayPool<byte>.Shared.Rent(capacity);
        try
        {
            int written = 0;

            Span<byte> status = stackalloc byte[3];
            WriteStatus(response.Status, status);
            written += HpackEncoder.Encode(block.AsSpan(written), StatusName, status);

            foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in response.Headers.AsSpan())
            {
                written += HpackEncoder.Encode(block.AsSpan(written), field.Key.Span, field.Value.Span);
            }

            // A header block over MAX_FRAME_SIZE must continue in CONTINUATION frames; nothing else
            // may interleave on the connection between them.
            int offset = 0;
            bool first = true;

            while (offset < written || first)
            {
                int chunk = Math.Min(_peerMaxFrameSize, written - offset);
                bool last = offset + chunk >= written;

                FrameFlags flags = FrameFlags.None;
                if (last)
                {
                    flags |= FrameFlags.EndHeaders;
                    if (endStream)
                    {
                        flags |= FrameFlags.EndStream;
                    }
                }

                Span<byte> header = stackalloc byte[FrameHeader.Size];
                new FrameHeader(chunk, first ? FrameType.Headers : FrameType.Continuation, flags, streamId)
                    .Write(header);

                Stage(header);
                if (chunk > 0)
                {
                    Stage(block.AsSpan(offset, chunk));
                }

                offset += chunk;
                first = false;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(block);
        }
    }

    private void WriteData(int streamId, ReadOnlySpan<byte> body, int window)
    {
        int offset = 0;

        while (offset < body.Length)
        {
            // Bounded by the frame size AND by both flow-control windows: exceeding either is a
            // connection error, and the peer would be right to hang up.
            int chunk = Math.Min(_peerMaxFrameSize, body.Length - offset);
            chunk = Math.Min(chunk, Math.Min(_peerConnectionWindow, window));

            if (chunk <= 0)
            {
                // Out of credit: the rest waits for a WINDOW_UPDATE the way a streamed response does.
                _responseWindows[streamId] = window;
                ParkRest(streamId, body[offset..]);
                return;
            }

            bool last = offset + chunk >= body.Length;

            Span<byte> header = stackalloc byte[FrameHeader.Size];
            new FrameHeader(chunk, FrameType.Data, last ? FrameFlags.EndStream : FrameFlags.None, streamId)
                .Write(header);

            Stage(header);
            Stage(body.Slice(offset, chunk));

            _peerConnectionWindow -= chunk;
            window -= chunk;
            offset += chunk;
        }
    }

    // Copied into a writer, because the body is the handler's again once it has returned.
    private void ParkRest(int streamId, ReadOnlySpan<byte> rest)
    {
        Http2ResponseWriter writer = RentWriter(streamId);
        writer.ContinueBody();
        rest.CopyTo(writer.GetSpan(rest.Length));
        writer.Advance(rest.Length);

        _ = CompleteParkedAsync(writer);
    }

    private async Task CompleteParkedAsync(Http2ResponseWriter writer)
    {
        try
        {
            await writer.CompleteAsync();
        }
        catch
        {
            // FlushAsync has already marked the connection broken; the read loop sees it.
        }
        finally
        {
            _creditWaiters.Remove(writer.StreamId);
            _responseWindows.Remove(writer.StreamId);
            _writerPool.Push(writer);
        }
    }

    // Three ASCII digits: HTTP/2 has no reason phrase and every valid status is 100..599.
    private static void WriteStatus(int status, Span<byte> destination)
    {
        int clamped = status is >= 100 and <= 599 ? status : 500;
        destination[0] = (byte)('0' + (clamped / 100));
        destination[1] = (byte)('0' + ((clamped / 10) % 10));
        destination[2] = (byte)(clamped % 10 + '0');
    }
}
