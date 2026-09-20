using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;

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
    private bool _writeDead;   // a flush faulted; the transport takes no more bytes, ever

    // Frames produced while a flush was in flight, in stage order. Drained into the pipe the
    // moment the flush completes, so wire order is exactly stage order.
    private byte[] _queued = [];
    private int _queuedUsed;

    // Completed when the flush AFTER the current one finishes - the one that carries the queue.
    // Callers who staged into the queue await this, which keeps the two things a real flush
    // provided: backpressure, and the yield that hands the reactor back.
    private TaskCompletionSource? _turnWaiter;

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

    private async ValueTask FlushAsync()
    {
        if (_disposed || _writeDead)
        {
            return;
        }

        if (_flushing)
        {
            // The pump owns the pipe. If this caller queued bytes they leave on the pump's next
            // turn - await it, so the caller keeps real backpressure. With nothing queued there
            // is nothing to wait for.
            if (_queuedUsed > 0)
            {
                await TurnAsync();
            }
            return;
        }

        if (!_staged)
        {
            return;
        }

        // This caller becomes the pump: it drives turn after turn until a flush completes with
        // the queue empty. Everyone else who staged meanwhile is parked on TurnAsync.
        _flushing = true;
        try
        {
            while (true)
            {
                _staged = false;

                // Waiters captured BEFORE the flush are the ones whose bytes are in it; anyone
                // arriving during the await parks a fresh waiter for the turn after.
                TaskCompletionSource? turn = _turnWaiter;
                _turnWaiter = null;

                await _pipe.Output.FlushAsync();

                // May resume writers inline; _flushing is still true, so anything they stage
                // lands in the queue and is picked up by the check just below.
                turn?.TrySetResult();

                if (_queuedUsed == 0 || _disposed)
                {
                    return;
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
            _flushing = false;
            // Never strand a waiter: on a fault the turn it is waiting for will not come, and it
            // has to wake to see the connection is broken rather than hang forever.
            _turnWaiter?.TrySetResult();
            _turnWaiter = null;
        }
    }

    private Task TurnAsync()
    {
        _turnWaiter ??= new TaskCompletionSource();
        return _turnWaiter.Task;
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
        Span<byte> frame = stackalloc byte[FrameHeader.Size + 4];
        new FrameHeader(4, FrameType.WindowUpdate, FrameFlags.None, streamId).Write(frame);
        BinaryPrimitives.WriteUInt32BigEndian(frame[FrameHeader.Size..], (uint)increment);
        Stage(frame);
    }

    private void ResetStream(int streamId, uint errorCode)
    {
        if (_streams.Remove(streamId, out PendingRequest? pending))
        {
            pending.Dispose();
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
        WriteHeaders(streamId, response, endStream: response.Body.Length == 0);

        if (response.Body.Length > 0)
        {
            WriteData(streamId, response.Body.Span);
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

    private void WriteData(int streamId, ReadOnlySpan<byte> body)
    {
        int offset = 0;

        while (offset < body.Length)
        {
            // Bounded by the frame size AND by both flow-control windows: exceeding either is a
            // connection error, and the peer would be right to hang up.
            int chunk = Math.Min(_peerMaxFrameSize, body.Length - offset);
            chunk = Math.Min(chunk, _peerConnectionWindow);

            if (chunk <= 0)
            {
                // Out of credit. The rest is dropped rather than queued: this server buffers whole
                // responses, and a 1 MiB default window makes running out mean the peer has stopped
                // reading entirely. Streaming responses would need a send queue here instead.
                ResetStream(streamId, Http2Error.FlowControlError);
                return;
            }

            bool last = offset + chunk >= body.Length;

            Span<byte> header = stackalloc byte[FrameHeader.Size];
            new FrameHeader(chunk, FrameType.Data, last ? FrameFlags.EndStream : FrameFlags.None, streamId)
                .Write(header);

            Stage(header);
            Stage(body.Slice(offset, chunk));

            _peerConnectionWindow -= chunk;
            offset += chunk;
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
