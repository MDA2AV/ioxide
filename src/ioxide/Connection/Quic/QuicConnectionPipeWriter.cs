using System.Buffers;
using System.IO.Pipelines;

namespace ioxide;

/// <summary>
/// Adapts one stream of the <see cref="QuicConnection"/> write API to a <see cref="PipeWriter"/> -
/// QUIC's mirror of <see cref="TcpConnectionPipeWriter"/>, no shared code. Simpler than TCP's:
/// there is no flush to await (framing, encryption and pacing belong to the engine), so writes
/// stage in a pooled buffer and <see cref="FlushAsync"/> is one synchronous
/// <see cref="QuicConnection.SendStream"/> call. Backpressure is the engine's retained-send cap,
/// not a parked flush. <see cref="Complete"/> sends fin (half-close); a faulted Complete discards
/// staged bytes and resets the stream (application error 0).
///
/// The stream id comes from the constructor, or from the shared binding when the dual pipe's
/// reader auto-binds - flushing bytes before any stream is bound throws. Reactor thread only,
/// like SendStream itself (the inline-resume handler already runs there).
/// </summary>
public sealed class QuicConnectionPipeWriter : PipeWriter
{
    private readonly QuicConnection _conn;
    private readonly QuicStreamBinding _binding;

    private byte[]? _buf;   // pooled staging; SendStream copies into engine-owned chunks, so it is reused across flushes
    private int _written;
    private bool _completed;
    private bool _cancelRequested;

    public QuicConnectionPipeWriter(QuicConnection connection, long streamId)
        : this(connection, new QuicStreamBinding { StreamId = streamId })
    {
        ArgumentOutOfRangeException.ThrowIfNegative(streamId);
    }

    internal QuicConnectionPipeWriter(QuicConnection connection, QuicStreamBinding binding)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _binding = binding;
    }

    public override bool CanGetUnflushedBytes => true;
    public override long UnflushedBytes => _written;

    public override Memory<byte> GetMemory(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buf!.AsMemory(_written);
    }

    public override Span<byte> GetSpan(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buf!.AsSpan(_written);
    }

    public override void Advance(int bytes)
    {
        ThrowIfCompleted();
        _written += bytes;
    }

    public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        if (_cancelRequested)
        {
            _cancelRequested = false;
            return new ValueTask<FlushResult>(new FlushResult(isCanceled: true, isCompleted: _completed));
        }

        FlushStaged(fin: false);
        return new ValueTask<FlushResult>(new FlushResult(isCanceled: false, isCompleted: _completed));
    }

    private void FlushStaged(bool fin)
    {
        long streamId = _binding.StreamId;
        if (streamId < 0)
        {
            if (_written > 0)
            {
                throw new InvalidOperationException(
                    "No QUIC stream bound yet - read from the peer first (auto-bind) or construct with an explicit stream id.");
            }
            return;   // no stream and nothing staged - nothing to send or finish
        }

        if (_written == 0 && !fin)
        {
            return;
        }

        ReadOnlySpan<byte> data = _written > 0 ? _buf!.AsSpan(0, _written) : default;
        _conn.SendStream(streamId, data, fin);
        _written = 0;
    }

    public override void CancelPendingFlush() => _cancelRequested = true;

    public override void Complete(Exception? exception = null)
    {
        if (_completed)
        {
            return;
        }

        _completed = true;

        if (exception is null)
        {
            FlushStaged(fin: true);
        }
        else
        {
            _written = 0;   // faulted: the staged bytes never reach the wire, and no clean fin
            if (_binding.StreamId >= 0)
            {
                _conn.ResetStream(_binding.StreamId, 0);   // nor a stream left open and owed
            }
        }

        if (_buf is not null)
        {
            ArrayPool<byte>.Shared.Return(_buf);
            _buf = null;
        }
    }

    private void Ensure(int sizeHint)
    {
        ThrowIfCompleted();

        if (sizeHint < 1)
        {
            sizeHint = 1;   // PipeWriter contract: 0 means "some space"
        }

        if (_buf is null)
        {
            _buf = ArrayPool<byte>.Shared.Rent(Math.Max(sizeHint, 4096));
            return;
        }

        if (_buf.Length - _written >= sizeHint)
        {
            return;
        }

        byte[] grown = ArrayPool<byte>.Shared.Rent(Math.Max(_written + sizeHint, _buf.Length * 2));
        _buf.AsSpan(0, _written).CopyTo(grown);
        ArrayPool<byte>.Shared.Return(_buf);
        _buf = grown;
    }

    private void ThrowIfCompleted()
    {
        if (_completed)
        {
            throw new InvalidOperationException("Writing is not allowed after the writer was completed.");
        }
    }
}
