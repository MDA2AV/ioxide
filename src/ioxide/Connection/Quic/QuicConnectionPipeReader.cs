using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;

namespace ioxide;

/// <summary>
/// Adapts one stream of the raw <see cref="QuicConnection"/> read API to a <see cref="PipeReader"/> -
/// QUIC's mirror of <see cref="TcpConnectionPipeReader"/>, same design, no shared code. Allocation-free
/// at steady state: a parked read chains onto the connection's value-task source (no async state
/// machine), delivered items live in pooled segments on a persistent chain, and consumption trims the
/// chain's front. Honors <c>examined</c>: when everything held has been examined, ReadAsync waits for
/// new bytes instead of returning the same data again.
///
/// Single-stream contract: the reader binds to the constructor's stream id, or auto-binds (-1) to the
/// first stream an item arrives on. Items for other streams are returned to the pool and DROPPED -
/// this adapter is the connection queue's sole consumer, so nothing else could have read them.
/// Fin, Closed or Reset on the bound stream (or connection close) completes the reader; StopSending
/// only concerns the write side and is ignored here.
/// </summary>
public sealed class QuicConnectionPipeReader : PipeReader, IValueTaskSource<ReadResult>, IRecvBufferHolder
{
    // One pooled object per held item: sequence segment over the item's pooled array plus the
    // original item (needed to return the buffer).
    private sealed class Slice : ReadOnlySequenceSegment<byte>
    {
        public QuicRecvRing.Delivery Item;
        public Slice? NextSlice;

        public void Set(in QuicRecvRing.Delivery item)
        {
            Item = item;
            Memory = item.Buf!.AsMemory(0, item.Len);   // only byte-carrying items are chained
            Next = null;
            NextSlice = null;
            RunningIndex = 0;
        }

        public void Link(Slice next)
        {
            next.RunningIndex = RunningIndex + Memory.Length;
            Next = next;
            NextSlice = next;
        }
    }

    private readonly QuicConnection _conn;
    private readonly QuicStreamBinding _binding;

    // Held slices, oldest first. _headConsumed is the consumed prefix of the
    // head slice; consumption never mutates segments, it moves the sequence start.
    private Slice? _head;
    private Slice? _tail;
    private int _headConsumed;
    private long _heldBytes;    // unconsumed bytes across the chain
    private long _examined;     // of those, how many the caller already examined

    private readonly Stack<Slice> _pool = new();
    private ReadOnlySequence<byte> _lastSequence;

    // Parked-read plumbing: chain onto the connection's IVTS, complete our own.
    private ManualResetValueTaskSourceCore<ReadResult> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };
    private ValueTaskAwaiter<QuicRecvSnapshot> _pendingRead;
    private readonly Action _onRecvReady;

    private bool _completed;
    private bool _cancelRequested;
    private bool _ended;   // bound stream finished (fin/closed/reset) or the connection closed

    public QuicConnectionPipeReader(QuicConnection connection, long streamId = -1)
        : this(connection, new QuicStreamBinding { StreamId = streamId })
    {
    }

    internal QuicConnectionPipeReader(QuicConnection connection, QuicStreamBinding binding)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _binding = binding;

        // So the connection can reclaim at teardown what this reader dequeued and never gave back.
        _conn.BufferHolder = this;
        _onRecvReady = OnRecvReady;
    }

    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfCompleted();

        if (_cancelRequested)
        {
            _cancelRequested = false;
            return new ValueTask<ReadResult>(BuildResult(isCanceled: true));
        }

        // Unexamined bytes (or a finished stream) complete synchronously.
        if (_heldBytes > _examined || _ended)
        {
            return new ValueTask<ReadResult>(BuildResult(isCanceled: false));
        }

        // Everything held was examined - wait for new bytes.
        while (true)
        {
            ValueTask<QuicRecvSnapshot> pending = _conn.ReadAsync();

            if (!pending.IsCompletedSuccessfully)
            {
                _core.Reset();
                _pendingRead = pending.GetAwaiter();
                _pendingRead.UnsafeOnCompleted(_onRecvReady);
                return new ValueTask<ReadResult>(this, _core.Version);
            }

            if (Ingest(pending.Result) || _ended || _cancelRequested)
            {
                bool canceled = _cancelRequested;
                _cancelRequested = false;
                return new ValueTask<ReadResult>(BuildResult(canceled));
            }
            // Spurious wake with nothing new (e.g. only foreign-stream items): arm again.
        }
    }

    // Completion of a parked conn.ReadAsync - runs inline on the reactor.
    private void OnRecvReady()
    {
        QuicRecvSnapshot snapshot = _pendingRead.GetResult();

        if (!Ingest(snapshot) && !_ended && !_cancelRequested)
        {
            // Nothing new: re-arm without completing the caller.
            while (true)
            {
                ValueTask<QuicRecvSnapshot> pending = _conn.ReadAsync();

                if (!pending.IsCompletedSuccessfully)
                {
                    _pendingRead = pending.GetAwaiter();
                    _pendingRead.UnsafeOnCompleted(_onRecvReady);
                    return;
                }

                if (Ingest(pending.Result) || _ended || _cancelRequested)
                {
                    break;
                }
            }
        }

        bool canceled = _cancelRequested;
        _cancelRequested = false;
        _core.SetResult(BuildResult(canceled));
    }

    // Drain a snapshot into the chain. Returns true if any bytes were added.
    private bool Ingest(in QuicRecvSnapshot snapshot)
    {
        bool any = false;

        while (_conn.TryGetDelivery(in snapshot, out QuicRecvRing.Delivery item))
        {
            long bound = _binding.StreamId;
            if (bound == -1)
            {
                _binding.StreamId = bound = item.StreamId;
            }

            if (item.StreamId != bound)
            {
                _conn.ReturnBuffer(in item);   // single-stream contract: foreign streams are dropped
                continue;
            }

            if (item.Kind == QuicStreamEvent.Closed || item.Kind == QuicStreamEvent.Reset)
            {
                _ended = true;
                continue;
            }
            if (item.Kind == QuicStreamEvent.StopSending)
            {
                continue;   // egress-side signal, not part of the incoming byte stream
            }

            if (item.Fin)
            {
                _ended = true;
            }

            if (item.Len == 0)
            {
                _conn.ReturnBuffer(in item);   // fin-only, no bytes to chain
                continue;
            }

            Slice slice = _pool.TryPop(out Slice? pooled) ? pooled : new Slice();
            slice.Set(in item);

            if (_tail == null)
            {
                _head = _tail = slice;
                _headConsumed = 0;
            }
            else
            {
                _tail.Link(slice);
                _tail = slice;
            }

            _heldBytes += item.Len;
            any = true;
        }

        _conn.ResetRead();

        if (snapshot.IsClosed)
        {
            _ended = true;
        }

        return any;
    }

    private ReadResult BuildResult(bool isCanceled)
    {
        _lastSequence = _head == null
            ? default
            : new ReadOnlySequence<byte>(_head, _headConsumed, _tail!, _tail!.Memory.Length);

        return new ReadResult(_lastSequence, isCanceled, _ended);
    }

    public override bool TryRead(out ReadResult result)
    {
        ThrowIfCompleted();

        if (_cancelRequested)
        {
            _cancelRequested = false;
            result = BuildResult(isCanceled: true);
            return true;
        }

        if (_heldBytes > _examined || _ended)
        {
            result = BuildResult(isCanceled: false);
            return true;
        }

        result = default;
        return false;
    }

    public override void AdvanceTo(SequencePosition consumed) => AdvanceTo(consumed, consumed);

    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
    {
        if (_head == null)
        {
            return;
        }

        // GetOffset measures from the start *segment*, not the sequence's logical start. When the
        // held sequence begins mid-segment (the head slice is partially consumed), GetOffset
        // over-counts by _headConsumed; rebase by the sequence start so consumed/examined stay
        // consistent with the relative _heldBytes/_examined counters below (same hang otherwise as
        // the TCP reader saw on chunked request bodies).
        long startOffset = _lastSequence.GetOffset(_lastSequence.Start);
        long consumedBytes = _lastSequence.GetOffset(consumed) - startOffset;
        long examinedBytes = _lastSequence.GetOffset(examined) - startOffset;
        if (examinedBytes < consumedBytes)
        {
            examinedBytes = consumedBytes;
        }

        // Trim fully-consumed slices off the front; their buffers go back to the pool.
        long remaining = consumedBytes;
        while (remaining > 0 && _head != null)
        {
            int available = _head.Memory.Length - _headConsumed;

            if (remaining >= available)
            {
                _conn.ReturnBuffer(in _head.Item);

                Slice released = _head;
                _head = released.NextSlice;
                if (_head == null)
                {
                    _tail = null;
                }
                _headConsumed = 0;
                _pool.Push(released);

                remaining -= available;
            }
            else
            {
                _headConsumed += (int)remaining;
                remaining = 0;
            }
        }

        _heldBytes -= consumedBytes;
        _examined = Math.Min(examinedBytes - consumedBytes, _heldBytes);
    }

    public override void CancelPendingRead() => _cancelRequested = true;

    public override void Complete(Exception? exception = null)
    {
        if (_completed)
        {
            return;
        }

        _completed = true;

        ReleaseHeld();
    }

    void IRecvBufferHolder.ReleaseHeldBuffers() => ReleaseHeld();

    /// <summary>
    /// Hand every held item's pooled buffer back and forget the chain.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="Complete"/> and by the connection at teardown
    /// (<see cref="QuicConnection.ReleaseHeldRecvBuffers"/>). Idempotent: the second walk finds an
    /// empty chain, so each item is returned exactly once however the two are ordered.
    ///
    /// Does not de-register and ends terminal, for the reasons on
    /// <see cref="TcpConnectionPipeReader"/>.
    /// </remarks>
    private void ReleaseHeld()
    {
        _completed = true;
        _ended = true;
        _lastSequence = default;

        while (_head != null)
        {
            _conn.ReturnBuffer(in _head.Item);
            Slice released = _head;
            _head = released.NextSlice;
            _pool.Push(released);
        }

        _tail = null;
        _headConsumed = 0;
        _heldBytes = 0;
        _examined = 0;
    }

    private void ThrowIfCompleted()
    {
        if (_completed)
        {
            throw new InvalidOperationException("Reading is not allowed after the reader was completed.");
        }
    }

    // IValueTaskSource<ReadResult> - forwards to the core armed in ReadAsync.
    ReadResult IValueTaskSource<ReadResult>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<ReadResult>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<ReadResult>.OnCompleted(
        Action<object?> continuation,
        object? state,
        short token,
        ValueTaskSourceOnCompletedFlags flags)
    {
        // Completes on the reactor thread only - strip the context-post so resumes stay inline
        // (see ReactorSynchronizationContext).
        _core.OnCompleted(continuation, state, token,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }
}
