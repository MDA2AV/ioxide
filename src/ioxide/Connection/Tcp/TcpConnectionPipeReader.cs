using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;
using ioxide.utils;

namespace ioxide;

/// <summary>
/// Adapts the raw <see cref="TcpConnection"/> read API to a <see cref="PipeReader"/>, allocation-free
/// at steady state: a parked read chains onto the connection's value-task source (no async state
/// machine), recv slices live in pooled segments on a persistent chain, and consumption trims the
/// chain's front. Honors <c>examined</c>: when everything held has been examined, ReadAsync waits
/// for new bytes instead of returning the same data again.
/// </summary>
public sealed unsafe class TcpConnectionPipeReader : PipeReader, IValueTaskSource<ReadResult>, IRecvBufferHolder
{
    // One pooled object per held recv slice: sequence segment + reusable memory
    // manager + the original ring item (needed to return the buffer).
    private sealed class Slice : ReadOnlySequenceSegment<byte>
    {
        public readonly UnmanagedMemoryManager Manager = new(null, 0);
        public SpscRecvRing.Item Item;
        public Slice? NextSlice;

        public void Set(in SpscRecvRing.Item item)
        {
            Item = item;
            Manager.Reset(item.Ptr, item.Len, item.Bid, item.Gen);
            Memory = Manager.Memory;
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

    private readonly TcpConnection _conn;

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
    private ValueTaskAwaiter<RecvSnapshot> _pendingRead;
    private readonly Action _onRecvReady;

    private bool _completed;
    private bool _cancelRequested;
    private bool _connectionClosed;

    public TcpConnectionPipeReader(TcpConnection connection)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _onRecvReady = OnRecvReady;

        // So the reactor can reclaim at recycle what this reader dequeued and never gave back.
        _conn.BufferHolder = this;
    }

    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfCompleted();

        if (_cancelRequested)
        {
            _cancelRequested = false;
            return new ValueTask<ReadResult>(BuildResult(isCanceled: true));
        }

        // Unexamined bytes (or a closed connection) complete synchronously.
        if (_heldBytes > _examined || _connectionClosed)
        {
            return new ValueTask<ReadResult>(BuildResult(isCanceled: false));
        }

        // Everything held was examined - wait for new bytes.
        while (true)
        {
            ValueTask<RecvSnapshot> pending = _conn.ReadAsync();

            if (!pending.IsCompletedSuccessfully)
            {
                _core.Reset();
                _pendingRead = pending.GetAwaiter();
                _pendingRead.UnsafeOnCompleted(_onRecvReady);
                return new ValueTask<ReadResult>(this, _core.Version);
            }

            if (Ingest(pending.Result) || _connectionClosed || _cancelRequested)
            {
                bool canceled = _cancelRequested;
                _cancelRequested = false;
                return new ValueTask<ReadResult>(BuildResult(canceled));
            }
            // Spurious wake with nothing new: arm again.
        }
    }

    // Completion of a parked conn.ReadAsync - runs inline on the reactor.
    private void OnRecvReady()
    {
        RecvSnapshot snapshot = _pendingRead.GetResult();

        if (!Ingest(snapshot) && !_connectionClosed && !_cancelRequested)
        {
            // Nothing new: re-arm without completing the caller.
            while (true)
            {
                ValueTask<RecvSnapshot> pending = _conn.ReadAsync();

                if (!pending.IsCompletedSuccessfully)
                {
                    _pendingRead = pending.GetAwaiter();
                    _pendingRead.UnsafeOnCompleted(_onRecvReady);
                    return;
                }

                if (Ingest(pending.Result) || _connectionClosed || _cancelRequested)
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
    private bool Ingest(in RecvSnapshot snapshot)
    {
        bool any = false;

        while (_conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (!item.HasBuffer)
            {
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
            _connectionClosed = true;
        }

        return any;
    }

    private ReadResult BuildResult(bool isCanceled)
    {
        _lastSequence = _head == null
            ? default
            : new ReadOnlySequence<byte>(_head, _headConsumed, _tail!, _tail!.Memory.Length);

        return new ReadResult(_lastSequence, isCanceled, _connectionClosed);
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

        if (_heldBytes > _examined || _connectionClosed)
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
        // held sequence begins mid-segment (the head recv slice is partially consumed - a request
        // whose header and body arrive in one recv), GetOffset over-counts by _headConsumed. Rebase
        // by the sequence start so consumed/examined stay consistent with the relative
        // _heldBytes/_examined counters below. Without this, _heldBytes underflows negative and the
        // next ReadAsync parks forever waiting for bytes that already arrived (the hang seen on
        // chunked request bodies, which read again for the terminating chunk).
        long startOffset = _lastSequence.GetOffset(_lastSequence.Start);
        long consumedBytes = _lastSequence.GetOffset(consumed) - startOffset;
        long examinedBytes = _lastSequence.GetOffset(examined) - startOffset;
        if (examinedBytes < consumedBytes)
        {
            examinedBytes = consumedBytes;
        }

        // Trim fully-consumed slices off the front; their buffers go back to the ring.
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
    /// Hand every held slice's buffer back to the ring and forget the chain.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="Complete"/>, and by the reactor at recycle for a reader whose caller
    /// never completed it (<see cref="TcpConnection.ReleaseHeldRecvBuffers"/>). Idempotent: once the
    /// chain is empty it does nothing, so the ordinary path of Complete-then-recycle returns each
    /// buffer exactly once.
    /// </remarks>
    private void ReleaseHeld()
    {
        // Does NOT de-register: completing leaves a parked read armed, so items can still be
        // ingested after this runs and the holder has to stay reachable. Clear() drops the slot.
        //
        // Terminal, so a reader kept past its handler fails instead of arming against the recycled
        // connection's NEXT tenant and handing out another peer's bytes.
        _completed = true;
        _connectionClosed = true;
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
