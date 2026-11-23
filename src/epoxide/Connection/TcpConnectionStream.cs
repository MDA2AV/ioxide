using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;
using epoxide.utils;

namespace epoxide;

/// <summary>
/// Adapts a <see cref="TcpConnection"/> to <see cref="Stream"/> so stream-based APIs - notably
/// <c>SslStream</c> for portable TLS - can run over the reactor. Reads copy recv slices into the
/// caller's buffer and return each buffer once drained; writes stage into the connection's slab and
/// flush. Allocation-free at steady state: read and write chain onto the connection's value-task
/// sources instead of an async state machine, preserving inline resume. The one cost the
/// <see cref="Stream"/> contract forces is a copy into the caller's buffer (the raw API and the pipe
/// adapter expose recv memory directly). Single reader, single writer, any thread; Dispose may come
/// from another thread while a read is parked or completing.
/// </summary>
public sealed class TcpConnectionStream : Stream, IValueTaskSource<int>, IValueTaskSource, IRecvBufferHolder
{
    private readonly TcpConnection _conn;

    // Read: lazy snapshot consumption - hold the current snapshot and the slice being copied out.
    private RecvSnapshot _snap;
    private bool _haveSnap;
    private SpscRecvRing.Item _cur;
    private int _curOffset;
    private bool _haveCur;
    private bool _eof;

    // Set by the reactor's reclaim at recycle: from then on a read still in flight takes nothing, since
    // what is left in the queue is the reactor's to return.
    private bool _reclaimed;

    // Guards the read state: the reader's calls are one at a time, but Dispose from another task and
    // the reactor's reclaim at recycle can come from other threads at the same moment as a read.
    private readonly Lock _sync = new();

    private ManualResetValueTaskSourceCore<int> _readCore = new() { RunContinuationsAsynchronously = false };
    private ValueTaskAwaiter<RecvSnapshot> _pendingRead;
    private Memory<byte> _readBuffer;
    private readonly Action _onReadReady;

    // Write: a parked flush chains onto the connection's flush source.
    private ManualResetValueTaskSourceCore<bool> _writeCore = new() { RunContinuationsAsynchronously = false };
    private ValueTaskAwaiter _pendingFlush;
    private readonly Action _onFlushDone;

    public TcpConnectionStream(TcpConnection connection)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));

        // The slice being copied out is held across calls and returned only once drained, so a
        // caller that stops mid-buffer strands it. Registering lets the reactor reclaim it at
        // recycle even when Dispose never runs.
        _conn.BufferHolder = this;
        _onReadReady = OnReadReady;
        _onFlushDone = OnFlushDone;
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>
    /// Returns the slice still being copied out, so a disposed stream does not hold a recv buffer
    /// until its connection is recycled.
    /// </summary>
    /// <remarks>
    /// This type inherited <see cref="Stream"/>'s do-nothing Dispose, which made the idiomatic
    /// spelling silently wrong: <c>new SslStream(new TcpConnectionStream(conn), leaveInnerStreamOpen:
    /// false)</c> disposes this on the way out and the held buffer stayed held anyway. An aborted
    /// handshake or a truncated record leaves one, which on a TLS listener is routine rather than
    /// exceptional.
    ///
    /// The reactor still reclaims at recycle (<see cref="IRecvBufferHolder"/>); this is the prompt
    /// path, and the release is idempotent, so the later reclaim finds nothing and does nothing.
    /// </remarks>
    protected override void Dispose(bool disposing)
    {
        lock (_sync)
        {
            ReleaseHeld();
        }
        base.Dispose(disposing);
    }

    void IRecvBufferHolder.ReleaseHeldBuffers()
    {
        lock (_sync)
        {
            _reclaimed = true;
            ReleaseHeld();
        }
    }

    // Under the lock, from Dispose or the reclaim at recycle, in either order or at once.
    private void ReleaseHeld()
    {
        // Terminal, like the reader's. _haveSnap otherwise survives with the PREVIOUS life's tail,
        // and a read after recycle would dequeue a stale entry, copy out another tenant's bytes, and
        // on draining it return a buffer the pool has already handed on.
        _haveSnap = false;
        _eof = true;

        if (_haveCur)
        {
            _haveCur = false;
            _conn.ReturnBuffer(in _cur);
        }
    }

    // -1 = nothing buffered, caller must await a fresh snapshot; >= 0 = bytes produced (0 = EOF).
    private int TryServe(Span<byte> destination)
    {
        lock (_sync)
        {
            return Serve(destination);
        }
    }

    // Under the lock.
    private int Serve(Span<byte> destination)
    {
        while (true)
        {
            if (_haveCur)
            {
                int n = Math.Min(_cur.Len - _curOffset, destination.Length);
                _cur.AsSpan().Slice(_curOffset, n).CopyTo(destination);
                _curOffset += n;
                if (_curOffset >= _cur.Len)
                {
                    _conn.ReturnBuffer(in _cur);
                    _haveCur = false;
                }
                return n;
            }

            if (_haveSnap)
            {
                if (_conn.TryGetItem(_snap, out _cur))
                {
                    _curOffset = 0;
                    _haveCur = _cur.HasBuffer;   // skip metadata-only items
                    continue;
                }

                _haveSnap = false;
                bool closed = _snap.IsClosed;
                _conn.ResetRead();
                if (closed)
                {
                    _eof = true;
                    return 0;
                }
                return -1;
            }

            return _eof ? 0 : -1;
        }
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return new ValueTask<int>(0);
        }

        while (true)
        {
            int served = TryServe(buffer.Span);
            if (served >= 0)
            {
                return new ValueTask<int>(served);
            }

            ValueTask<RecvSnapshot> pending = _conn.ReadAsync();
            if (!pending.IsCompletedSuccessfully)
            {
                _readBuffer = buffer;
                _readCore.Reset();
                _pendingRead = pending.GetAwaiter();
                _pendingRead.UnsafeOnCompleted(_onReadReady);
                return new ValueTask<int>(this, _readCore.Version);
            }

            TakeSnapshot(pending.Result);
        }
    }

    // A reclaimed stream takes no new snapshot: it would dequeue what recycle is returning.
    private void TakeSnapshot(in RecvSnapshot snapshot)
    {
        lock (_sync)
        {
            if (!_reclaimed)
            {
                _snap = snapshot;
                _haveSnap = true;
            }
        }
    }

    // Completion of a parked conn.ReadAsync - where the caller belongs (the connection's source decides).
    private void OnReadReady()
    {
        TakeSnapshot(_pendingRead.GetResult());

        while (true)
        {
            int served = TryServe(_readBuffer.Span);
            if (served >= 0)
            {
                _readCore.SetResult(served);
                return;
            }

            ValueTask<RecvSnapshot> pending = _conn.ReadAsync();
            if (!pending.IsCompletedSuccessfully)
            {
                _pendingRead = pending.GetAwaiter();
                _pendingRead.UnsafeOnCompleted(_onReadReady);
                return;
            }

            TakeSnapshot(pending.Result);
        }
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Span<byte> destination = _conn.GetSpan(1);   // full slab when empty
        if (buffer.Length > destination.Length)
        {
            return WriteMultiAsync(buffer);          // record larger than the slab - rare
        }

        buffer.Span.CopyTo(destination);
        _conn.Advance(buffer.Length);

        ValueTask flush = _conn.FlushAsync();
        if (flush.IsCompletedSuccessfully)
        {
            return ValueTask.CompletedTask;
        }

        _writeCore.Reset();
        _pendingFlush = flush.GetAwaiter();
        _pendingFlush.UnsafeOnCompleted(_onFlushDone);
        return new ValueTask(this, _writeCore.Version);
    }

    private void OnFlushDone()
    {
        _pendingFlush.GetResult();
        _writeCore.SetResult(true);
    }

    // Fallback for a single write larger than the slab: stage and flush in chunks.
    private async ValueTask WriteMultiAsync(ReadOnlyMemory<byte> buffer)
    {
        ReadOnlyMemory<byte> remaining = buffer;
        while (!remaining.IsEmpty)
        {
            Span<byte> destination = _conn.GetSpan(1);
            int n = Math.Min(destination.Length, remaining.Length);
            remaining.Span.Slice(0, n).CopyTo(destination);
            _conn.Advance(n);
            remaining = remaining.Slice(n);
            await _conn.FlushAsync();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task FlushAsync(CancellationToken cancellationToken) => _conn.FlushAsync().AsTask();

    public override void Flush() { }

    // Sync paths block on the async ones; SslStream's async APIs never reach these.
    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    // IValueTaskSource<int> - read; IValueTaskSource - write. The ValueTask's static type
    // (ValueTask<int> vs ValueTask) routes each call to the right core.
    int IValueTaskSource<int>.GetResult(short token) => _readCore.GetResult(token);
    ValueTaskSourceStatus IValueTaskSource<int>.GetStatus(short token) => _readCore.GetStatus(token);
    // Both cores complete from inside a connection operation's continuation, which already runs
    // where the caller belongs - so the caller resumes inline there.
    void IValueTaskSource<int>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) =>
        Continuations.OnCompletedInline(ref _readCore, continuation, state, token, flags);

    void IValueTaskSource.GetResult(short token) => _writeCore.GetResult(token);
    ValueTaskSourceStatus IValueTaskSource.GetStatus(short token) => _writeCore.GetStatus(token);
    void IValueTaskSource.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) =>
        Continuations.OnCompletedInline(ref _writeCore, continuation, state, token, flags);
}
