using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;
// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Adapts the <see cref="TcpConnection"/> write API to a <see cref="PipeWriter"/>. Writes go straight
/// into the connection's slab; a parked flush chains onto the connection's value-task source
/// instead of an async state machine, so the adapter allocates nothing at steady state.
/// </summary>
public sealed class TcpConnectionPipeWriter : PipeWriter, IValueTaskSource<FlushResult>
{
    private readonly TcpConnection _conn;

    private ManualResetValueTaskSourceCore<FlushResult> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };
    private ValueTaskAwaiter _pendingFlush;
    private readonly Action _onFlushDone;

    private bool _completed;
    private bool _cancelRequested;
    private long _unflushed;

    public TcpConnectionPipeWriter(TcpConnection connection)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _onFlushDone = OnFlushDone;
    }

    public override bool CanGetUnflushedBytes => true;
    public override long UnflushedBytes => _unflushed;

    public override Memory<byte> GetMemory(int sizeHint = 0) => _conn.GetMemory(sizeHint);

    public override Span<byte> GetSpan(int sizeHint = 0) => _conn.GetSpan(sizeHint);

    public override void Advance(int bytes)
    {
        _unflushed += bytes;
        _conn.Advance(bytes);
    }

    public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        if (_cancelRequested)
        {
            _cancelRequested = false;
            return new ValueTask<FlushResult>(new FlushResult(isCanceled: true, isCompleted: _completed || _conn.IsClosed));
        }

        _unflushed = 0;
        ValueTask inner = _conn.FlushAsync();

        if (inner.IsCompletedSuccessfully)
        {
            return new ValueTask<FlushResult>(new FlushResult(isCanceled: false, isCompleted: _completed || _conn.IsClosed));
        }

        _core.Reset();
        _pendingFlush = inner.GetAwaiter();
        _pendingFlush.UnsafeOnCompleted(_onFlushDone);
        return new ValueTask<FlushResult>(this, _core.Version);
    }

    // Completion of a parked flush - runs inline on the reactor.
    private void OnFlushDone()
    {
        _pendingFlush.GetResult();

        bool canceled = _cancelRequested;
        _cancelRequested = false;

        // IsCompleted must include a closed connection, exactly as both synchronous paths above
        // report it. This one did not, so a flush that PARKED on a real send and was then released
        // by teardown told the caller the pipe was still open - and a caller doing the ordinary
        // "write until IsCompleted" loop kept producing against a peer that had gone, which is the
        // unbounded growth TcpConnection.DropStaged warns about.
        _core.SetResult(new FlushResult(canceled, _completed || _conn.IsClosed));
    }

    public override void CancelPendingFlush() => _cancelRequested = true;

    public override void Complete(Exception? exception = null) => _completed = true;

    // IValueTaskSource<FlushResult> - forwards to the core armed in FlushAsync.
    FlushResult IValueTaskSource<FlushResult>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<FlushResult>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<FlushResult>.OnCompleted(
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
