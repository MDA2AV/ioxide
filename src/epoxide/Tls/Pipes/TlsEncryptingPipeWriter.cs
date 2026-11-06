using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;
using epoxide.utils;

namespace epoxide.tls;

/// <summary>
/// The write half when the kernel is <b>not</b> encrypting: plaintext is staged here, BoringSSL turns
/// it into records on flush, and the records go into the connection's slab.
///
/// The counterpart is <see cref="TcpConnectionPipeWriter"/>, which is what a kTLS-TX connection
/// uses - there, plaintext goes straight into the slab and the kernel makes the records on send.
/// This class is the entire difference between the two worlds on the write side, and the reason
/// <see cref="TlsConnectionDualPipe"/> can be a composer rather than a hierarchy.
/// </summary>
/// <remarks>
/// The staging buffer is the copy kTLS avoids. SSL_write needs the plaintext contiguously, so it
/// cannot be handed the slab directly - but BIO_read afterwards writes the records straight into
/// the slab, so there is exactly one extra pass over the bytes, not two.
///
/// Any thread, one writer at a time. A flush encrypts and sends where it is called, under the
/// session's lock for the encrypt, so it may run on one thread while the session's reader decrypts
/// on another. ioxide hands a flush made off its reactor to the reactor instead, because there the
/// reactor is the one thread a session's calls may be made on.
/// </remarks>
public sealed class TlsEncryptingPipeWriter : PipeWriter, IValueTaskSource<FlushResult>
{
    private readonly TcpConnection _conn;
    private readonly TlsSession _tls;

    private byte[] _staging;
    private int _staged;
    private bool _completed;
    private bool _cancelRequested;

    // One flush at a time, so one reused completion serves every flush that has to wait.
    private ManualResetValueTaskSourceCore<FlushResult> _core = new()
    {
        RunContinuationsAsynchronously = false,
    };
    private ValueTaskAwaiter _pendingFlush;
    private readonly Action _onFlushDone;

    public TlsEncryptingPipeWriter(TcpConnection connection, TlsSession session, int initialCapacity = 16 * 1024)
    {
        _conn = connection ?? throw new ArgumentNullException(nameof(connection));
        _tls = session ?? throw new ArgumentNullException(nameof(session));
        _staging = ArrayPool<byte>.Shared.Rent(Math.Max(initialCapacity, 4 * 1024));
        _onFlushDone = OnFlushDone;
    }

    public override bool CanGetUnflushedBytes => true;

    public override long UnflushedBytes => _staged;

    public override Memory<byte> GetMemory(int sizeHint = 0)
    {
        ThrowIfCompleted();
        Ensure(sizeHint);
        return _staging.AsMemory(_staged);
    }

    public override Span<byte> GetSpan(int sizeHint = 0)
    {
        ThrowIfCompleted();
        Ensure(sizeHint);
        return _staging.AsSpan(_staged);
    }

    public override void Advance(int bytes)
    {
        ThrowIfCompleted();
        _staged += bytes;
    }

    public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfCompleted();

        if (TryFlush(out FlushResult result))
        {
            return new ValueTask<FlushResult>(result);
        }

        _core.Reset();
        _pendingFlush.UnsafeOnCompleted(_onFlushDone);
        return new ValueTask<FlushResult>(this, _core.Version);
    }

    // Encrypts what is staged and starts the connection's flush: true, with its result, when that
    // finished at once; false when it waits in _pendingFlush.
    private bool TryFlush(out FlushResult result)
    {
        if (_cancelRequested)
        {
            _cancelRequested = false;
            result = new FlushResult(isCanceled: true, isCompleted: _completed || _conn.IsClosed);
            return true;
        }

        if (_staged > 0)
        {
            _tls.WriteEncrypted(_conn, _staging.AsSpan(0, _staged));
            _staged = 0;
        }

        ValueTask inner = _conn.FlushAsync();
        if (inner.IsCompletedSuccessfully)
        {
            result = new FlushResult(isCanceled: false, isCompleted: _completed || _conn.IsClosed);
            return true;
        }

        _pendingFlush = inner.GetAwaiter();
        result = default;
        return false;
    }

    // Completion of a flush that waited - where the caller belongs (the connection's source decides).
    private void OnFlushDone()
    {
        try
        {
            _pendingFlush.GetResult();
        }
        catch (Exception e)
        {
            _core.SetException(e);
            return;
        }

        // Report the cancel on the flush it was aimed at, and clear it. CancelPendingFlush cannot
        // wake a flush already parked on the connection's send - only the completion or a close
        // releases that - but leaving the flag set was worse than not honouring it: the NEXT
        // FlushAsync saw it, returned IsCanceled before reaching the encrypt block, and dropped the
        // plaintext staged for it. A flush nobody cancelled was cancelled, silently and lossily.
        bool canceled = _cancelRequested;
        _cancelRequested = false;
        _core.SetResult(new FlushResult(canceled, _completed || _conn.IsClosed));
    }

    public override void CancelPendingFlush() => _cancelRequested = true;

    public override void Complete(Exception? exception = null)
    {
        if (_completed)
        {
            return;
        }
        _completed = true;

        // Complete commits: advanced-but-unflushed plaintext is encrypted into the slab, exactly
        // as the kTLS-mode TcpConnectionPipeWriter leaves its advanced bytes there - either way
        // the connection's final flush carries them out. A faulted completion discards instead;
        // committing half a response on an error would dress a failure up as a short success.
        if (exception is null && _staged > 0)
        {
            try
            {
                _tls.WriteEncrypted(_conn, _staging.AsSpan(0, _staged));
            }
            catch (Exception e) when (e is IOException or InvalidOperationException)
            {
                // Best effort, because Complete is a notification and PipeWriter forbids it from
                // throwing. Encrypting can fail - the session is already dead, from a decrypt fault,
                // a peer that vanished, or a disposal - and on a connection being torn down there is
                // nobody left to tell. Letting it escape aborted the caller's teardown mid-way and
                // leaked the SSL, its BIOs and the handle rooting the session.
                // Or a flush in flight refuses the slab (InvalidOperationException): the records
                // stay in the write BIO and go out ahead of the close_notify, or neither does.
            }
        }
        _staged = 0;

        if (_staging.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_staging);
            _staging = [];
        }
    }

    // After Complete the staging buffer is back in the pool and the session may already be
    // disposed. Fail as a managed exception on the offending caller, rather than encrypting from a
    // buffer someone else now holds.
    private void ThrowIfCompleted()
    {
        if (_completed)
        {
            throw new InvalidOperationException("The PipeWriter is completed; no further writes are allowed.");
        }
    }

    private void Ensure(int sizeHint)
    {
        int want = Math.Max(sizeHint, 1);
        if (_staging.Length - _staged >= want)
        {
            return;
        }

        // A TLS record carries at most 16 KiB of plaintext, but a caller may stage far more than
        // one record before flushing - SSL_write splits it into records itself.
        int size = Math.Max(_staging.Length * 2, _staged + want);
        byte[] grown = ArrayPool<byte>.Shared.Rent(size);
        _staging.AsSpan(0, _staged).CopyTo(grown);
        ArrayPool<byte>.Shared.Return(_staging);
        _staging = grown;
    }

    // IValueTaskSource<FlushResult> - forwards to the core armed in FlushAsync.
    FlushResult IValueTaskSource<FlushResult>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<FlushResult>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<FlushResult>.OnCompleted(
        Action<object?> continuation,
        object? state,
        short token,
        ValueTaskSourceOnCompletedFlags flags)
    {
        // Completed from inside the connection flush's continuation, which already runs where the
        // caller belongs - so the caller resumes inline there.
        Continuations.OnCompletedInline(ref _core, continuation, state, token, flags);
    }
}
