using System.Threading.Tasks.Sources;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// The connection's flush lifecycle: hand the buffered response to the reactor for sending and park the
/// caller on an <see cref="IValueTaskSource"/> until that send completes. The reactor chooses a plain
/// SEND for a contiguous response or a vectored SENDMSG for a segmented one (TcpConnection.Write.Segmented.cs).
/// </summary>
public sealed unsafe partial class TcpConnection : IValueTaskSource
{
    private ManualResetValueTaskSourceCore<bool> _flushSignal = new()
    {
        RunContinuationsAsynchronously = false,
    };
    // 0 idle, 1 armed (queued for the reactor), 2 with the kernel - which may read the slab until the
    // send's final completion, so only that completion may end a flush in state 2 (#221, #244).
    private int _flushArmed;
    private int _flushInProgress;

    internal bool FlushSubmitted => Volatile.Read(ref _flushArmed) == 2;

    /// <summary>
    /// The reactor's cached clock at the moment a flush was handed over. The sweep reads it against
    /// <see cref="TcpOptions.SendTimeoutMs"/> while the flush is outstanding, and afterwards as the
    /// last time the server sent, which restarts the read clock.
    ///
    /// Written on every arm and never cleared, because clearing it would put a store on
    /// CompleteFlush, which is the hottest path in the server.
    /// </summary>
    internal long FlushArmedMs;

    /// <summary>
    /// Whether a flush is outstanding - which is what tells the reactor's sweep that this
    /// connection is sending rather than waiting on its peer, so the send clock governs it and the
    /// read one does not. Read rather than <see cref="FlushArmedMs"/> being non-zero, so the stamp
    /// never has to double as a flag.
    /// </summary>
    internal bool FlushOutstanding => Volatile.Read(ref _flushInProgress) != 0;

    public ValueTask FlushAsync()
    {
        if (Volatile.Read(ref _closed) == 1)
        {
            if (!FlushSubmitted)
            {
                DropStaged();
            }

            return default;
        }

        // One flush at a time: the parked caller waits on _flushSignal, a single
        // ManualResetValueTaskSourceCore with room for exactly one continuation. A second flush
        // would hand a second awaiter the same token and the source would throw on the second
        // OnCompleted instead - deeper, and on the reactor thread. An application that flushes
        // twice concurrently has a bug in its own write serialization, and hearing about it here
        // is the point.
        if (Interlocked.Exchange(ref _flushInProgress, 1) == 1)
        {
            throw new InvalidOperationException("FlushAsync already in progress.");
        }

        return FlushCore();
    }

    /// <summary>
    /// The teardown counterpart of <see cref="FlushAsync"/>: flush what is staged, but say nothing
    /// and send nothing when a flush is already in flight.
    /// </summary>
    /// <remarks>
    /// For the internal callers that flush on the application's behalf while tearing a connection
    /// down, <see cref="ioxide.tls.TlsConnectionDualPipe.DisposeAsync"/> above all. They flush
    /// unconditionally because a handler that wrote its response and never flushed has nothing else
    /// to carry it out, and against a flush the application left in flight that unconditional call
    /// threw out of a finally and faulted the connection handler (#234).
    ///
    /// Skipping loses nothing: while _flushInProgress is set every GetSpan/GetMemory/Advance/Write
    /// is refused (TcpConnection.Write.cs), so nothing can have entered the slab since the
    /// in-flight flush armed, and that flush snapshotted everything that was already there. A
    /// second flush would compute target == 0 and return anyway.
    ///
    /// Not the same as relaxing the guard above. A caller that means "send my bytes" must still
    /// hear that they were not sent.
    /// </remarks>
    internal ValueTask FlushIfIdleAsync()
    {
        if (Volatile.Read(ref _closed) == 1)
        {
            if (!FlushSubmitted)
            {
                DropStaged();
            }

            return default;
        }

        if (Interlocked.Exchange(ref _flushInProgress, 1) == 1)
        {
            return default;
        }

        return FlushCore();
    }

    // The connection is already torn down, so the staged bytes are dropped rather than kept:
    // nothing will ever send them, and leaving the tail where it was made every later write append
    // to a slab that only ever grew - a writer that keeps producing against a peer that has gone
    // reaches gigabytes, because doubling the slab is the one thing that never fails.
    //
    // Segmented needs its own release, and zeroing the tail alone did nothing for it: once
    // _inOverflow is set every write is routed to overflow rather than to the slab, so the
    // growth continued one pooled slab per fill. Clear() has always released them on recycle;
    // this is the same release on the path that never reaches recycle.
    private void DropStaged()
    {
        WriteTail = 0;
        if (_ovCount > 0)
        {
            ReleaseOverflow();
        }
    }

    // Both entry points past their guards: whoever gets here owns _flushInProgress and is the one
    // flush the connection is allowed to have outstanding.
    private ValueTask FlushCore()
    {
        int target = WriteTail;
        for (int i = 0; i < _ovCount; i++)
        {
            target += _ov![i].Used;
        }
        if (target == 0)
        {
            Volatile.Write(ref _flushInProgress, 0);

            return default;
        }

        if (Interlocked.CompareExchange(ref _flushArmed, 1, 0) != 0)
        {
            throw new InvalidOperationException("FlushAsync already armed.");
        }

        _flushSignal.Reset();
        WriteInFlight = target;
        Volatile.Write(ref FlushArmedMs, _reactor.NowMs);

        // A segmented response that spilled past the primary slab is gathered into one SENDMSG.
        _flushVectored = _inOverflow;
        if (_flushVectored)
        {
            BuildIovec();
        }

        // The generation lets the reactor drop a flush whose connection closed (or
        // whose fd was reused) before the queue drained.
        int gen = Volatile.Read(ref _generation);

        _reactor.EnqueueFlush(ClientFd, gen);

        // Race recovery: if close raced in after the entry guard, self-complete so we
        // don't hang on a send the reactor will never make.
        if (Volatile.Read(ref _closed) == 1)
        {
            ReleaseParkedFlush();
        }

        return new ValueTask(this, (short)gen);
    }

    // The reactor takes a queued flush to the kernel. Fails if it was released first.
    internal bool TryClaimFlush() => Interlocked.CompareExchange(ref _flushArmed, 2, 1) == 1;

    // Frees a caller parked on a flush the kernel does not have. One it has completes with the send.
    private void ReleaseParkedFlush()
    {
        if (Interlocked.CompareExchange(ref _flushArmed, 0, 1) == 1)
        {
            Volatile.Write(ref _flushInProgress, 0);
            _flushSignal.SetResult(true);
        }
    }

    // Called by the reactor's send-completion path.
    internal void CompleteFlush()
    {
        if (_ovCount > 0)
        {
            ReleaseOverflow();
        }

        WriteHead = 0;
        WriteTail = 0;
        WriteInFlight = 0;
        ZcNotifPending = 0;
        Volatile.Write(ref _flushInProgress, 0);

        // Only the call that actually disarms the flush signals: a second SetResult throws on the
        // reactor thread and crashes the process.
        if (Interlocked.Exchange(ref _flushArmed, 0) != 0)
        {
            _flushSignal.SetResult(true);
        }
    }

#region IValueTaskSource

    void IValueTaskSource.GetResult(short token)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            return;
        }

        _flushSignal.GetResult(_flushSignal.Version);
    }

    ValueTaskSourceStatus IValueTaskSource.GetStatus(short token)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            return ValueTaskSourceStatus.Succeeded;
        }

        return _flushSignal.GetStatus(_flushSignal.Version);
    }

    void IValueTaskSource.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
    {
        if (token != (short)Volatile.Read(ref _generation))
        {
            continuation(state);

            return;
        }
        // Completes on the reactor thread only - strip the context-post so resumes stay inline
        // (see ReactorSynchronizationContext).
        _flushSignal.OnCompleted(continuation, state, _flushSignal.Version,
            flags & ~ValueTaskSourceOnCompletedFlags.UseSchedulingContext);
    }

#endregion
}
