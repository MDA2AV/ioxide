using System.Threading.Tasks.Sources;
using epoxide.utils;
using static epoxide.Native;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace epoxide;

/// <summary>
/// The connection's flush: send the buffered response from the caller's own thread, and only when the
/// socket's buffer is full park the caller on an <see cref="IValueTaskSource"/> - the reactor then
/// sends the rest at the next writable edge and completes the flush. A plain send for a contiguous
/// response, a vectored sendmsg for a segmented one (TcpConnection.Write.Segmented.cs).
/// </summary>
public sealed unsafe partial class TcpConnection : IValueTaskSource
{
    private ManualResetValueTaskSourceCore<bool> _flushSignal;

    // Who may send the rest of a flush, handed between the writer and the reactor with CAS:
    //   Idle   - nothing known since the writer last found the socket full.
    //   Ready  - a writable edge since: a writer that just found it full tries again before parking.
    //   Parked - a flush waits on the socket, and the reactor sends the rest on the next edge.
    private const int WrIdle = 0, WrReady = 1, WrParked = 2;
    private int _wr;

    private int _flushInProgress;

    // What SendPending found.
    private const int SendDone = 0, SendBlocked = 1, SendFailed = 2;

    /// <summary>
    /// The reactor's cached clock when a flush began. The sweep reads it against
    /// <see cref="TcpOptions.SendTimeoutMs"/> while the flush is outstanding, and afterwards as the
    /// last time the server sent, which restarts the read clock.
    /// </summary>
    internal long FlushArmedMs;

    /// <summary>
    /// Whether a flush is outstanding - which tells the sweep that this connection is sending rather
    /// than waiting on its peer, so the send clock governs it and the read one does not.
    /// </summary>
    internal bool FlushOutstanding => Volatile.Read(ref _flushInProgress) != 0;

    public ValueTask FlushAsync()
    {
        if (Volatile.Read(ref _closed) == 1)
        {
            DropStaged();
            return default;
        }

        // One flush at a time: the parked caller waits on _flushSignal, which has room for exactly
        // one continuation. An application that flushes twice concurrently has a bug in its own write
        // serialization, and hearing about it here is the point.
        if (Interlocked.Exchange(ref _flushInProgress, 1) == 1)
        {
            throw new InvalidOperationException("FlushAsync already in progress.");
        }

        return FlushCore();
    }

    /// <summary>
    /// The teardown counterpart of <see cref="FlushAsync"/>: flush what is staged, but say nothing and
    /// send nothing when a flush is already in flight - for internal callers that flush on the
    /// application's behalf while tearing a connection down (the TLS pipe's DisposeAsync).
    /// </summary>
    internal ValueTask FlushIfIdleAsync()
    {
        if (Volatile.Read(ref _closed) == 1)
        {
            if (!FlushOutstanding)
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

    // The connection is already torn down, so the staged bytes are dropped rather than kept: nothing
    // will ever send them, and keeping them would grow the slab for a writer that keeps producing.
    private void DropStaged()
    {
        WriteTail = 0;
        if (_ovCount > 0)
        {
            ReleaseOverflow();
        }
    }

    // Past the guards: whoever gets here owns _flushInProgress and is the one flush the connection has.
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

        WriteHead = 0;
        WriteInFlight = target;
        Volatile.Write(ref FlushArmedMs, _reactor.NowMs);

        // A segmented response that spilled past the primary slab is gathered into one sendmsg.
        _flushVectored = _inOverflow;
        if (_flushVectored)
        {
            BuildIovec();
        }

        while (true)
        {
            int sent = SendPending();
            if (sent != SendBlocked)
            {
                EndFlush();
                if (sent == SendFailed)
                {
                    OnPeerGone();
                }
                return default;
            }

            // Full. Reset before parking: once parked, the reactor may complete it at any moment.
            _flushSignal.Reset();
            if (TryParkFlush())
            {
                return new ValueTask(this, (short)Volatile.Read(ref _generation));
            }
            if (Volatile.Read(ref _closed) == 1)
            {
                EndFlush();   // closed while it tried to park: nothing will send the rest
                return default;
            }
            // A writable edge came in meanwhile: send again.
        }
    }

    // True once parked. False to send again (an edge arrived), or when the connection closed under it.
    private bool TryParkFlush()
    {
        while (true)
        {
            int state = Volatile.Read(ref _wr);
            if (state == WrReady)
            {
                if (Interlocked.CompareExchange(ref _wr, WrIdle, WrReady) == WrReady)
                {
                    return false;
                }
                continue;
            }

            if (Interlocked.CompareExchange(ref _wr, WrParked, WrIdle) != WrIdle)
            {
                continue;
            }

            // MarkClosed sets _closed before it looks for a parked flush, so one of the two sees the other.
            if (Volatile.Read(ref _closed) == 1 && Interlocked.CompareExchange(ref _wr, WrIdle, WrParked) == WrParked)
            {
                return false;
            }
            return true;
        }
    }

    // Send what is left of the flush. The caller owns it: the writer, or the reactor for a parked one.
    private int SendPending()
    {
        while (WriteHead < WriteInFlight)
        {
            nint n = _flushVectored
                ? sendmsg(ClientFd, _msg, MSG_NOSIGNAL)
                : send(ClientFd, WriteBuffer + WriteHead, (nuint)(WriteInFlight - WriteHead), MSG_NOSIGNAL);
            if (n > 0)
            {
                WriteHead += (int)n;
                if (_flushVectored)
                {
                    AdvanceIov((int)n);
                }
                continue;
            }

            int errno = n < 0 ? Errno : 0;
            if (errno == EAGAIN)
            {
                return SendBlocked;
            }
            if (errno == EINTR)
            {
                continue;
            }
            return SendFailed;
        }

        return SendDone;
    }

    // The flush is over, sent or dropped: the slab is the writer's again.
    private void EndFlush()
    {
        if (_ovCount > 0)
        {
            ReleaseOverflow();
        }

        WriteHead = 0;
        WriteTail = 0;
        WriteInFlight = 0;
        Volatile.Write(ref _flushInProgress, 0);
    }

    /// <summary>
    /// An edge reported the socket writable, or failed. Reactor thread only. As in OnReadable, every
    /// state change happens before the writer is resumed, since it may run inline and let go.
    /// </summary>
    internal void OnWritable()
    {
        if (Volatile.Read(ref _connecting) != 0)
        {
            OnConnectReady();
            return;
        }

        while (true)
        {
            int state = Volatile.Read(ref _wr);
            if (state == WrParked)
            {
                // Claimed, not just read: a writer that has just parked takes its flush back when it
                // sees the connection closed (TryParkFlush), and only one of the two may own it.
                if (Interlocked.CompareExchange(ref _wr, WrIdle, WrParked) != WrParked)
                {
                    continue;
                }

                int sent = SendPending();
                if (sent == SendBlocked)
                {
                    Volatile.Write(ref _wr, WrParked);   // still full: parked again for the next edge
                    return;
                }
                if (sent == SendFailed)
                {
                    Volatile.Write(ref _wr, WrParked);   // the reactor's end releases it
                    OnPeerGone();
                    return;
                }

                EndFlush();

                // The FIN this flush held back, for a handler that let go or called ShutdownWrite meanwhile.
                if (HandlerReleased || FinWanted)
                {
                    SendFin();
                }

                _flushSignal.SetResult(true);
                return;
            }

            if (state == WrReady || Interlocked.CompareExchange(ref _wr, WrReady, WrIdle) == WrIdle)
            {
                return;
            }
        }
    }

    // Frees a caller parked on a flush; its bytes are dropped. From MarkClosed, on the reactor.
    private void ReleaseParkedFlush()
    {
        if (Interlocked.CompareExchange(ref _wr, WrIdle, WrParked) == WrParked)
        {
            EndFlush();
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

        Continuations.OnCompleted(ref _flushSignal, _reactor, continuation, state, _flushSignal.Version, flags);
    }

#endregion
}
