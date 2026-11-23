using System.Collections.Concurrent;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// The clocks on a TCP connection's lifecycle: a connection waiting on a silent peer is reaped, and
/// so is one whose send the peer stopped draining.
/// </summary>
/// <remarks>
/// Rides the reactor's existing ~250 ms ticker rather than arming anything of its own, which is
/// what <see cref="ioxide.tls.TlsService"/> does for handshakes and the QUIC transport does for
/// idle connections. Second-scale timeouts do not need better granularity than that.
/// </remarks>
public sealed unsafe partial class Reactor
{
    private readonly int _readTimeoutMs;
    private readonly int _sendTimeoutMs;

    /// <summary>
    /// Native.MonotonicMs, refreshed once per loop pass rather than read per completion.
    ///
    /// The stamps this feeds are read by a sweep that runs four times a second, so a clock good to
    /// one batch of completions is far finer than anything that consumes it - while reading the
    /// real one per CQE put a vDSO call on both the recv and the send hot path, three per request,
    /// and measured as a 4-9% throughput cost on the small-response samples.
    /// </summary>
    internal long NowMs = Native.MonotonicMs;

    // Connections whose write shutdown waits for a flush (TcpConnection.ShutdownWrite), (gen << 32) | slot.
    // Added by any thread; nearly always empty, as a handler that awaits its last flush never defers one.
    private readonly ConcurrentQueue<ulong> _deferredWriteShutdowns = new();

    internal void DeferWriteShutdown(int slot, int gen)
        => _deferredWriteShutdowns.Enqueue(((ulong)(ushort)gen << 32) | (uint)slot);

    // One look at each per tick: one whose flush is still in flight waits for the next. A connection that
    // is gone was torn down by the reactor, which leaves nothing to shut down.
    private void RunDeferredWriteShutdowns()
    {
        for (int left = _deferredWriteShutdowns.Count; left > 0 && _deferredWriteShutdowns.TryDequeue(out ulong packed); left--)
        {
            TcpConnection? conn = ConnAt((int)(uint)packed, (ushort)(packed >> 32));
            if (conn != null && !conn.RunDeferredWriteShutdown())
            {
                _deferredWriteShutdowns.Enqueue(packed);
            }
        }
    }

    /// <summary>
    /// What TCP needs from every tick, and a pass over the connection table when something on a
    /// connection needs one. Runs on the reactor thread from the ticker, so it owns the table outright
    /// and can touch a connection directly.
    /// </summary>
    /// <remarks>
    /// The pass is over this reactor's own connections, as many slots as it has held at once, and made
    /// only when something on one needs it: one of the two clocks, or a recv parked on -ENOBUFS waiting
    /// for the buffers of the shared ring that connections their handler let go still hold. With a ring
    /// per connection only those parked are looked at, as no other connection's buffers can serve them.
    /// A write shutdown deferred behind a flush is not a reason either: those are in a queue of their
    /// own, looked at on every tick.
    /// </remarks>
    private void TcpSweep()
    {
        foreach (int listenFd in _acceptPaused)
        {
            SubmitAcceptMultishot(listenFd);
        }
        _acceptPaused.Clear();

        RunDeferredWriteShutdowns();

        bool starved = _recvStarved.Count > 0;
        if (starved && _incremental)
        {
            ReturnStarvedBuffers();
            starved = false;   // nothing another connection holds can serve them
        }

        if (!starved && _readTimeoutMs <= 0 && _sendTimeoutMs <= 0)
        {
            CloseCondemnedStarved();
            return;
        }

        long now = Native.MonotonicMs;

        foreach (TcpConnection? conn in _slots.AsSpan(0, _slotsUsed))
        {
            if (conn is null)
            {
                continue;
            }

            // A recv is waiting for a buffer, maybe its own, and this connection holds some for nobody.
            if (starved && conn.HandlerReleased)
            {
                ReturnReleasedBuffers(conn);
            }

            if (conn.SweepClosed)
            {
                continue;
            }

            // Sending, so not waiting on the peer: only the send clock applies, and the read clock
            // restarts once the flush is done. A flush call off the reactor can be caught here before it
            // has armed, with the last flush's time still on the clock: it is not judged by that.
            if (conn.FlushOutstanding)
            {
                conn.FlushSeenMs = now;
                if (_sendTimeoutMs > 0 && conn.FlushArmed && now - Volatile.Read(ref conn.FlushArmedMs) > _sendTimeoutMs)
                {
                    TcpSweepClose(conn);
                }
                continue;
            }

            if (_readTimeoutMs > 0 && conn.WaitingOnPeer(out long sinceMs) && now - sinceMs > _readTimeoutMs)
            {
                TcpSweepClose(conn);
            }
        }

        CloseCondemnedStarved();
    }

    // Incremental mode: a recv parked on a ring its handler filled and then let go of, which nobody will empty.
    private void ReturnStarvedBuffers()
    {
        foreach (ulong parked in _recvStarved)
        {
            if (ConnAt((int)(uint)parked, (ushort)(parked >> 32)) is { HandlerReleased: true } conn)
            {
                ReturnReleasedBuffers(conn);
            }
        }
    }

    // A condemned connection whose recv is parked has no completion coming for its shutdown to end.
    private void CloseCondemnedStarved()
    {
        for (int i = _recvStarved.Count - 1; i >= 0; i--)
        {
            ulong parked = _recvStarved[i];
            if (ConnAt((int)(uint)parked, (ushort)(parked >> 32)) is { SweepClosed: true } conn)
            {
                _recvStarved.RemoveAt(i);
                CloseFromRecv(conn);
            }
        }
    }

    /// <summary>
    /// End one connection the sweep has condemned - and nothing more than that.
    /// </summary>
    /// <remarks>
    /// shutdown() is what the PEER sees, and it is also what releases the connection: a
    /// TcpConnection is held by two refs, the handler's and the reactor's, and the reactor's is
    /// given up only when its outstanding operation completes. For an idle connection that is a
    /// multishot recv against a peer saying nothing, which otherwise never completes; for a stalled
    /// one it is a SEND the peer's closed window is holding, which otherwise never completes
    /// either. Shutting the socket down ends both.
    ///
    /// MarkClosed is what wakes a handler parked on a read NOW, with the closed state its loop
    /// already knows how to handle, rather than one io_uring round trip later. One parked on the
    /// flush being timed out wakes when shutdown() fails that send: the slab is the kernel's until then.
    ///
    /// What this deliberately does NOT do is clear the table slot, cancel, or DecRef. The teardown
    /// those completions already run (CloseFromRecv, and the send path's res &lt;= 0 branch) is the
    /// one that gets the refcount right, and it only runs once the kernel has finished with the
    /// connection's slab. Releasing the reactor's ref here instead would let the connection reach
    /// zero - and be recycled, with its slab freed or resized - while a SEND the kernel has not
    /// given back still points into it.
    ///
    /// A recv parked on -ENOBUFS has no completion to wait for, so <see cref="TcpSweep"/> runs that
    /// teardown itself.
    /// </remarks>
    private void TcpSweepClose(TcpConnection conn)
    {
        conn.SweepClosed = true;   // one shutdown per connection, not one per tick until it lands

        conn.SuppressWriteShutdown();   // this shutdown ends both sides
        shutdown(conn.ClientFd, SHUT_RDWR);
        conn.MarkClosed();
    }
}
