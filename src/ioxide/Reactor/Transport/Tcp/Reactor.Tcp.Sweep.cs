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

    /// <summary>
    /// One pass over the connection table. Runs on the reactor thread from the ticker, so it owns
    /// the table outright and can touch a connection directly.
    /// </summary>
    /// <remarks>
    /// The table is indexed by fd, so it spans every descriptor in the process rather than this
    /// reactor's connections alone: a million connections over 64 reactors is a million slots per
    /// reactor, every reactor walking its own four times a second, and on the same tick, since they
    /// start together. That walk held a reactor off its ring long enough to show in the tail of every
    /// request scheduled behind it. So it is made only when something on a connection needs it: one
    /// of the two clocks, or a recv parked on -ENOBUFS waiting for the buffers that connections their
    /// handler let go still hold. The FIN asked for behind a flush is not a reason - the flush's own
    /// completion sends it (Reactor.FinishSend), and the few asks that outlive their flush are on a
    /// list of their own, retried every tick (RetryFinAsks).
    /// </remarks>
    private void TcpSweep()
    {
        foreach (int listenFd in _acceptPaused)
        {
            SubmitAcceptMultishot(listenFd);
        }
        _acceptPaused.Clear();

        RetryFinAsks();

        bool starved = _recvStarved.Count > 0;
        if (!starved && _readTimeoutMs <= 0 && _sendTimeoutMs <= 0)
        {
            return;
        }

        long now = Native.MonotonicMs;
        TcpConnection?[] conns = _connections;

        for (int fd = 0; fd < conns.Length; fd++)
        {
            TcpConnection? conn = conns[fd];
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
            // restarts once the flush is done.
            if (conn.FlushOutstanding)
            {
                conn.FlushSeenMs = now;
                if (_sendTimeoutMs > 0 && now - Volatile.Read(ref conn.FlushArmedMs) > _sendTimeoutMs)
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

        // A condemned connection whose recv is parked has no completion coming for its shutdown to end.
        for (int i = _recvStarved.Count - 1; i >= 0; i--)
        {
            ulong parked = _recvStarved[i];
            int fd = (int)(uint)parked;
            if (ConnAt(fd, (ushort)(parked >> 32)) is { SweepClosed: true } conn)
            {
                _recvStarved.RemoveAt(i);
                CloseFromRecv(conn, fd);
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

        conn.SuppressFin();   // this shutdown is the FIN
        shutdown(conn.ClientFd, SHUT_RDWR);
        conn.MarkClosed();
    }
}
