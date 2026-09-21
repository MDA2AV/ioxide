using static ioxide.Native;

namespace ioxide;

/// <summary>
/// The clocks on a TCP connection's lifecycle: an idle connection is reaped, and so is one whose
/// send the peer stopped draining.
/// </summary>
/// <remarks>
/// Rides the reactor's existing ~250 ms ticker rather than arming anything of its own, which is
/// what <see cref="ioxide.tls.TlsService"/> does for handshakes and the QUIC transport does for
/// idle connections. Second-scale timeouts do not need better granularity than that.
/// </remarks>
public sealed unsafe partial class Reactor
{
    private readonly int _idleTimeoutMs;
    private readonly int _sendTimeoutMs;

    /// <summary>
    /// Environment.TickCount64, refreshed once per loop pass rather than read per completion.
    ///
    /// The stamps this feeds are read by a sweep that runs four times a second, so a clock good to
    /// one batch of completions is far finer than anything that consumes it - while reading the
    /// real one per CQE put a vDSO call on both the recv and the send hot path, three per request,
    /// and measured as a 4-9% throughput cost on the small-response samples.
    /// </summary>
    internal long NowMs = Environment.TickCount64;

    // Registered whenever TCP is on, not only when a clock is configured: the deferred-send pass
    // has to run regardless, or SendTimeoutMs = 0 leaves a stalled connection pinning an fd and a
    // slab for the life of the process.
    private bool TcpSweepEnabled => _tcpEnabled;

    /// <summary>
    /// One pass over the connection table. Runs on the reactor thread from the ticker, so it owns
    /// the table outright and can touch a connection directly.
    /// </summary>
    private void TcpSweep()
    {
        // Deferred connections are off the table below, so they need their own pass.
        if (_sendDraining.Count != 0)
        {
            SweepDrainingSends();
        }

        // With both clocks off there is nothing the walk below could decide, so it is skipped
        // entirely - the registration exists only for the deferred pass above.
        if (_idleTimeoutMs <= 0 && _sendTimeoutMs <= 0)
        {
            return;
        }

        long now = Environment.TickCount64;
        TcpConnection?[] conns = _connections;

        for (int fd = 0; fd < conns.Length; fd++)
        {
            TcpConnection? conn = conns[fd];
            if (conn is null || conn.SweepClosed)
            {
                continue;
            }

            // A connection with a flush outstanding is not idle, it is sending - so the send clock
            // governs it and the idle one does not apply. Under MSG_WAITALL the whole flush is a
            // single completion, so nothing refreshes the activity stamp for as long as the send
            // legitimately takes.
            if (conn.FlushOutstanding)
            {
                if (_sendTimeoutMs > 0 && now - Volatile.Read(ref conn.FlushArmedMs) > _sendTimeoutMs)
                {
                    TcpSweepClose(conn);
                }
                continue;
            }

            if (_idleTimeoutMs > 0 && now - conn.LastActivityMs > _idleTimeoutMs)
            {
                TcpSweepClose(conn);
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
    /// MarkClosed is what wakes the handler NOW - parked on a read, or on the very flush being
    /// timed out - with the closed state its loop already knows how to handle, rather than one
    /// io_uring round trip later.
    ///
    /// What this deliberately does NOT do is clear the table slot, cancel, or DecRef. The teardown
    /// those completions already run (CloseFromRecv, and the send path's res &lt;= 0 branch) is the
    /// one that gets the refcount right, and it only runs once the kernel has finished with the
    /// connection's slab. Releasing the reactor's ref here instead would let the connection reach
    /// zero - and be recycled, with its slab freed or resized - while a SEND the kernel has not
    /// given back still points into it.
    /// </remarks>
    private void TcpSweepClose(TcpConnection conn)
    {
        conn.SweepClosed = true;   // one shutdown per connection, not one per tick until it lands

        shutdown(conn.ClientFd, SHUT_RDWR);
        conn.MarkClosed();
    }
}
