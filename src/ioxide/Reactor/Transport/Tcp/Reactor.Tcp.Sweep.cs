using static ioxide.Native;

namespace ioxide;

/// <summary>
/// The clocks on a TCP connection's lifecycle: a connection whose read the peer never answers is
/// reaped, and so is one whose send the peer stopped draining.
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
    /// Environment.TickCount64, refreshed once per loop pass rather than read per completion.
    ///
    /// The stamps this feeds are read by a sweep that runs four times a second, so a clock good to
    /// one batch of completions is far finer than anything that consumes it - while reading the
    /// real one per CQE put a vDSO call on both the recv and the send hot path, three per request,
    /// and measured as a 4-9% throughput cost on the small-response samples.
    /// </summary>
    internal long NowMs = Environment.TickCount64;

    // Registered whenever TCP is on, not only when a clock is configured: the deferred FIN of a
    // handler that let go mid-flush (see TcpConnection.DecRef) is sent from here, clocks or not.
    private bool TcpSweepEnabled => _tcpEnabled;

    /// <summary>
    /// One pass over the connection table. Runs on the reactor thread from the ticker, so it owns
    /// the table outright and can touch a connection directly.
    /// </summary>
    private void TcpSweep()
    {
        long now = Environment.TickCount64;
        TcpConnection?[] conns = _connections;

        for (int fd = 0; fd < conns.Length; fd++)
        {
            TcpConnection? conn = conns[fd];
            if (conn is null || conn.SweepClosed)
            {
                continue;
            }

            // A handler that let go with a flush in flight left its FIN for later, since sending
            // it then would have cut that flush short. The flush is done now.
            if (conn.HandlerReleased && !conn.FinSent && !conn.FlushOutstanding)
            {
                conn.SendFin();
            }

            // The two clocks are independent: a duplex connection can be waiting on the peer to
            // read and to write at once. Neither runs while the handler is simply busy - its read is
            // not parked and it has nothing in flight - however long that takes.
            if (_sendTimeoutMs > 0 && conn.FlushOutstanding
                && now - Volatile.Read(ref conn.FlushArmedMs) > _sendTimeoutMs)
            {
                TcpSweepClose(conn);
                continue;
            }

            if (_readTimeoutMs > 0 && conn.WaitingOnPeer(out long sinceMs) && now - sinceMs > _readTimeoutMs)
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
    /// given up only when its outstanding operation completes. For a connection waiting on its peer
    /// that is a multishot recv against a peer saying nothing, which otherwise never completes; for
    /// a stalled one it is a SEND the peer's closed window is holding, which otherwise never
    /// completes either. Shutting the socket down ends both.
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

        conn.SuppressFin();        // this shutdown is the FIN; the handler letting go adds none
        shutdown(conn.ClientFd, SHUT_RDWR);
        conn.MarkClosed();
    }
}
