using static epoxide.Native;

namespace epoxide;

/// <summary>
/// The clocks on a TCP connection's lifecycle, as in ioxide: a connection waiting on a silent peer
/// is reaped, and so is one whose flush the peer stopped draining. Rides the reactor's ~250 ms ticker.
/// </summary>
public sealed unsafe partial class Reactor
{
    private readonly int _readTimeoutMs;
    private readonly int _sendTimeoutMs;

    /// <summary>
    /// Native.MonotonicMs, refreshed once per loop pass rather than read per event. The stamps it
    /// feeds are read by a sweep that runs four times a second, so a clock good to one batch is far
    /// finer than anything that consumes it.
    /// </summary>
    internal long NowMs = MonotonicMs;

    // Whenever TCP is on: the deferred FIN (TcpConnection.DecRef) is sent from here, clocks or not.
    private bool TcpSweepEnabled => _tcpEnabled;

    // Whether the sweep is on this reactor's tickers. A reactor with no listener registers it with
    // its first outbound connection, whose clocks and deferred FIN need it just the same.
    private bool _tcpSweepRegistered;

    // Reactor thread only.
    private void EnsureTcpSweep()
    {
        if (!_tcpSweepRegistered)
        {
            _tcpSweepRegistered = true;
            AddTicker(TcpSweep);
        }
    }

    /// <summary>One pass over the connection table, on the reactor thread, which owns it outright.</summary>
    private void TcpSweep()
    {
        ResumePausedAccepts();

        long now = MonotonicMs;
        TcpConnection?[] conns = _connections;

        for (int fd = 0; fd < conns.Length; fd++)
        {
            TcpConnection? conn = conns[fd];
            if (conn is null || conn.SweepClosed)
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

            // A FIN left behind a flush - by a handler that let go, or by ShutdownWrite - goes now.
            if ((conn.HandlerReleased || conn.FinWanted) && !conn.FinSent)
            {
                conn.SendFin();
            }

            if (_readTimeoutMs > 0 && conn.WaitingOnPeer(out long sinceMs) && now - sinceMs > _readTimeoutMs)
            {
                TcpSweepClose(conn);
            }
        }
    }

    /// <summary>
    /// End one connection the sweep has condemned. shutdown() is what the peer sees and what fails
    /// a handler's syscall in flight on another thread; the reactor's end does the rest at once - no
    /// operation is held in a kernel queue on epoll, so nothing has to complete first.
    /// </summary>
    private void TcpSweepClose(TcpConnection conn)
    {
        conn.SweepClosed = true;
        conn.SuppressFin();   // this shutdown is the FIN
        shutdown(conn.ClientFd, SHUT_RDWR);
        CloseFromReactor(conn);
    }
}
