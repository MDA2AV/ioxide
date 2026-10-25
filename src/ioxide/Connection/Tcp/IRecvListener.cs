namespace ioxide;

/// <summary>
/// An adapter parked on a connection's read in place of an awaiter.
/// </summary>
/// <remarks>
/// <see cref="TcpConnectionPipeReader"/> used to park on <see cref="TcpConnection.ReadAsync"/>'s
/// value-task source and complete its own from that source's continuation: two sources, two
/// continuation registrations and the interface calls between them, on every read that waits.
/// Parked through <see cref="TcpConnection.TryReadOrPark"/> instead, the connection calls the reader
/// directly, and the reader's own source - the one its caller awaits - is the only one left.
///
/// <see cref="TcpConnection.ReadAsync"/> parks the same way, with the connection as its listener: the
/// read claims the connection's one read slot, readies its value task, then publishes itself there,
/// and only the completion that takes it back delivers - so <see cref="OnRecvReady"/> runs exactly once
/// per park, on the thread that completed the read: the reactor's for a recv, the closing one for a
/// close.
/// </remarks>
internal interface IRecvListener
{
    /// <summary>
    /// The connection has claimed its read slot for this listener - a read racing it is refused, and
    /// nothing delivers to a claim - and publishes the park next. The listener readies the value task
    /// its caller will wait on here and nowhere earlier, since a read refused for overlapping a parked
    /// one must leave that one's source alone, and not later either: once published, the completion can
    /// run <see cref="OnRecvReady"/> before the park returns. Not called for a read refused or served at
    /// once - though a completion that came while the listener was readying still serves the read at
    /// once, and then that value task goes unused.
    /// </summary>
    void OnParking();

    void OnRecvReady(RecvSnapshot snapshot);
}
