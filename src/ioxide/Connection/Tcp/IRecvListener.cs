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
/// The arm protocol is <see cref="TcpConnection.ReadAsync"/>'s, with one addition: whichever side
/// takes the arm back delivers, so <see cref="OnRecvReady"/> runs exactly once per park, on the thread
/// that completed the read - the reactor's for a recv, the closing one for a close.
/// </remarks>
internal interface IRecvListener
{
    /// <summary>
    /// The connection is about to park this listener: every guard has passed, and the arm that
    /// publishes the park comes next. The listener readies the value task its caller will wait on
    /// here and nowhere earlier - a read refused for overlapping a parked one must leave that one's
    /// source alone - and not later either, since off the reactor the completion can run
    /// <see cref="OnRecvReady"/> before the park returns. Not called for a read served at once.
    /// </summary>
    void OnParking();

    void OnRecvReady(RecvSnapshot snapshot);
}
