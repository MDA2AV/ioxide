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
    void OnRecvReady(RecvSnapshot snapshot);
}
