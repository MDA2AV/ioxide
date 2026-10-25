namespace ioxide;

/// <summary>
/// An adapter parked on a connection's flush in place of an awaiter - the write side of
/// <see cref="IRecvListener"/>, for <see cref="TcpConnectionPipeWriter"/>.
/// </summary>
/// <remarks>
/// Parked through <see cref="TcpConnection.TryFlushOrPark"/>. <see cref="OnFlushDone"/> runs exactly
/// once per flush that had to wait, from whichever path disarms it: the send's completion on the
/// reactor, or the release of a flush whose connection closed before the kernel had it.
/// </remarks>
internal interface IFlushListener
{
    /// <summary>
    /// The connection is about to arm this listener's flush: the in-progress guard has passed and
    /// something is staged. As <see cref="IRecvListener.OnParking"/>: the listener readies its value
    /// task here, so a flush refused for overlapping one in flight, or one that sends nothing, leaves
    /// an earlier flush's source alone.
    /// </summary>
    void OnParking();

    void OnFlushDone();
}
