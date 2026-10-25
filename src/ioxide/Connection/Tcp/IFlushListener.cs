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
    void OnFlushDone();
}
