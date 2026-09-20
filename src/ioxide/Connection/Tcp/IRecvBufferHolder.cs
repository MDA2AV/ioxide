namespace ioxide;

/// <summary>
/// Something holding recv buffers it took out of a connection's queue.
/// </summary>
/// <remarks>
/// <see cref="TcpConnection.TryGetItem"/> is a DEQUEUE, so the moment a buffer is handed out the
/// connection's queue no longer has it and <c>DrainRecv</c> at recycle walks straight past it. The
/// buffer then comes back only if the holder is told to give it back - which, on the plaintext
/// path, nothing enforced: <see cref="TcpConnectionDualPipe"/> has no disposal, unlike the TLS one.
/// A handler that returned early stranded a buffer per connection.
///
/// Implemented by the two types that hold buffers across calls - <see cref="TcpConnectionPipeReader"/>
/// and <see cref="TcpConnectionStream"/> - so recycle can reclaim from either without knowing which.
/// </remarks>
internal interface IRecvBufferHolder
{
    /// <summary>
    /// Hand every held buffer back to its ring. Must be idempotent: the ordinary path releases on
    /// completion and recycle asks again afterwards, and each buffer may be returned only once.
    /// </summary>
    void ReleaseHeldBuffers();
}
