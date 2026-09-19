namespace ioxide.tls;

/// <summary>The one socket call the TLS module needs that is not about TLS itself.</summary>
internal static class Sockets
{
    /// <summary>
    /// Ends a connection at the socket, so the peer gets a FIN and any outstanding io_uring recv
    /// completes with EOF - which is what actually releases a connection the reactor is still
    /// holding a reference to.
    /// </summary>
    /// <remarks>
    /// Failure is ignored on purpose: every reason it can fail (already shut down, already closed,
    /// never connected) is a socket that is going away regardless, and the caller is a sweep with
    /// nothing to report to.
    /// </remarks>
    public static void Shutdown(int fd)
    {
        if (fd >= 0)
        {
            _ = Native.shutdown(fd, Native.SHUT_RDWR);
        }
    }
}
