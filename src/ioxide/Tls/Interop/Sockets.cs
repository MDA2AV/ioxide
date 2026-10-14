namespace ioxide.tls;

/// <summary>The socket calls the TLS module needs that are not about TLS itself.</summary>
internal static unsafe class Sockets
{
    private const int MSG_DONTWAIT = 0x40;

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern nint recv(int fd, byte* buffer, nuint length, int flags);

    /// <summary>
    /// Takes at most <paramref name="length"/> bytes that are already waiting, without blocking. 0
    /// when none are, or on any error: the caller's next ring recv reports those.
    /// </summary>
    public static int ReceiveWaiting(int fd, byte* buffer, int length)
    {
        nint n = recv(fd, buffer, (nuint)length, MSG_DONTWAIT);
        return n > 0 ? (int)n : 0;
    }

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
