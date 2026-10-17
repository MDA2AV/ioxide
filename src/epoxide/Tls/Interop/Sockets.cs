namespace epoxide.tls;

/// <summary>The socket calls the TLS module needs that are not about TLS itself.</summary>
internal static unsafe class Sockets
{
    private const int MSG_DONTWAIT = 0x40;

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern nint recv(int fd, byte* buffer, nuint length, int flags);

    /// <summary>
    /// Takes at most <paramref name="length"/> bytes that are already waiting, without blocking. 0
    /// when none are, or on any error: the caller's next read reports those.
    /// </summary>
    public static int ReceiveWaiting(int fd, byte* buffer, int length)
    {
        nint n = recv(fd, buffer, (nuint)length, MSG_DONTWAIT);
        return n > 0 ? (int)n : 0;
    }

    /// <summary>
    /// Ends a connection at the socket: the peer gets a FIN, and a recv or send another thread has
    /// in flight on it - or makes next - fails at once instead of waiting on a peer that may never
    /// answer.
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
