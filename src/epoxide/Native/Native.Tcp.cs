namespace epoxide;

/// <summary>TCP-specific ABI: stream socket type and protocol options.</summary>
public static unsafe partial class Native
{
    public const int SOCK_STREAM = 1;
    public const int IPPROTO_TCP = 6;
    public const int TCP_NODELAY = 1;

    /// <summary>
    /// How long, in ms, sent data may go unacknowledged - or a peer keep its window shut against the
    /// probes - before the kernel aborts the connection. Accepted sockets take it from the listener.
    /// </summary>
    public const int TCP_USER_TIMEOUT = 18;
}
