namespace ioxide;

/// <summary>
/// The contract a reactor implements so ring-native clients (Postgres, files, Redis) can run on
/// it. A client hands each submission an fd, a native buffer, and the completion to call back;
/// the reactor builds the SQE and routes the CQE to that completion - inline, on the reactor
/// thread. Routing is per operation, so concurrent ops on one fd never collide.
///
/// Buffers cross as <see cref="nint"/> because pointers can't survive an await. Safe from any
/// thread (off-reactor callers are marshalled). Results: bytes transferred (0 for connect), or a
/// negative errno.
/// </summary>
public interface IRingHost
{
    /// <summary>
    /// Connect <paramref name="fd"/> to the native sockaddr at <paramref name="sockaddr"/>.
    /// </summary>
    void SubmitConnect(int fd, nint sockaddr, int sockaddrLen, IRingCompletion completion);

    /// <summary>
    /// Send <paramref name="length"/> bytes from <paramref name="buffer"/> on <paramref name="fd"/>.
    /// </summary>
    void SubmitSend(int fd, nint buffer, int length, IRingCompletion completion);

    /// <summary>
    /// Receive up to <paramref name="length"/> bytes into <paramref name="buffer"/> on <paramref name="fd"/>.
    /// </summary>
    void SubmitRecv(int fd, nint buffer, int length, IRingCompletion completion);

    /// <summary>
    /// Read up to <paramref name="length"/> bytes into <paramref name="buffer"/> from <paramref name="offset"/>.
    /// </summary>
    void SubmitRead(int fd, nint buffer, int length, long offset, IRingCompletion completion);

    /// <summary>
    /// Write <paramref name="length"/> bytes from <paramref name="buffer"/> at <paramref name="offset"/>.
    /// </summary>
    void SubmitWrite(int fd, nint buffer, int length, long offset, IRingCompletion completion);

    /// <summary>
    /// Completes after <paramref name="nanoseconds"/> have elapsed, on this reactor's thread,
    /// with no file descriptor involved. The kernel holds the deadline on the ring, so a wait
    /// costs one SQE and one CQE and no syscall of its own.
    ///
    /// Expiry is reported the way io_uring reports it: <c>Complete</c> receives <c>-ETIME</c>
    /// (-62), which is success for a timeout rather than a failure.
    /// </summary>
    void SubmitTimeout(long nanoseconds, IRingCompletion completion);

    /// <summary>True when the caller is on the host's thread, where a client's own state lives.</summary>
    bool OnReactorThread { get; }

    /// <summary>Run <paramref name="callback"/> on the host's thread.</summary>
    void ScheduleOnReactor(Action<object?> callback, object? state);
}

/// <summary>
/// The reactor calls this when a submitted operation's CQE arrives.
/// </summary>
public interface IRingCompletion
{
    /// <param name="result">Bytes transferred, or a negative errno.</param>
    void Complete(int result);
}
