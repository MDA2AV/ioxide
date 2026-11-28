namespace ioxide;

public sealed unsafe partial class TcpConnection
{
    // A fleet's connection's follower, made the first time it is asked for: the object's lives share it.
    private ConnectionHost? _ringHost;

    /// <summary>
    /// This connection's reactor wherever the connection is, to keep where code would keep the reactor, for the
    /// connection's life: <c>await new ReactorSwitch(connection.RingHost)</c> gets back to it from anywhere. Without
    /// <see cref="TcpOptions.Rebalance"/> it is the reactor the connection was accepted on itself.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>A switch to it lands on the reactor serving the connection when it gets there, or throws
    /// <see cref="ObjectDisposedException"/> once that reactor has stopped.</item>
    /// <item>What is posted through it (<see cref="IRingHost.ScheduleOnReactor"/>) runs there. Once the connection's
    /// reactor has stopped it is dropped, as what is posted to that reactor is. Posts made on one thread keep their order
    /// on one reactor, but not across a move: one made while the connection was leaving can run after one made once it
    /// had arrived.</item>
    /// <item>An operation submitted through it goes to the reactor serving the connection as the submitting thread sees
    /// it (on the reactor it is leaving, the one it is going to) and completes there, also when the connection has
    /// moved on since; it throws once that reactor is stopping. So a one-off wait, as a <c>RingTimer</c>'s, can go
    /// through it, and code that goes on to the connection afterwards switches to it again. A client that keeps state,
    /// such as a pool or a socket, is opened on a <see cref="ioxide.Reactor"/>, never on this, and nothing is submitted
    /// through it on the connection's own descriptor.</item>
    /// <item>The connection object is pooled: kept past the connection's end, it follows the object's next connection.
    /// It is the reactor itself only for a connection that can't move.</item>
    /// </list>
    /// A flush that something other than the connection's handler asks for while a read of it waits is made after
    /// <c>await new ReactorSwitch(connection.RingHost)</c>: one asked for anywhere else while the connection is between
    /// two reactors can get lost.
    /// </remarks>
    public IRingHost RingHost => Movable ? _ringHost ?? CreateRingHost() : _reactor;

    private ConnectionHost CreateRingHost()
    {
        var host = new ConnectionHost(this);
        return Interlocked.CompareExchange(ref _ringHost, host, null) ?? host;
    }
}

/// <summary>
/// The reactor serving a connection that can change reactors, wherever it is (<see cref="TcpConnection.RingHost"/>).
/// </summary>
internal sealed class ConnectionHost(TcpConnection connection) : IRingHost
{
    internal TcpConnection Connection => connection;

    public bool OnReactorThread => connection.Reactor.OnReactorThread;

    public void ScheduleOnReactor(Action<object?> callback, object? state) => new Hop(connection, callback, state).Post();

    public void SubmitConnect(int fd, nint sockaddr, int sockaddrLen, IRingCompletion completion)
        => connection.Reactor.SubmitConnect(fd, sockaddr, sockaddrLen, completion);

    public void SubmitSend(int fd, nint buffer, int length, IRingCompletion completion)
        => connection.Reactor.SubmitSend(fd, buffer, length, completion);

    public void SubmitRecv(int fd, nint buffer, int length, IRingCompletion completion)
        => connection.Reactor.SubmitRecv(fd, buffer, length, completion);

    public void SubmitRead(int fd, nint buffer, int length, long offset, IRingCompletion completion)
        => connection.Reactor.SubmitRead(fd, buffer, length, offset, completion);

    public void SubmitWrite(int fd, nint buffer, int length, long offset, IRingCompletion completion)
        => connection.Reactor.SubmitWrite(fd, buffer, length, offset, completion);

    public void SubmitTimeout(long nanoseconds, IRingCompletion completion)
        => connection.Reactor.SubmitTimeout(nanoseconds, completion);

    /// <summary>
    /// A hop, as posted to a reactor. One that has stopped hands it to the thread pool, as it does a switch's own
    /// continuation (<see cref="ReactorSwitch.Resume"/>), and from there it follows the connection or ends (<see cref="Hop.Run"/>).
    /// </summary>
    internal static readonly Action<object?> HopRun = static hop => ((Hop)hop!).Run();

    /// <summary>
    /// A callback on its way to the reactor serving the connection, posted where the posting thread sees it. Where it
    /// runs, the connection may have moved on (it was between two reactors, or has been given again): then it posts
    /// itself on to the next one, which takes the connection first, as what is posted to a reactor runs in order. If that
    /// reactor has stopped, it goes on to the one the connection is on its way to, if that one hasn't; otherwise it ends
    /// as what is posted to the stopped reactor does: a switch's continuation resumes on the thread pool, where the switch
    /// throws, and anything else is dropped.
    /// </summary>
    internal sealed class Hop(TcpConnection connection, Action<object?> callback, object? state)
    {
        private readonly bool _continuation = callback == ReactorSwitch.Resume;

        internal void Post() => connection.Reactor.ScheduleOnReactor(HopRun, this);

        internal void Run()
        {
            while (true)
            {
                Reactor reactor = connection.Reactor;
                if (reactor.OnReactorThread)
                {
                    callback(state);
                    return;
                }

                if (!reactor.PostsClosed)
                {
                    reactor.ScheduleOnReactor(HopRun, this);   // it moved on meanwhile
                    return;
                }

                // Given away, or sent back, by a reactor that has stopped: the one it is going to, this thread's own
                // included, has it next, behind its arrival, which was posted before that reactor stopped.
                Reactor next = connection.Destination;
                if (next != reactor && !next.PostsClosed)
                {
                    next.ScheduleOnReactor(HopRun, this);
                    return;
                }

                // Its next stopped too: a stop past a hand-over shows the reactor that one gave it to, so look again,
                // unless nothing has changed.
                if (ReferenceEquals(connection.Destination, next) && ReferenceEquals(connection.Reactor, reactor))
                {
                    break;
                }
            }

            if (_continuation)
            {
                if (Reactor.Current is null)
                {
                    callback(state);
                }
                else
                {
                    ThreadPool.UnsafeQueueUserWorkItem(static hop => hop.Resume(), this, preferLocal: false);   // not on a reactor that isn't its own
                }
            }
        }

        private void Resume() => callback(state);
    }
}
