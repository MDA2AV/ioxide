using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace ioxide;

/// <summary>
/// <c>await new ReactorSwitch(reactor)</c> continues the method on the reactor's thread: at once
/// when the caller is already there or there is no reactor, else through its post queue. Throws
/// <see cref="ObjectDisposedException"/> once the reactor has stopped. Given a connection's
/// <see cref="TcpConnection.RingHost"/>, it lands on the reactor serving the connection when it gets there.
/// </summary>
public readonly struct ReactorSwitch : ICriticalNotifyCompletion
{
    internal static readonly Action<object?> Resume = static continuation => ((Action)continuation!)();

    private readonly IRingHost? _reactor;

    public ReactorSwitch(IRingHost? reactor) => _reactor = reactor;

    /// <summary>
    /// Continues on the reactor's thread from its post queue, even when the caller is already there:
    /// after whatever is running now has returned.
    /// </summary>
    public static ReactorYield Yield(IRingHost reactor) => new(reactor);

    public ReactorSwitch GetAwaiter() => this;

    public bool IsCompleted => _reactor is null || _reactor.OnReactorThread;

    public void OnCompleted(Action continuation) => _reactor!.ScheduleOnReactor(Resume, continuation);

    public void UnsafeOnCompleted(Action continuation) => _reactor!.ScheduleOnReactor(Resume, continuation);

    public void GetResult()
    {
        if (Stopped(_reactor))
        {
            ThrowStopped();
        }
    }

    // A reactor that has stopped; for a connection's host (TcpConnection.RingHost), one whose reactor has stopped, or a
    // switch that didn't land on the reactor serving the connection, which is how one resumed by a reactor's stop gets here.
    internal static bool Stopped(IRingHost? host)
        => host is Reactor { PostsClosed: true } or ConnectionHost { Connection.Reactor: { PostsClosed: true } or { OnReactorThread: false } };

    [DoesNotReturn]
    internal static void ThrowStopped() => throw new ObjectDisposedException(nameof(Reactor), "The reactor has stopped.");
}

/// <summary>The awaitable behind <see cref="ReactorSwitch.Yield"/>: always posts.</summary>
public readonly struct ReactorYield : ICriticalNotifyCompletion
{
    private readonly IRingHost _reactor;

    internal ReactorYield(IRingHost reactor) => _reactor = reactor;

    public ReactorYield GetAwaiter() => this;

    public bool IsCompleted => false;

    public void OnCompleted(Action continuation) => _reactor.ScheduleOnReactor(ReactorSwitch.Resume, continuation);

    public void UnsafeOnCompleted(Action continuation) => _reactor.ScheduleOnReactor(ReactorSwitch.Resume, continuation);

    public void GetResult()
    {
        if (ReactorSwitch.Stopped(_reactor))
        {
            ReactorSwitch.ThrowStopped();
        }
    }
}
