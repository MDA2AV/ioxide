using System.Runtime.CompilerServices;

namespace ioxide;

/// <summary>
/// <c>await new ReactorSwitch(reactor)</c> continues the method on the reactor's thread: at once
/// when the caller is already there or there is no reactor, else through its post queue.
/// </summary>
public readonly struct ReactorSwitch : ICriticalNotifyCompletion
{
    private static readonly Action<object?> Resume = static continuation => ((Action)continuation!)();

    private readonly IRingHost? _reactor;

    public ReactorSwitch(IRingHost? reactor) => _reactor = reactor;

    public ReactorSwitch GetAwaiter() => this;

    public bool IsCompleted => _reactor is null || _reactor.OnReactorThread;

    public void OnCompleted(Action continuation) => _reactor!.ScheduleOnReactor(Resume, continuation);

    public void UnsafeOnCompleted(Action continuation) => _reactor!.ScheduleOnReactor(Resume, continuation);

    public void GetResult()
    {
    }
}
