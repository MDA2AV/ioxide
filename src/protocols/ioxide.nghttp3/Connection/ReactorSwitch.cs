using System.Runtime.CompilerServices;

namespace ioxide.nghttp3;

/// <summary>Awaiter that resumes its continuation on the given reactor's thread (via the reactor post queue).</summary>
internal readonly struct ReactorSwitch : ICriticalNotifyCompletion
{
    private readonly Reactor _reactor;
    public ReactorSwitch(Reactor reactor) => _reactor = reactor;
    public ReactorSwitch GetAwaiter() => this;
    public bool IsCompleted => false;
    public void OnCompleted(Action continuation) => _reactor.ScheduleOnReactor(static s => ((Action)s!)(), continuation);
    public void UnsafeOnCompleted(Action continuation) => _reactor.ScheduleOnReactor(static s => ((Action)s!)(), continuation);
    public void GetResult() { }
}
