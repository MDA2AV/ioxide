using System.Threading.Tasks.Sources;
using epoxide.utils;

namespace epoxide;

/// <summary>
/// A wait that completes on a reactor's thread - ioxide's RingTimer, with the deadline held by the
/// reactor's timer queue instead of the ring. The awaiter resumes inline when it is on that reactor,
/// and on its own context or the thread pool when it is not.
///
/// One wait in flight per timer: hold one per connection, or one per thing that waits. Zero
/// allocation per wait once constructed (one is posted when armed from another thread).
/// </summary>
public sealed class ReactorTimer : ITimerCompletion, IValueTaskSource<int>
{
    /// <summary>
    /// What a ring timeout reports on expiry, kept so code written against ioxide's RingTimer reads
    /// the same: <see cref="Expired"/> accepts it, though this timer completes with 0.
    /// </summary>
    public const int ETime = -62;

    /// <summary>What a wait completes with when its reactor stopped first: -ECANCELED, which <see cref="Expired"/> refuses.</summary>
    public const int ECanceled = -125;

    private const long NanosecondsPerMillisecond = 1_000_000L;

    private readonly Reactor _reactor;
    private ManualResetValueTaskSourceCore<int> _core;
    private volatile bool _inFlight;

    public ReactorTimer(Reactor reactor)
    {
        _reactor = reactor ?? throw new ArgumentNullException(nameof(reactor));
    }

    /// <summary>Completes once <paramref name="milliseconds"/> have elapsed.</summary>
    public ValueTask<int> DelayAsync(int milliseconds) => DelayNanosecondsAsync(milliseconds * NanosecondsPerMillisecond);

    /// <summary>Completes once <paramref name="delay"/> has elapsed.</summary>
    public ValueTask<int> DelayAsync(TimeSpan delay) => DelayNanosecondsAsync((long)(delay.TotalMilliseconds * NanosecondsPerMillisecond));

    /// <summary>Completes once <paramref name="nanoseconds"/> have elapsed; at or below zero, on the next pass.</summary>
    public ValueTask<int> DelayNanosecondsAsync(long nanoseconds)
    {
        if (_inFlight)
        {
            throw new InvalidOperationException("A wait is already in flight on this ReactorTimer.");
        }

        _inFlight = true;
        _core.Reset();
        var pending = new ValueTask<int>(this, _core.Version);
        _reactor.ScheduleTimer(Math.Max(0, nanoseconds), this);
        return pending;
    }

    /// <summary>True for a completion that is the timer expiring rather than an error.</summary>
    public static bool Expired(int result) => result == 0 || result == ETime;

    void ITimerCompletion.Expire()
    {
        // Cleared before SetResult: the inline continuation may arm the next wait.
        _inFlight = false;
        _core.SetResult(0);
    }

    void ITimerCompletion.Cancel()
    {
        _inFlight = false;
        _core.SetResult(ECanceled);
    }

    int IValueTaskSource<int>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<int>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<int>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
        => Continuations.OnCompleted(ref _core, _reactor, continuation, state, token, flags);
}
