using System.Diagnostics;

namespace epoxide;

/// <summary>
/// Time on the reactor: tickers (the ~250 ms sweeps), and one-shot timers that complete on the
/// reactor thread (<see cref="ReactorTimer"/>). Neither has a descriptor of its own - the loop's
/// epoll_wait is bounded by whichever is due first.
/// </summary>
public sealed unsafe partial class Reactor
{
    private long _nextTickMs;
    private readonly List<Action> _tickers = [];

    /// <summary>The ticker's interval: the granularity of every sweep.</summary>
    public const int TickMs = 250;

    /// <summary>
    /// Register a callback invoked on the reactor thread every timer interval (~250 ms). Call from
    /// <c>OnStart</c>.
    /// </summary>
    public void AddTicker(Action ticker) => _tickers.Add(ticker);

    private void StartTicker()
    {
        NowMs = Native.MonotonicMs;
        _nextTickMs = NowMs + TickMs;
    }

    // Checked on every pass, not left to the wait running out: a busy reactor's wait never does.
    private void RunDueTickers()
    {
        if (NowMs < _nextTickMs)
        {
            return;
        }
        _nextTickMs = NowMs + TickMs;

        for (int i = 0; i < _tickers.Count; i++)
        {
            try
            {
                _tickers[i]();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[r{_id}] ticker faulted: {e.Message}");
            }
        }
    }

    // Timers by deadline in Stopwatch ticks. Reactor thread only; a timer armed elsewhere is posted.
    private readonly PriorityQueue<ITimerCompletion, long> _timers = new();

    /// <summary>
    /// Complete <paramref name="completion"/> on this reactor's thread once <paramref name="nanoseconds"/>
    /// have passed. Safe from any thread: off the reactor the arming itself is posted.
    /// </summary>
    internal void ScheduleTimer(long nanoseconds, ITimerCompletion completion)
    {
        long due = Stopwatch.GetTimestamp() + (long)(nanoseconds * (Stopwatch.Frequency / 1e9));
        if (OnReactorThread)
        {
            _timers.Enqueue(completion, due);
            return;
        }

        ScheduleOnReactor(static s =>
        {
            var (reactor, timer, at) = ((Reactor, ITimerCompletion, long))s!;
            reactor._timers.Enqueue(timer, at);
        }, (this, completion, due));
    }

    private void RunDueTimers()
    {
        if (_timers.Count == 0)
        {
            return;
        }

        long now = Stopwatch.GetTimestamp();
        while (_timers.TryPeek(out ITimerCompletion? timer, out long due) && due <= now)
        {
            _timers.Dequeue();
            try
            {
                timer.Expire();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[r{_id}] timer continuation threw: {e}");
            }
        }
    }

    // The loop's wait in ms: until the next ticker run or timer, whichever is first; 0 with work queued.
    private int WaitTimeoutMs()
    {
        if (!_postQ.IsEmpty || !_registerQ.IsEmpty || !_closeQ.IsEmpty || !_recycleQ.IsEmpty)
        {
            return 0;
        }

        // Not NowMs: that was read before this pass's work, and the wait would oversleep by all of it.
        long untilTick = Math.Max(0, _nextTickMs - Native.MonotonicMs);
        if (_timers.TryPeek(out _, out long due))
        {
            // Rounded up, so a timer never fires early; +1 for the coarse clock reading just short.
            long untilTimer = (due - Stopwatch.GetTimestamp()) * 1000 / Stopwatch.Frequency + 1;
            untilTick = Math.Min(untilTick, Math.Max(0, untilTimer));
        }

        return (int)Math.Min(untilTick + 1, int.MaxValue);
    }
}

/// <summary>A one-shot reactor timer's completion (<see cref="ReactorTimer"/>).</summary>
internal interface ITimerCompletion
{
    void Expire();
}
