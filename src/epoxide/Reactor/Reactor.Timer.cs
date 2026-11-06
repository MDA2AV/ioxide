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
        if (_stopped)
        {
            // No loop will run it: cancelled, on the pool, as the teardown cancels the rest.
            ThreadPool.UnsafeQueueUserWorkItem(static timer => timer.Cancel(), completion, preferLocal: false);
            return;
        }

        if (OnReactorThread)
        {
            _timers.Enqueue(completion, due);
            return;
        }

        ScheduleOnReactor(static s =>
        {
            var (reactor, timer, at) = ((Reactor, ITimerCompletion, long))s!;

            // Run on the pool by a stopped reactor (ScheduleOnReactor): no loop will expire it.
            if (reactor._stopped)
            {
                timer.Cancel();
                return;
            }
            reactor._timers.Enqueue(timer, at);
        }, (this, completion, due));
    }

    // Teardown, after _stopped: every timer still queued is cancelled. Counted first, so a
    // continuation that arms again - which ScheduleTimer now cancels on the pool - cannot keep this
    // loop going.
    private void CancelTimers()
    {
        for (int n = _timers.Count; n > 0 && _timers.TryDequeue(out ITimerCompletion? timer, out _); n--)
        {
            try
            {
                timer.Cancel();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[r{_id}] timer continuation threw: {e}");
            }
        }
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

    private static readonly double NanosecondsPerTick = 1e9 / Stopwatch.Frequency;

    // The loop's wait in ns: until the next ticker run or timer, whichever is first; 0 with work queued.
    private long WaitTimeoutNs()
    {
        if (!_postQ.IsEmpty || !_registerQ.IsEmpty || !_closeQ.IsEmpty || !_recycleQ.IsEmpty)
        {
            return 0;
        }

        // Not NowMs: that was read before this pass's work, and the wait would oversleep by all of it.
        // +1 ms for the ticker's coarse clock, so the reading after the wait is past its deadline.
        long ns = (Math.Max(0, _nextTickMs - Native.MonotonicMs) + 1) * 1_000_000;
        if (_timers.TryPeek(out _, out long due))
        {
            // To the deadline itself: the wait never ends before it, and anything later is a late timer.
            ns = Math.Min(ns, Math.Max(0, (long)((due - Stopwatch.GetTimestamp()) * NanosecondsPerTick)));
        }

        return ns;
    }
}

/// <summary>A one-shot reactor timer's completion (<see cref="ReactorTimer"/>).</summary>
internal interface ITimerCompletion
{
    void Expire();

    /// <summary>The reactor stopped before the deadline: complete without having expired.</summary>
    void Cancel();
}
