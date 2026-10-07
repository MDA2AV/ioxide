namespace ioxide;

public sealed unsafe partial class Reactor
{
    // Registered tickers (per-command timeout sweeps, pool replenishment), run by the loop every
    // TickMs. No timer of their own: the loop's wait is bounded by the next run.
    private long _nextTickMs;
    private readonly List<Action> _tickers = [];

    /// <summary>
    /// The ticker's interval: the granularity of every sweep.
    /// </summary>
    public const int TickMs = 250;

    /// <summary>
    /// Register a callback invoked on the reactor thread every timer interval (~250 ms). Call from
    /// <c>OnStart</c>. Pools use it to sweep per-command timeouts and replenish connections.
    /// </summary>
    public void AddTicker(Action ticker) => _tickers.Add(ticker);

    // The first run is one interval after the loop starts.
    private void StartTicker()
    {
        NowMs = Environment.TickCount64;
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

    // The loop's wait, bounded by the next ticker run and the earliest engine deadline.
    private int WaitForCompletions()
    {
        // No QUIC connections left: the tracked deadline is the last one's leftover.
        long quicDue = _quicConnSet.Count == 0 ? long.MaxValue : _quicNextTimeoutMs;
        long wakeAt = Math.Min(_nextTickMs, quicDue);

        // Not NowMs: that was read before this pass's work, and the wait would oversleep by all of it.
        long now = Environment.TickCount64;

        // +1: the ms clock can read just short of the deadline when the kernel's timer wakes us.
        return _ring.SubmitAndWait(1, Math.Max(0, wakeAt - now) + 1);
    }
}
