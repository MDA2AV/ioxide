using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static ioxide.Native;

namespace ioxide;

public sealed unsafe partial class Reactor
{
    // Periodic timer driving registered tickers (per-command timeout sweeps, pool replenishment).
    // Single-shot, re-armed each fire. One timer in flight per reactor.
    private __kernel_timespec* _timerTs;
    private const long TimerIntervalNs = 250_000_000;   // 250 ms
    private readonly List<Action> _tickers = [];

    /// <summary>
    /// Register a callback invoked on the reactor thread every timer interval (~250 ms). Call from
    /// <c>OnStart</c>. Pools use it to sweep per-command timeouts and replenish connections.
    /// </summary>
    public void AddTicker(Action ticker) => _tickers.Add(ticker);

    // Armed before the loop starts; the timespec is freed in Teardown, after the ring fd closes.
    private void StartTicker()
    {
        _timerTs = (__kernel_timespec*)NativeMemory.Alloc((nuint)sizeof(__kernel_timespec));
        _timerTs->tv_sec  = 0;
        _timerTs->tv_nsec = TimerIntervalNs;
        ArmTimer();
    }

    private void ArmTimer()
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_TIMEOUT;
        sqe->addr      = (ulong)_timerTs;
        sqe->len       = 1;
        sqe->off       = 0;            // pure time-based (no completion-count trigger)
        sqe->user_data = Tag(KindTimer, 0, 0);
    }
}
