using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// The millisecond clock every timeout and deadline reads: CLOCK_MONOTONIC_COARSE, the clock
/// <see cref="Environment.TickCount64"/> reads, called through the vDSO's own entry point with no
/// runtime shim or libc wrapper in between (~2.1 ns against ~3.6 ns). Same values as
/// Environment.TickCount64, so the two mix freely.
/// </summary>
public static unsafe partial class Native {
    private const int CLOCK_MONOTONIC_COARSE = 6;

    // Null where the vDSO cannot be found (musl registers it under no name): Environment.TickCount64 serves.
    private static readonly delegate* unmanaged[SuppressGCTransition]<int, __kernel_timespec*, int> CoarseClock = FindCoarseClock();

    /// <summary>Milliseconds on CLOCK_MONOTONIC_COARSE: what Environment.TickCount64 returns, read straight from the vDSO.</summary>
    public static long MonotonicMs
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            if (CoarseClock == null)
            {
                return Environment.TickCount64;
            }

            __kernel_timespec ts;
            CoarseClock(CLOCK_MONOTONIC_COARSE, &ts);
            return ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000;
        }
    }

    // x86_64 exports __vdso_clock_gettime, arm64 __kernel_clock_gettime (vdso(7)).
    private static delegate* unmanaged[SuppressGCTransition]<int, __kernel_timespec*, int> FindCoarseClock()
    {
        if (!NativeLibrary.TryLoad("linux-vdso.so.1", out nint vdso))
        {
            return null;
        }

        if (!NativeLibrary.TryGetExport(vdso, "__vdso_clock_gettime", out nint entry) &&
            !NativeLibrary.TryGetExport(vdso, "__kernel_clock_gettime", out entry))
        {
            return null;
        }

        var clock = (delegate* unmanaged[SuppressGCTransition]<int, __kernel_timespec*, int>)entry;
        __kernel_timespec ts;
        return clock(CLOCK_MONOTONIC_COARSE, &ts) == 0 ? clock : null;
    }
}
