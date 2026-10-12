using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// The millisecond clock every timeout and deadline reads: CLOCK_MONOTONIC_COARSE, the clock
/// <see cref="Environment.TickCount64"/> reads, called through the vDSO's own entry point with no
/// runtime shim or libc wrapper in between (~2.1 ns against ~3.6 ns). It returns what
/// Environment.TickCount64 returns, except under an LD_PRELOAD wrapper around libc's
/// clock_gettime (libfaketime), which it bypasses; so ioxide reads only this clock, and hands it
/// to the code it calls as nowMs.
/// </summary>
public static unsafe partial class Native {
    private const int CLOCK_MONOTONIC_COARSE = 6;
    private const int RTLD_LAZY   = 1;
    private const int RTLD_NOLOAD = 4;   // the same on glibc and musl

    // Null where no vDSO clock is found: Environment.TickCount64 serves.
    private static readonly delegate* unmanaged[SuppressGCTransition]<int, __kernel_timespec*, int> CoarseClock =
        FindCoarseClock();

    /// <summary>
    /// Milliseconds on CLOCK_MONOTONIC_COARSE, read straight from the vDSO: the clock of every ioxide
    /// timeout and deadline.
    /// </summary>
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

    internal static bool MonotonicMsFromVdso => CoarseClock != null;

    private static delegate* unmanaged[SuppressGCTransition]<int, __kernel_timespec*, int> FindCoarseClock()
    {
        // Our own dlopen, for RTLD_NOLOAD: it returns only an object already loaded, so a miss loads nothing.
        if (!NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "dlopen", out nint dlopenEntry))
        {
            return null;
        }

        var dlopen = (delegate* unmanaged<byte*, int, nint>)dlopenEntry;
        nint vdso;
        fixed (byte* glibcName = "linux-vdso.so.1\0"u8, muslName = "linux-gate.so.1\0"u8)
        {
            vdso = dlopen(glibcName, RTLD_LAZY | RTLD_NOLOAD);
            if (vdso == 0)
            {
                vdso = dlopen(muslName, RTLD_LAZY | RTLD_NOLOAD);
            }
        }

        // x86_64 exports __vdso_clock_gettime, arm64 __kernel_clock_gettime (vdso(7)).
        if (vdso == 0 ||
            (!NativeLibrary.TryGetExport(vdso, "__vdso_clock_gettime", out nint entry) &&
             !NativeLibrary.TryGetExport(vdso, "__kernel_clock_gettime", out entry)))
        {
            return null;
        }

        var clock = (delegate* unmanaged[SuppressGCTransition]<int, __kernel_timespec*, int>)entry;
        __kernel_timespec ts;
        return clock(CLOCK_MONOTONIC_COARSE, &ts) == 0 ? clock : null;
    }
}
