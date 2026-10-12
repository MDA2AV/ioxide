using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="Native.MonotonicMs"/> is the clock of every ioxide timeout and deadline. It must be
/// CLOCK_MONOTONIC_COARSE in milliseconds, exactly what Environment.TickCount64 reads, and it must
/// actually come from the vDSO wherever the process has one.
/// </summary>
internal static class ClockTests
{
    // Distinct readings to collect, so the comparison straddles that many coarse-clock ticks.
    private const int TicksToCross = 20;

    // getauxval(3): the vDSO's address in this process, 0 when none is mapped.
    private const nuint AT_SYSINFO_EHDR = 33;

    [DllImport("libc")]
    private static extern nuint getauxval(nuint type);

    public static void Register(Runner runner)
    {
        runner.Test("clock: Native.MonotonicMs reads the clock Environment.TickCount64 reads", () =>
        {
            // Bracketed by two reads of the coarse clock, so a finer or different clock lands outside
            // the bracket as soon as it runs ahead of a tick the coarse clock has not taken yet.
            long last = long.MinValue;
            int distinct = 0;
            long reads = 0;
            while (distinct < TicksToCross)
            {
                long before = Environment.TickCount64;
                long now = Native.MonotonicMs;
                long after = Environment.TickCount64;
                reads++;

                Assert.True(before <= now && now <= after,
                    $"read {reads}: Native.MonotonicMs gave {now}, outside Environment.TickCount64's {before}..{after}");
                if (now != last)
                {
                    last = now;
                    distinct++;
                }
            }
        });

        runner.Test("clock: Native.MonotonicMs goes through the vDSO, not the fallback", () =>
        {
            // The fallback is correct but slower, so a lookup that silently fails would pass the test above.
            Assert.True(Native.MonotonicMsFromVdso,
                "this process maps a vDSO, but no clock_gettime was found in it, "
                + "so every read takes Environment.TickCount64's slower path");
        }, skip: RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64)
                 || getauxval(AT_SYSINFO_EHDR) == 0);
    }
}
