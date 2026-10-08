using System.Reflection;
using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="Native.MonotonicMs"/> replaces Environment.TickCount64 in every timeout and deadline,
/// and some stamps are still compared with values from Environment.TickCount64, so the two must be
/// the same clock to the millisecond, not merely close.
/// </summary>
internal static class ClockTests
{
    // Distinct readings to collect, so the comparison straddles that many coarse-clock ticks.
    private const int TicksToCross = 20;

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
            FieldInfo field = typeof(Native).GetField("CoarseClock", BindingFlags.NonPublic | BindingFlags.Static)
                ?? throw new InvalidOperationException("Native.CoarseClock not found");
            object? value = field.GetValue(null);
            nint entry = value is nint pointer ? pointer : 0;

            Assert.True(entry != 0, $"no vDSO clock_gettime was found (CoarseClock = {value ?? "null"}), so every read takes Environment.TickCount64's slower path");
        }, skip: RuntimeInformation.RuntimeIdentifier.Contains("musl"));
    }
}
