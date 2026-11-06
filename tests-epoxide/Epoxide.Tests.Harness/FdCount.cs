namespace Epoxide.Tests;

/// <summary>
/// Descriptor counting for the leak tests.
///
/// The count is process-global: a connection recycling late, the previous test's server still
/// letting go of its descriptors, or any unrelated BCL activity moves the number. Sleeping a fixed
/// 200 ms and hoping it has settled is what these tests used to do, and it is the likeliest thing in
/// the suite to go red for no reason.
///
/// <see cref="Stable"/> waits for the count to stop moving instead, which is the actual condition
/// those sleeps were standing in for.
/// </summary>
public static class FdCount
{
    /// <summary>Open descriptors right now, including every other test's.</summary>
    public static int Now() => Directory.EnumerateFileSystemEntries("/proc/self/fd").Count();

    /// <summary>
    /// Poll until two consecutive samples agree, then return that count. Falls back to the last
    /// sample if it never settles, so a busy machine yields a slightly noisy assertion rather than
    /// a hang.
    /// </summary>
    public static int Stable(int settleMs = 100, int timeoutMs = 5_000)
    {
        long deadlineMs = Environment.TickCount64 + timeoutMs;
        int previous = Now();

        while (Environment.TickCount64 < deadlineMs)
        {
            Thread.Sleep(settleMs);

            int current = Now();
            if (current == previous)
            {
                return current;
            }
            previous = current;
        }

        // Never settled. Say so: an fd assertion measured against a moving baseline is worth
        // knowing about when it fails, and silence here makes that impossible to diagnose.
        Console.Error.WriteLine($"[fdcount] never settled within {timeoutMs} ms; using {previous}");
        return previous;
    }
}
