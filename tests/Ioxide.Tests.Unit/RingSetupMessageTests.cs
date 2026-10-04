using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// What a refused io_uring_setup says (#270). "errno 22" on its own sent people to limits and
/// permissions, when the usual cause is a kernel older than the setup flags - WSL2's 5.15 refused
/// both attempts with EINVAL.
/// </summary>
internal static class RingSetupMessageTests
{
    public static void Register(Runner runner)
    {
        runner.Test("ring setup: a kernel older than 6.1 is named as the cause", () =>
        {
            string message = Ring.DescribeSetupFailure(22, 8192, "5.15.167.4-microsoft-standard-WSL2");

            Assert.True(message.Contains("5.15.167.4-microsoft-standard-WSL2") && message.Contains("Linux 6.1 or later"),
                $"the message does not say the kernel is too old: {message}");
        });

        runner.Test("ring setup: too many entries is named, not the kernel", () =>
        {
            string message = Ring.DescribeSetupFailure(22, 65_536, "6.14.0-37-generic");

            Assert.True(message.Contains("at most 32768"), $"the message does not name the entry limit: {message}");
            Assert.True(!message.Contains("6.1 or later"), $"a 6.14 kernel was blamed for being too old: {message}");
        });

        runner.Test("ring setup: io_uring disabled by policy says so", () =>
        {
            string message = Ring.DescribeSetupFailure(1, 8192, "6.14.0-37-generic");

            Assert.True(message.Contains("disabled"), $"EPERM was not explained: {message}");
        });
    }
}
