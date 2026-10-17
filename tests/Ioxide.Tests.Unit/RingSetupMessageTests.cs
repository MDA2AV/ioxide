using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// What a refused io_uring_setup says (#270). "errno 22" on its own sent people to limits and
/// permissions, when the usual cause is a kernel older than the setup flags - WSL2's 5.15 refused
/// both attempts with EINVAL.
/// </summary>
/// <remarks>
/// The config sizes the reactor cannot run with go the same way (#102): they passed construction and
/// failed at the first accept, inside CQE dispatch, where they ended or hung the reactor. Construction
/// refuses them now and names the property. No reactor is run here, so nothing binds.
/// </remarks>
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

        RegisterConfigSizes(runner);
    }

    private static void RegisterConfigSizes(Runner runner)
    {
        (string Case, string Property, ServerConfig Config)[] refused =
        [
            ("Tcp.RecvQueueEntries not a power of two", "config.Tcp.RecvQueueEntries",
                new ServerConfig { Tcp = new TcpOptions { RecvQueueEntries = 48 } }),
            ("Tcp.WriteSlabSize of 0", "config.Tcp.WriteSlabSize",
                new ServerConfig { Tcp = new TcpOptions { WriteSlabSize = 0 } }),
            ("RecvSlots not a power of two", "config.RecvSlots",
                new ServerConfig { RecvSlots = 3000 }),
            ("RecvSlots above 32768", "config.RecvSlots",
                new ServerConfig { RecvSlots = 65_536 }),
            ("RecvBufferSize of 0", "config.RecvBufferSize",
                new ServerConfig { RecvBufferSize = 0 }),
            ("Incremental.RecvSlots not a power of two", "config.Incremental.RecvSlots",
                new ServerConfig { Incremental = new IncrementalOptions { RecvSlots = 24 } }),
            ("Incremental.RecvSlots above 32768", "config.Incremental.RecvSlots",
                new ServerConfig { Incremental = new IncrementalOptions { RecvSlots = 65_536 } }),
            ("Incremental.RecvBufferSize of 0", "config.Incremental.RecvBufferSize",
                new ServerConfig { Incremental = new IncrementalOptions { RecvBufferSize = 0 } }),
            ("Incremental.MaxConnections of 0", "config.Incremental.MaxConnections",
                new ServerConfig { Incremental = new IncrementalOptions { MaxConnections = 0 } }),
            ("Incremental.MaxConnections above 65534", "config.Incremental.MaxConnections",
                new ServerConfig { Incremental = new IncrementalOptions { MaxConnections = 65_535 } }),
        ];

        foreach ((string name, string property, ServerConfig config) in refused)
        {
            runner.Test($"config: {name} is refused at construction, by name", () =>
                Assert.Throws<ArgumentException>(() => _ = new Reactor(0, config), $"'{property}'"));
        }

        runner.Test("control: the largest sizes the kernel and the gid space take still construct", () =>
        {
            _ = new Reactor(0, new ServerConfig
            {
                RecvSlots = 32_768,
                Tcp = new TcpOptions { RecvQueueEntries = 1, WriteSlabSize = 1 },
            });
            _ = new Reactor(0, new ServerConfig
            {
                Incremental = new IncrementalOptions { RecvSlots = 32_768, MaxConnections = 65_534, RecvBufferSize = 1 },
            });
        });
    }
}
