using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// Config sizes the reactor cannot run with are refused when it is constructed, naming the property
/// (ioxide's #102). Passed through, they fail later - inside the loop or the first accept, where they
/// end or hang the reactor and the message names something the host never set. No reactor is run
/// here, so nothing binds.
/// </summary>
/// <remarks>
/// From ioxide's RingSetupMessageTests, whose other half - what a refused io_uring_setup says - has
/// no counterpart: epoxide sets up no ring. The ring-only sizes (RecvSlots, the Incremental block)
/// do not exist here; MaxEvents is epoxide's own.
/// </remarks>
internal static class ConfigValidationTests
{
    // fs/eventpoll.c: epoll_wait refuses maxevents above INT_MAX / sizeof(struct epoll_event).
    private static readonly int EpollMaxEvents = int.MaxValue / Native.EpollEventSize;

    public static void Register(Runner runner)
    {
        (string Case, string Property, ServerConfig Config)[] refused =
        [
            ("Tcp.RecvQueueEntries not a power of two", "config.Tcp.RecvQueueEntries",
                new ServerConfig { Tcp = new TcpOptions { RecvQueueEntries = 48 } }),
            ("Tcp.RecvQueueEntries of 0", "config.Tcp.RecvQueueEntries",
                new ServerConfig { Tcp = new TcpOptions { RecvQueueEntries = 0 } }),
            ("Tcp.WriteSlabSize of 0", "config.Tcp.WriteSlabSize",
                new ServerConfig { Tcp = new TcpOptions { WriteSlabSize = 0 } }),
            ("RecvBufferSize of 0", "config.RecvBufferSize",
                new ServerConfig { RecvBufferSize = 0 }),
            ("MaxEvents of 0", "config.MaxEvents",
                new ServerConfig { MaxEvents = 0 }),
        ];

        foreach ((string name, string property, ServerConfig config) in refused)
        {
            runner.Test($"config: {name} is refused at construction, by name", () =>
                Assert.Throws<ArgumentException>(() => _ = new Reactor(0, config), $"'{property}'"));
        }

        runner.KnownCoreBug("config: MaxEvents above what epoll_wait accepts is refused at construction, by name", () =>
        {
            // Constructed, it fails at the first epoll_wait - EINVAL, thrown from the loop - and the
            // event buffer it allocates first is sized in int arithmetic that wraps past this value.
            Assert.Throws<ArgumentException>(
                () => _ = new Reactor(0, new ServerConfig { MaxEvents = EpollMaxEvents + 1 }), "'config.MaxEvents'");
        }, bug: "E3: MaxEvents has no upper bound");

        runner.KnownCoreBug("control: the smallest sizes still construct", () =>
        {
            // ioxide constructs with one-byte buffers and a one-entry queue. epoxide's buffer pools keep
            // a free-list link in each free buffer, four bytes, and refuse anything smaller from inside
            // the pool - naming its own parameter, 'bufferSize', which no config has.
            _ = new Reactor(0, new ServerConfig
            {
                RecvBufferSize = 1,
                MaxEvents = 1,
                Tcp = new TcpOptions { RecvQueueEntries = 1, WriteSlabSize = 1 },
            });
        }, bug: "E2: RecvBufferSize/WriteSlabSize below 4 throw from BufferPool");

        runner.Test("control: the largest sizes still construct, and the smallest the pools can hold", () =>
        {
            _ = new Reactor(0, new ServerConfig
            {
                MaxEvents = EpollMaxEvents,
                Tcp = new TcpOptions { RecvQueueEntries = 1 << 30 },
            });
            _ = new Reactor(0, new ServerConfig
            {
                RecvBufferSize = sizeof(int),
                MaxEvents = 1,
                Tcp = new TcpOptions { RecvQueueEntries = 1, WriteSlabSize = sizeof(int) },
            });
        });
    }
}
