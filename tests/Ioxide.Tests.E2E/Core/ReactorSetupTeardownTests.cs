using System.Net;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Teardown after a setup that FAILED. Run tears the ring down on every exit path, including a
/// throw from the setup sequence itself, so the fd tables it closes may only be half filled.
/// </summary>
/// <remarks>
/// The tables are <c>new int[n]</c>, so an unset slot reads as 0 - and 0 is stdin, not something
/// this library ever opened. Closing it is not a leak but the opposite: the number goes back to
/// the process and the next socket opened takes it, after which the next teardown to close 0
/// shuts a live connection belonging to somebody else. The same holds for <c>_wakeFd</c>, which
/// OpenWakeFd only sets near the end of setup.
///
/// /proc/self/fd/0 is the cheapest way to ask whether fd 0 is still open, and it needs no
/// P/Invoke: the entry exists exactly while the descriptor does.
/// </remarks>
internal static class ReactorSetupTeardownTests
{
    public static void Register(Runner runner)
    {
        runner.Test("reactor: a bind that fails tears down without closing stdin", () =>
        {
            Assert.True(File.Exists("/proc/self/fd/0"), "fd 0 must be open before the test says anything");

            // A plain listener sets neither SO_REUSEADDR nor SO_REUSEPORT, and a SO_REUSEPORT bind
            // is refused unless EVERY socket on the port asked for it. So the reactor's bind to
            // this port fails with EADDRINUSE - deterministically, and without needing privilege
            // or a race. That throw lands inside OpenTcpListeners, which runs before OpenWakeFd:
            // both _listenFds[0] and _wakeFd are still 0 when the finally calls Teardown.
            using var blocker = new TcpListener(IPAddress.Any, 0);
            blocker.Start();
            int port = ((IPEndPoint)blocker.LocalEndpoint).Port;

            var config = new ServerConfig
            {
                ReactorCount = 1,
                Tcp = new TcpOptions { Port = (ushort)port },
            };
            var reactor = new Reactor(0, config)
            {
                TcpHandle = (_, connection) =>
                {
                    connection.DecRef();
                    return Task.CompletedTask;
                },
            };

            Exception? failure = null;
            var thread = new Thread(() =>
            {
                try
                {
                    reactor.Run();
                }
                catch (Exception e)
                {
                    failure = e;
                }
            });
            thread.Start();

            Assert.True(thread.Join(TimeSpan.FromSeconds(10)),
                "the reactor should have failed its bind and returned, not parked in the loop");
            Assert.True(failure is not null,
                "binding a port already held without SO_REUSEPORT must fail the reactor");

            Assert.True(File.Exists("/proc/self/fd/0"),
                "teardown after the failed bind closed fd 0 - stdin - and the number is now free "
                + "for the next socket the process opens");
        });
    }
}
