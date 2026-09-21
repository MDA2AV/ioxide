using System.Net;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Teardown after a setup that FAILED. Run tears the ring down on every exit path, including a
/// throw from the setup sequence itself, so the fd tables it closes may only be half filled.
/// </summary>
/// <remarks>
/// The tables are <c>new int[n]</c>, so an unset slot reads as 0 - stdin, not something this
/// library opened. Closing it is the opposite of a leak: the number goes back to the process, the
/// next socket opened takes it, and the next teardown to close 0 shuts somebody else's live
/// connection. Same for <c>_wakeFd</c>, which OpenWakeFd sets only near the end of setup.
///
/// /proc/self/fd/0 answers whether fd 0 is open without a P/Invoke: it exists while it does.
/// </remarks>
internal static class ReactorSetupTeardownTests
{
    public static void Register(Runner runner)
    {
        runner.Test("reactor: a bind that fails tears down without closing stdin", () =>
        {
            Assert.True(File.Exists("/proc/self/fd/0"), "fd 0 must be open before the test says anything");

            // A SO_REUSEPORT bind is refused unless EVERY socket on the port asked for it, and a
            // plain listener asks for nothing - so this bind fails with EADDRINUSE, deterministically
            // and without privilege. The throw lands in OpenTcpListeners, which runs before
            // OpenWakeFd: _listenFds[0] and _wakeFd are both still 0 when the finally tears down.
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
