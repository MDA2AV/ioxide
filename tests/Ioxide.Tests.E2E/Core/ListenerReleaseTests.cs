using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// What a stop gives back: the listening port. An armed multishot accept holds a reference of its own to
/// the socket until the ring's deferred cancel lets go of it, so closing the listener's descriptor alone
/// leaves the port bound, and accepting, for a while after the reactor has stopped.
/// </summary>
internal static class ListenerReleaseTests
{
    private const int EADDRINUSE = 98;

    public static void Register(Runner runner)
    {
        // The control for the pending test below: a listener of our own cannot share the port with the
        // server's, so the bind there tells a released port from a held one.
        runner.Test("control: while a reactor listens, a listener of our own on its port is refused with EADDRINUSE", () =>
        {
            (int port, _, _) = TestServer.StartConfigured(Handlers.Raw, Config());
            AssertServes(port);

            Assert.Equal(EADDRINUSE, BindPlain(port));
        });

        // Without the shutdown the port stayed bound 52-54 ms after the join, in every round, and a connect in
        // that window completed and was never answered (#432).
        runner.Test("reactor: after Stop and a join, the port refuses connections and can be bound again", () =>
        {
            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(Handlers.Raw, Config());
            AssertServes(port);

            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");

            Assert.True(Refused(port), "a connect after Stop and a join was accepted, with nothing left to serve it");

            int errno = BindPlain(port);
            Assert.True(errno == 0, $"binding the port after Stop and a join failed with errno {errno}");
        });
    }

    private static bool Refused(int port)
    {
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            client.Connect(IPAddress.Loopback, port);
            return false;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return true;
        }
    }

    private static ServerConfig Config() => new()
    {
        RecvBufferSize = 4096, RecvSlots = 64,
        Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
    };

    private static void AssertServes(int port)
    {
        (int status, string body) = Client.Get(port, "/");
        Assert.Equal(200, status);
        Assert.Equal("ok", body);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SockAddrIn
    {
        public ushort Family;
        public ushort Port;       // network order
        public uint Address;      // 0: INADDR_ANY, as the server binds
        public ulong Zero;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int name, ref int value, int length);

    [DllImport("libc", SetLastError = true)]
    private static extern int bind(int fd, ref SockAddrIn address, int length);

    [DllImport("libc", SetLastError = true)]
    private static extern int listen(int fd, int backlog);

    [DllImport("libc")]
    private static extern int close(int fd);

    // A listener as most servers open one, SO_REUSEADDR without SO_REUSEPORT, on 0.0.0.0: 0 once it binds
    // and listens, else the errno. Unlike another ioxide listener it cannot join a port that is still held.
    private static int BindPlain(int port)
    {
        int fd = socket(2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
        Assert.True(fd >= 0, $"socket failed with errno {Marshal.GetLastPInvokeError()}");
        try
        {
            int one = 1;
            setsockopt(fd, 1 /* SOL_SOCKET */, 2 /* SO_REUSEADDR */, ref one, sizeof(int));

            var address = new SockAddrIn { Family = 2, Port = (ushort)IPAddress.HostToNetworkOrder((short)port) };
            if (bind(fd, ref address, Marshal.SizeOf<SockAddrIn>()) != 0)
            {
                return Marshal.GetLastPInvokeError();
            }

            return listen(fd, 16) == 0 ? 0 : Marshal.GetLastPInvokeError();
        }
        finally
        {
            close(fd);
        }
    }
}
