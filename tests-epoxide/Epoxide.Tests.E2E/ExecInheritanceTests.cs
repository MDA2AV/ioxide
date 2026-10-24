using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// Descriptors a host's child processes must not inherit: a child holding a server's socket keeps it
/// open after the server closes it, and a held listener keeps the port.
/// </summary>
/// <remarks>
/// ioxide's version also covers a UDP socket and a ring client socket; epoxide has no UDP, and its
/// counterparts of the ring's own descriptors are the reactor's epoll set and eventfd, plus the
/// socket of an outbound connection (<see cref="Reactor.ConnectAsync"/>).
/// </remarks>
internal static class ExecInheritanceTests
{
    [DllImport("libc")]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc")]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int fcntl(int fd, int command);

    private const int FGetFd = 1;
    private const int FdCloexec = 1;

    public static void Register(Runner runner)
    {
        runner.Test("exec: a child process inherits none of the server's descriptors", () =>
        {
            var accepted = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, _) = TestServer.StartConfigured(
                (_, conn) => HoldConnection(conn, accepted),
                new ServerConfig
                {
                    RecvBufferSize = 4096,
                    Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
                });

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(IPAddress.Loopback, port);
            client.Send([1]);
            Assert.True(accepted.Task.Wait(5_000), "the handler never saw the test's connection");

            // An outbound connection of the same reactor, to its own listener.
            Task<TcpConnection> connecting = reactor.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
            Assert.True(connecting.Wait(5_000), "the outbound connect never settled");
            TcpConnection outbound = connecting.Result;

            // The control: a socket opened without close-on-exec is inherited, so a leak would be seen.
            int plain = socket(2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
            (string Kind, string Target)[] sockets =
            [
                ("listener", ExecInheritance.TcpListener(port)),
                ("accepted connection", accepted.Task.Result),
                ("outbound connection", ExecInheritance.Target(outbound.ClientFd)),
            ];
            string control = ExecInheritance.Target(plain);

            HashSet<string> held;
            try
            {
                held = ExecInheritance.HeldByChild();
            }
            finally
            {
                close(plain);
                outbound.DecRef();
            }

            foreach ((string kind, string target) in sockets)
            {
                Assert.True(target.StartsWith("socket:[", StringComparison.Ordinal), $"{kind}: not open in this process, so nothing was tested");
            }
            Assert.True(held.Contains(control), "control: the child did not inherit a plain socket, so a leak would go unseen");

            string[] leaked = sockets.Where(s => held.Contains(s.Target)).Select(s => s.Kind).ToArray();
            Assert.True(leaked.Length == 0, $"inherited by the child: {string.Join(", ", leaked)}");

            // The epoll set and the eventfd are anonymous inodes, every one of a kind named alike, so a
            // child's table cannot say WHICH it got: their close-on-exec flag is asked directly instead.
            (string Kind, int Fd)[] own =
            [
                ("epoll set", Internals.EpollFd(reactor)),
                ("eventfd", Internals.WakeFd(reactor)),
            ];
            foreach ((string kind, int fd) in own)
            {
                int flags = fcntl(fd, FGetFd);
                Assert.True(flags >= 0, $"{kind}: fd {fd} is not open, so nothing was tested");
                Assert.True((flags & FdCloexec) != 0, $"{kind}: fd {fd} has no close-on-exec, so every child the host starts inherits it");
            }
        });
    }

    // Reports its descriptor once the test's client has sent (the harness's readiness probe never
    // does), then holds the connection until the client leaves.
    private static async Task HoldConnection(TcpConnection conn, TaskCompletionSource<string> accepted)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            bool received = false;
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    received = true;
                    conn.ReturnBuffer(in item);
                }
            }

            if (received && !snapshot.IsClosed)
            {
                accepted.TrySetResult(ExecInheritance.Target(conn.ClientFd));
            }

            if (!snapshot.IsClosed)
            {
                conn.ResetRead();
                await conn.ReadAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }
}
