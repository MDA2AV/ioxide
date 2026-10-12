using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Descriptors a host's child processes must not inherit: a child holding a server's socket keeps it
/// open after the server closes it, and a held listener keeps the port.
/// </summary>
internal static class ExecInheritanceTests
{
    [DllImport("libc")]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc")]
    private static extern int close(int fd);

    public static void Register(Runner runner)
    {
        runner.Test("exec: a child process inherits none of the server's sockets", () =>
        {
            int udpPort = TestServer.DeadUdpPort();
            var accepted = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            RingSocket? ringSocket = null;

            (int port, _, _) = TestServer.StartConfigured(
                (_, conn) => HoldConnection(conn, accepted),
                new ServerConfig
                {
                    RecvBufferSize = 4096, RecvSlots = 64,
                    Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
                    Udp = new UdpOptions { Ports = [(ushort)udpPort] },
                },
                r => ringSocket = RingSocket.CreateTcp(r));

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(IPAddress.Loopback, port);
            client.Send([1]);
            Assert.True(accepted.Task.Wait(5_000), "the handler never saw the test's connection");

            // The control: a socket opened without close-on-exec is inherited, so a leak would be seen.
            int plain = socket(2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
            (string Kind, string Target)[] sockets =
            [
                ("listener", ExecInheritance.TcpListener(port)),
                ("accepted connection", accepted.Task.Result),
                ("udp socket", ExecInheritance.Udp(udpPort)),
                ("ring client socket", ExecInheritance.Target(ringSocket!.Fd)),
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
                ringSocket.Dispose();
            }

            foreach ((string kind, string target) in sockets)
            {
                Assert.True(target.StartsWith("socket:[", StringComparison.Ordinal), $"{kind}: not open in this process, so nothing was tested");
            }
            Assert.True(held.Contains(control), "control: the child did not inherit a plain socket, so a leak would go unseen");

            string[] leaked = sockets.Where(s => held.Contains(s.Target)).Select(s => s.Kind).ToArray();
            Assert.True(leaked.Length == 0, $"inherited by the child: {string.Join(", ", leaked)}");
        });
    }

    // Reports its descriptor once the test's client has sent (the harness's readiness probe never
    // does), then holds the connection until the client leaves.
    private static async Task HoldConnection(TcpConnection conn, TaskCompletionSource<string> accepted)
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    conn.ReturnBuffer(in item);
                }
            }

            if (!snapshot.IsClosed)
            {
                accepted.TrySetResult(ExecInheritance.Target(conn.ClientFd));
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
