using System.Net;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TcpOptions.SendWaitAll"/>: whether sends carry MSG_WAITALL, bound onto every connection
/// at accept (#265). Before it there was no way to turn the flag off short of patching the library:
/// the slot started at MSG_WAITALL and <c>Clear()</c> put it back for every pooled connection.
/// </summary>
/// <remarks>
/// Here rather than in E2E because the flags are only half of it: switching them off must not also
/// switch off zero-copy, which the public setter does on purpose for kTLS, and the send a
/// connection uses is only visible from inside it (<see cref="TcpConnection.UseZc"/>, internal).
/// </remarks>
internal static class SendWaitAllTests
{
    private const uint MsgWaitAll = 0x100;

    public static void Register(Runner runner)
    {
        runner.Test("tcp: SendWaitAll off sends without MSG_WAITALL on fresh and pooled connections, and keeps ZeroCopySend (#265)", () =>
        {
            AssertEverySend("0 zc", Ask(Config(incremental: false, zeroCopy: true, waitAll: false)));
        });

        runner.Test("tcp: control: by default sends carry MSG_WAITALL", () =>
        {
            AssertEverySend($"{MsgWaitAll} zc", Ask(Config(incremental: false, zeroCopy: true, waitAll: true)));
        });

        runner.Test("tcp: SendWaitAll off reaches incremental-mode connections too", () =>
        {
            AssertEverySend("0 plain", Ask(Config(incremental: true, zeroCopy: false, waitAll: false)));
        }, skip: !TestServer.KernelAtLeast(6, 12));

        runner.Test("tcp: SendWaitAll off: a zero-copy response far past the socket buffer arrives whole, sent in short sends", () =>
        {
            // Without MSG_WAITALL each short SEND_ZC completes on its own, with its own notif, and the
            // reactor submits the rest: a path that only a failing send reached before.
            byte[] body = new byte[4 * 1024 * 1024];
            for (int i = 0; i < body.Length; i++)
            {
                body[i] = (byte)(i % 251);
            }

            (int port, _, _) = TestServer.StartConfigured(Respond(body), Config(incremental: false, zeroCopy: true, waitAll: false));

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                ReceiveBufferSize = 4096,   // before the connect, so the window the server sees is small
                ReceiveTimeout = 10_000,
            };
            client.Connect(IPAddress.Loopback, port);
            client.Send("?"u8);

            byte[] received = new byte[body.Length + 1];
            int got = 0, n;
            while ((n = client.Receive(received, got, received.Length - got, SocketFlags.None)) > 0)
            {
                got += n;
            }

            Assert.Equal(body.Length, got);
            Assert.True(received.AsSpan(0, got).SequenceEqual(body), "the response arrived out of order or corrupted");
        });
    }

    private static ServerConfig Config(bool incremental, bool zeroCopy, bool waitAll) => new()
    {
        RecvBufferSize = 4096,
        RecvSlots = 64,
        Incremental = incremental ? new IncrementalOptions { MaxConnections = 16, RecvSlots = 4, RecvBufferSize = 1024 } : null,
        Tcp = new TcpOptions
        {
            WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64,
            ZeroCopySend = zeroCopy,
            SendWaitAll = waitAll,
        },
    };

    /// <summary>
    /// What each served connection reported, as "0 zc fresh", "256 plain pooled" and so on. Two
    /// connections at once first: only the readiness probe has ended by then, so the pool can serve
    /// one of them at most and the other is a fresh object. Then one at a time until a pooled one is
    /// handed out.
    /// </summary>
    private static List<string> Ask(ServerConfig config)
    {
        var seen = new HashSet<TcpConnection>();
        (int port, _, _) = TestServer.StartConfigured(ReportSend(seen), config);

        var replies = new List<string>();
        using (Socket first = Connect(port), second = Connect(port))
        {
            replies.Add(Request(first));
            replies.Add(Request(second));
        }

        // A connection is pooled once the reactor has seen its peer close, which is its own event.
        for (int i = 0; i < 20 && !replies.Exists(r => r.EndsWith(" pooled", StringComparison.Ordinal)); i++)
        {
            using Socket next = Connect(port);
            replies.Add(Request(next));
        }

        return replies;
    }

    private static void AssertEverySend(string send, List<string> replies)
    {
        string all = string.Join(", ", replies);
        Assert.True(replies.Exists(r => r.EndsWith(" fresh", StringComparison.Ordinal))
                    && replies.Exists(r => r.EndsWith(" pooled", StringComparison.Ordinal)),
            $"a fresh and a pooled connection were not both served, so one of them was never asked: {all}");
        Assert.True(replies.TrueForAll(r => r.StartsWith(send + " ", StringComparison.Ordinal)),
            $"expected every connection to send with \"{send}\": {all}");
    }

    // Answers one request with this connection's op_flags and send, and whether an earlier
    // connection already used its TcpConnection. The readiness probe only connects, so it gets nothing.
    private static Func<Reactor, TcpConnection, Task> ReportSend(HashSet<TcpConnection> seen) => async (_, conn) =>
    {
        bool pooled;
        lock (seen)
        {
            pooled = !seen.Add(conn);
        }

        try
        {
            if (await Asked(conn))
            {
                conn.Write(Encoding.ASCII.GetBytes(
                    $"{conn.SendOpFlags} {(conn.UseZc ? "zc" : "plain")} {(pooled ? "pooled" : "fresh")}"));
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    };

    private static Func<Reactor, TcpConnection, Task> Respond(byte[] body) => async (_, conn) =>
    {
        try
        {
            if (await Asked(conn))
            {
                conn.Write(body);
                await conn.FlushAsync();
            }
        }
        finally
        {
            conn.DecRef();
        }
    };

    // Whether the first read brought bytes - the readiness probe's brings none.
    private static async Task<bool> Asked(TcpConnection conn)
    {
        RecvSnapshot snapshot = await conn.ReadAsync();
        bool asked = false;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                asked = true;
                conn.ReturnBuffer(in item);
            }
        }
        return asked;
    }

    private static Socket Connect(int port)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 5_000 };
        socket.Connect(IPAddress.Loopback, port);
        return socket;
    }

    // The reply, read up to the FIN the handler's release sends.
    private static string Request(Socket socket)
    {
        socket.Send("?"u8);

        var reply = new StringBuilder();
        var buffer = new byte[64];
        int n;
        while ((n = socket.Receive(buffer)) > 0)
        {
            reply.Append(Encoding.ASCII.GetString(buffer, 0, n));
        }
        return reply.ToString();
    }
}
