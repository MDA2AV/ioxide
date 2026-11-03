using System.Net;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TcpOptions.ZeroCopySend"/> is bound onto every connection at accept, in both recv
/// modes. Only the shared-ring branch of the accept set it, so incremental-mode connections sent
/// with plain SEND whatever the option said (#100). And the binding must pick the opcode: SEND_ZC
/// with it, plain SEND without.
/// </summary>
/// <remarks>
/// Here rather than in E2E because the send a connection uses is only visible from inside it
/// (<see cref="TcpConnection.UseZc"/>, internal): on loopback a zero-copy send and a plain one put
/// the same bytes on the wire.
/// </remarks>
internal static class ZeroCopySendTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tcp: ZeroCopySend reaches incremental-mode connections, fresh and pooled alike (#100)", () =>
        {
            AssertEverySend("zc", Ask(Config(incremental: true, zeroCopy: true)));
        }, skip: !TestServer.KernelAtLeast(6, 12));

        runner.Test("tcp: control: ZeroCopySend reaches shared-mode connections, fresh and pooled alike", () =>
        {
            AssertEverySend("zc", Ask(Config(incremental: false, zeroCopy: true)));
        });

        runner.Test("tcp: control: an incremental-mode connection without ZeroCopySend sends plain", () =>
        {
            AssertEverySend("plain", Ask(Config(incremental: true, zeroCopy: false)));
        }, skip: !TestServer.KernelAtLeast(6, 12));

        runner.Test("tcp: a ZeroCopySend connection sends with SEND_ZC, so its flush waits for the notif until the peer reads", () =>
        {
            AssertSentWith(zeroCopy: true);
        });

        runner.Test("tcp: control: a connection without ZeroCopySend sends with plain SEND, so its flush ends before the peer reads", () =>
        {
            AssertSentWith(zeroCopy: false);
        });
    }

    /// <summary>Far past what the peer's 4 KB window takes, well inside the server's socket send buffer.</summary>
    private const int UnreadBytes = 256 * 1024;

    /// <summary>
    /// Against a peer that reads nothing, a plain SEND completes once its bytes are in the socket, and
    /// the flush with it. A SEND_ZC completes owing a notif (<see cref="TcpConnection.ZcNotifPending"/>)
    /// that comes only once the peer has acked every byte, and the flush waits for it.
    /// </summary>
    private static void AssertSentWith(bool zeroCopy)
    {
        var writing = new TaskCompletionSource<TcpConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
        var flushed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        (int port, _, _) = TestServer.StartConfigured(async (_, conn) =>
        {
            try
            {
                if (await Asked(conn))
                {
                    conn.Write(new byte[UnreadBytes]);
                    writing.TrySetResult(conn);
                    await conn.FlushAsync();
                    flushed.TrySetResult();
                }
            }
            finally
            {
                conn.DecRef();
            }
        }, Config(incremental: false, zeroCopy));

        // Never read: draining through a 4 KB window takes seconds, and the close resets a parked send.
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            ReceiveBufferSize = 4096,   // before the connect, so the window the server sees is small
        };
        client.Connect(IPAddress.Loopback, port);
        client.Send("?"u8);

        Assert.True(writing.Task.Wait(5_000), "the handler never wrote its response");
        TcpConnection conn = writing.Task.Result;

        // Either send settles with the peer still not reading: the flush has ended, or a notif is owed.
        Assert.True(SpinWait.SpinUntil(() => flushed.Task.IsCompleted || Volatile.Read(ref conn.ZcNotifPending) != 0, 5_000),
            "the send never completed into the socket");
        bool notifOwed = Volatile.Read(ref conn.ZcNotifPending) != 0;
        bool ended = flushed.Task.IsCompleted;

        Assert.True(client.Available < UnreadBytes,
            "the peer's window took the whole response unread, so a SEND_ZC would have ended too and this proved nothing");

        if (zeroCopy)
        {
            Assert.True(notifOwed && !ended,
                "the zero-copy connection's flush ended before the peer read, with no notif owed: it was sent with plain SEND");
        }
        else
        {
            Assert.True(ended && !notifOwed,
                "the plain connection's send completed owing a notif: it was sent with SEND_ZC");
        }
    }

    private static ServerConfig Config(bool incremental, bool zeroCopy) => new()
    {
        RecvBufferSize = 4096,
        RecvSlots = 64,
        Incremental = incremental ? new IncrementalOptions { MaxConnections = 16, RecvSlots = 4, RecvBufferSize = 1024 } : null,
        Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64, ZeroCopySend = zeroCopy },
    };

    /// <summary>
    /// What each served connection reported, as "zc fresh", "plain pooled" and so on. Two connections
    /// at once first: only the readiness probe has ended by then, so the pool can serve one of them at
    /// most and the other is a fresh object. Then one at a time until a pooled one is handed out.
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
            $"expected every connection to send {send}: {all}");
    }

    // Answers one request with the send this connection was accepted with, and whether an earlier
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

            if (asked)
            {
                conn.Write(Encoding.ASCII.GetBytes($"{(conn.UseZc ? "zc" : "plain")} {(pooled ? "pooled" : "fresh")}"));
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
