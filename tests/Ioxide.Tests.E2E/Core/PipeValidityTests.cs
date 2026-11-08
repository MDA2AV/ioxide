using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// IsValid on the TCP pipe reader, writer and dual pipe. A TcpConnection is pooled, so code that keeps one past
/// DecRef calls it to tell whether the connection is still its client's.
/// </summary>
internal static class PipeValidityTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tcp: a pipe reader is valid in the connection's life it was made in, and a kept one is not in the next", () =>
        {
            Assert.Equal("ok", AcrossTwoLives(conn => new TcpConnectionPipeReader(conn), r => r.IsValid(), r => r.Complete()));
        });

        runner.Test("tcp: a pipe writer is valid in the connection's life it was made in, and a kept one is not in the next", () =>
        {
            Assert.Equal("ok", AcrossTwoLives(conn => new TcpConnectionPipeWriter(conn), w => w.IsValid(), w => w.Complete()));
        });

        runner.Test("tcp: a dual pipe is valid in the connection's life it was made in, and a kept one is not in the next", () =>
        {
            Assert.Equal("ok", AcrossTwoLives(conn => new TcpConnectionDualPipe(conn), p => p.IsValid(), p =>
            {
                p.Input.Complete();
                p.Output.Complete();
            }));
        });
    }

    /// <summary>
    /// Two clients in turn. The first one's handler makes an adapter and keeps it; the second client gets the same
    /// pooled object, and its handler reports whether the kept adapter still says it is valid.
    /// </summary>
    private static string AcrossTwoLives<T>(Func<TcpConnection, T> make, Func<T, bool> isValid, Action<T> complete) where T : class
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        TcpConnection? firstObject = null;
        T? kept = null;

        int port = TestServer.Start(async (_, conn) =>
        {
            try
            {
                if (!await SentSomething(conn))
                {
                    return;   // the harness probe
                }

                T made = make(conn);
                try
                {
                    if (!isValid(made))
                    {
                        outcome.TrySetResult("a new one is not valid on its own connection");
                    }
                    else if (firstObject is null)
                    {
                        (firstObject, kept) = (conn, made);
                    }
                    else if (!ReferenceEquals(firstObject, conn))
                    {
                        outcome.TrySetResult("the pool did not hand on the same object, so this proves nothing");
                    }
                    else
                    {
                        outcome.TrySetResult(isValid(kept!) ? "a kept one is still valid in the connection's next life" : "ok");
                    }
                }
                finally
                {
                    complete(made);
                }
            }
            finally
            {
                conn.DecRef();
            }
        });

        using (var first = new TcpClient { ReceiveTimeout = 3_000 })
        {
            first.Connect("127.0.0.1", port);
            first.GetStream().Write("A"u8);
            Assert.Equal(0, first.GetStream().Read(new byte[16]));   // the handler let go, so the server closed
        }
        Thread.Sleep(100);   // its connection goes back to the pool

        using var second = new TcpClient();
        second.Connect("127.0.0.1", port);
        second.GetStream().Write("B"u8);

        Assert.True(outcome.Task.Wait(5_000), "the second handler never reported");
        return outcome.Task.Result;
    }

    // Through the connection itself, so the adapter under test reads nothing.
    private static async Task<bool> SentSomething(TcpConnection conn)
    {
        RecvSnapshot snapshot = await conn.ReadAsync();
        bool any = false;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                any = true;
                conn.ReturnBuffer(in item);
            }
        }

        return any;
    }
}
