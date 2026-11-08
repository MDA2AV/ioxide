using System.Net;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// A TcpConnection is pooled, so a reference kept past the connection's life is the next client's connection.
/// The pipe reader, the pipe writer and the stream know which life they were made for and refuse the next one;
/// the connection's own methods can't tell an old caller from the new one (#527).
/// </summary>
internal static class StaleConnectionTests
{
    public static void Register(Runner runner)
    {
        const string NoHandle = "#527: the connection's own API has no per-life handle, so a stale call can't be told from the next client's";

        runner.Pending("tcp: a write through a connection kept past its life does not reach the next client", () =>
        {
            TwoLives(prepare: conn => conn, stale: async (conn, _) =>
            {
                conn.Write("SECRET-OF-CLIENT-1"u8);
                await conn.FlushAsync();
            }, next: DrainUntilClosed, play: (second, gate) =>
            {
                gate.SetResult();
                Assert.Equal("", WhatArrives(second));
            });
        }, because: NoHandle);

        runner.Test("tcp: a pipe writer kept past its connection's life does not reach the next client", () =>
        {
            TwoLives(prepare: conn => new TcpConnectionDualPipe(conn), stale: async (_, pipe) =>
            {
                await pipe.Output.WriteAsync("SECRET-VIA-PIPE-WRITER"u8.ToArray());
            }, next: DrainUntilClosed, play: (second, gate) =>
            {
                gate.SetResult();
                Assert.Equal("", WhatArrives(second));
            });
        });

        runner.Test("tcp: a stream kept past its connection's life does not reach the next client", () =>
        {
            TwoLives(prepare: conn => new TcpConnectionStream(conn), stale: async (_, stream) =>
            {
                await stream.WriteAsync("SECRET-VIA-STREAM"u8.ToArray());
            }, next: DrainUntilClosed, play: (second, gate) =>
            {
                gate.SetResult();
                Assert.Equal("", WhatArrives(second));
            });
        });

        runner.Pending("tcp: a read through a connection kept past its life does not take the next client's bytes", () =>
        {
            var stolen = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            TwoLives(prepare: conn => conn, stale: async (conn, _) =>
            {
                string taken = "";
                try
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            taken += Encoding.ASCII.GetString(item.AsSpan());
                            conn.ReturnBuffer(in item);
                        }
                    }
                }
                finally
                {
                    stolen.TrySetResult(taken);
                }
            }, next: async conn =>
            {
                await release.Task;   // busy, so its read is not parked ahead of the stale one
                await DrainUntilClosed(conn);
            }, play: (second, gate) =>
            {
                second.Send("SECRET-FROM-CLIENT-2"u8);
                Thread.Sleep(100);
                gate.SetResult();

                bool finished = stolen.Task.Wait(3_000);
                release.TrySetResult();
                Assert.True(finished, "the stale read neither returned nor threw");
                Assert.Equal("", stolen.Task.Result);
            });
        }, because: NoHandle);

        runner.Test("tcp: control: a pipe reader kept past its connection's life is refused", () =>
        {
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            TwoLives(prepare: conn => new TcpConnectionDualPipe(conn), stale: async (_, pipe) =>
            {
                try
                {
                    await pipe.Input.ReadAsync();
                    outcome.TrySetResult("it read");
                }
                catch (InvalidOperationException e)
                {
                    outcome.TrySetResult(e.Message);
                }
            }, next: DrainUntilClosed, play: (_, gate) =>
            {
                gate.SetResult();
                Assert.True(outcome.Task.Wait(3_000), "the stale read neither returned nor threw");
                Assert.True(outcome.Task.Result.Contains("after the reader was completed"), outcome.Task.Result);
            });
        });

        // A completed pipe writer used to only set a flag nothing read, so a write after Complete still went out.
        runner.Test("tcp: a pipe writer refuses writes once completed", () =>
        {
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(async (_, conn) =>
            {
                try
                {
                    if (await FirstByte(conn) < 0)
                    {
                        return;   // the harness's listen probe
                    }

                    var pipe = new TcpConnectionDualPipe(conn);
                    pipe.Output.Complete();
                    try
                    {
                        pipe.Output.GetSpan(1);
                        outcome.TrySetResult("it handed out the slab");
                    }
                    catch (InvalidOperationException e)
                    {
                        outcome.TrySetResult(e.Message);
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using Socket client = Connect(port, 3_000);
            client.Send("A"u8);
            Assert.True(outcome.Task.Wait(5_000), "the handler never reported");
            Assert.True(outcome.Task.Result.Contains("after the writer was completed"), outcome.Task.Result);
        });
    }

    /// <summary>
    /// A first client whose handler lets go early, as DecRef offers, and waits at a gate with what it kept; then a
    /// second client, which gets the same object from the pool. <paramref name="play"/> opens the gate.
    /// </summary>
    private static void TwoLives<T>(Func<TcpConnection, T> prepare, Func<TcpConnection, T, Task> stale,
        Func<TcpConnection, Task> next, Action<Socket, TaskCompletionSource> play)
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondRunning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        TcpConnection? firstObject = null, secondObject = null;

        int port = TestServer.Start(async (r, conn) =>
        {
            int marker = await FirstByte(conn);
            if (marker == 'A')
            {
                firstObject = conn;
                T kept = prepare(conn);
                conn.DecRef();
                await gate.Task;
                await new ReactorSwitch(r);   // back on the thread such a handler would be on
                await stale(conn, kept);
            }
            else if (marker == 'B')
            {
                secondObject = conn;
                secondRunning.TrySetResult();
                try
                {
                    await next(conn);
                }
                finally
                {
                    conn.DecRef();
                }
            }
            else
            {
                conn.DecRef();   // the harness's listen probe
            }
        });

        using (Socket first = Connect(port, 3_000))
        {
            first.Send("A"u8);
            Assert.Equal(0, first.Receive(new byte[16]));   // the FIN of the early release
        }
        Thread.Sleep(100);   // its connection goes back to the pool

        using Socket second = Connect(port, 1_500);
        second.Send("B"u8);
        Assert.True(secondRunning.Task.Wait(5_000), "the second handler never ran");
        Assert.True(ReferenceEquals(firstObject, secondObject), "the pool did not hand on the same object, so this proves nothing");

        play(second, gate);
    }

    private static async Task<int> FirstByte(TcpConnection conn)
    {
        RecvSnapshot snapshot = await conn.ReadAsync();

        int first = -1;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                if (first < 0)
                {
                    first = item.AsSpan()[0];
                }
                conn.ReturnBuffer(in item);
            }
        }

        return first;
    }

    private static async Task DrainUntilClosed(TcpConnection conn)
    {
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    conn.ReturnBuffer(in item);
                }
            }

            if (snapshot.IsClosed)
            {
                return;
            }
        }
    }

    private static string WhatArrives(Socket client)
    {
        var buffer = new byte[64];
        try
        {
            int n = client.Receive(buffer);
            return Encoding.ASCII.GetString(buffer, 0, n);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
        {
            return "";
        }
    }

    private static Socket Connect(int port, int receiveTimeoutMs)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            ReceiveTimeout = receiveTimeoutMs,
        };
        socket.Connect(IPAddress.Loopback, port);
        return socket;
    }
}
