using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// The two clocks on a TCP connection: <see cref="TcpOptions.ReadTimeoutMs"/> reaps one that has
/// gone quiet, <see cref="TcpOptions.SendTimeoutMs"/> reaps one whose peer stopped draining.
/// Before these there was no clock anywhere in the TCP connection lifecycle, so both shapes held
/// an fd, a pooled connection and its native write slab for as long as the peer cared to.
/// </summary>
/// <remarks>
/// Timeouts here are hundreds of milliseconds rather than the second-scale defaults, because the
/// sweep's granularity is the reactor's ~250 ms ticker and a test should not pay a real one. Every
/// deadline below is generous against that tick, not tight against it - the assertion is that the
/// connection closes at all, never that it closed at a particular moment.
/// </remarks>
internal static class TcpTimeoutTests
{
    /// <summary>Two ticks plus slack: what "the sweep has certainly run" costs.</summary>
    private const int SweepGraceMs = 4_000;

    public static void Register(Runner runner)
    {
        runner.Test("tcp/read: a read the peer never answers is closed at the read timeout", () =>
        {
            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = StartWith(readMs: 500, sendMs: 0, async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    // Parked here with a peer that has gone quiet. Only the sweep ends this - which
                    // is the point: nothing else was ever going to.
                    conn.ResetRead();
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    closed.TrySetResult(snapshot.IsClosed);
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = SweepGraceMs;

            // One byte, then silence. It marks this connection as the test's - and it means the
            // assertion is that an ACTIVE connection going quiet is reaped, not merely that a
            // connection which never said anything was.
            client.GetStream().Write("hi"u8);

            // The peer's side of it: shutdown() reaches the client as a FIN, so a read returns 0.
            int n = client.GetStream().Read(new byte[16], 0, 16);

            Assert.Equal(0, n);
            Assert.True(closed.Task.Wait(SweepGraceMs), "the handler was never woken by the sweep");
            Assert.True(closed.Task.Result, "the handler woke, but not with a closed snapshot");
        });

        runner.Test("tcp/read: a connection still talking is left alone", () =>
        {
            // The false positive that would make the whole feature unusable. Same timeout as the
            // test above, driven for well over three times its length - if activity did not refresh
            // the stamp, this closes long before the loop finishes.
            int port = StartWith(readMs: 500, sendMs: 0, EchoHandler);

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 2_000;
            NetworkStream stream = client.GetStream();

            var reply = new byte[2];
            for (int i = 0; i < 10; i++)
            {
                stream.Write("ping"u8);
                Assert.Equal(2, stream.Read(reply, 0, 2));
                Thread.Sleep(200);   // 2s of traffic at 200ms intervals, against a 500ms timeout
            }

            // Still usable after the loop: the sweep never touched it.
            stream.Write("ping"u8);
            Assert.Equal(2, stream.Read(reply, 0, 2));
        });

        runner.Test("tcp/read: 0 disables the clock", () =>
        {
            int port = StartWith(readMs: 0, sendMs: 0, EchoHandler);

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 2_000;
            NetworkStream stream = client.GetStream();

            // Quiet for several ticks. With the sweep off nothing may reap this, so the connection
            // must still answer afterwards.
            Thread.Sleep(1_500);

            stream.Write("ping"u8);
            var reply = new byte[2];
            Assert.Equal(2, stream.Read(reply, 0, 2));
        });

        runner.Test("tcp/read: a handler busy for longer than the read timeout still answers", () =>
        {
            // A slow answer with nothing on the wire meanwhile: the server is not waiting on the peer.
            int port = StartWith(readMs: 500, sendMs: 0, async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    await Task.Delay(2_000);   // four read timeouts

                    conn.Write("done"u8);
                    await conn.FlushAsync();

                    conn.ResetRead();
                    await conn.ReadAsync();    // park until the client hangs up
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 6_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            Assert.Equal("done", ReadExactly(stream, 4));
        });

        runner.Test("tcp/read: a server that keeps sending is not waiting on its peer", () =>
        {
            // A push feed: a read parked throughout and a peer that never answers. The server's own
            // sends restart the clock, so four read timeouts of pushing go through.
            int port = StartWith(readMs: 500, sendMs: 0, async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    conn.ResetRead();
                    ValueTask<RecvSnapshot> parked = conn.ReadAsync();

                    for (int i = 0; i < 16; i++)   // 16 x 150 ms
                    {
                        await Task.Delay(150);
                        conn.Write("tick"u8);
                        await conn.FlushAsync();
                    }

                    await parked;   // until the client hangs up
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 4_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            Assert.Equal(string.Concat(Enumerable.Repeat("tick", 16)), ReadExactly(stream, 64));
        });

        runner.Test("tcp/exit: a handler that lets go sends its peer a FIN", () =>
        {
            // Both clocks off, so only the handler letting go can produce the EOF.
            int port = StartWith(readMs: 0, sendMs: 0, async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    conn.Write("bye"u8);
                    await conn.FlushAsync();
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 2_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            Assert.Equal("bye", ReadExactly(stream, 3));
            Assert.Equal(0, stream.Read(new byte[16], 0, 16));
        });

        runner.Test("tcp/exit: a peer that ignores the FIN is shut down at the read timeout", () =>
        {
            int port = StartWith(readMs: 500, sendMs: 0, async (_, conn) =>
            {
                try
                {
                    await IsThisTestsConnection(conn);
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 2_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);
            Assert.Equal(0, stream.Read(new byte[16], 0, 16));   // the FIN

            // Past the deadline, the server's socket is gone: a write draws a reset, which only the next
            // write can see (after a FIN, reads return 0 regardless).
            Thread.Sleep(SweepGraceMs / 2);

            string outcome = "both writes accepted - the server is still holding the connection";
            try
            {
                stream.Write("still here"u8);
                Thread.Sleep(300);
                stream.Write("still here"u8);
            }
            catch (IOException)
            {
                outcome = "reset";
            }
            Assert.Equal("reset", outcome);
        });

        runner.Test("tcp/exit: a handler that lets go mid-flush gets the whole flush out before the FIN", () =>
        {
            // The FIN waits for the flush, so the peer's time to close must too: a read timeout far
            // shorter than the send takes may not cut the send short.
            byte[] body = new byte[6 * 1024 * 1024];

            int port = StartWith(readMs: 500, sendMs: 10_000, async (_, conn) =>
            {
                try
                {
                    if (!await IsThisTestsConnection(conn))
                    {
                        return;
                    }

                    conn.Write(body);
                    ValueTask inFlight = conn.FlushAsync();   // let go with it still in flight
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.ReceiveBufferSize = 4096;   // a slow reader: the flush outlives the read timeout
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 5_000;
            NetworkStream stream = client.GetStream();
            stream.Write("hi"u8);

            var buffer = new byte[16 * 1024];
            long total = 0;
            int n;
            while ((n = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += n;
                Thread.Sleep(5);
            }

            Assert.Equal((long)body.Length, total);
        });

        runner.Test("tcp/send: a flush the peer stopped draining is released, not parked forever", () =>
        {
            // The reported shape (#234's workload, and the reason the idle clock alone is not
            // enough): the peer keeps the connection open and simply stops reading. Its window
            // shuts, the SEND never completes, and FlushAsync parks with no bound at all.
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = StartWith(readMs: 0, sendMs: 700, StalledFlushHandler(report));

            using var client = new TcpClient();

            // Set before the connect so it is what gets advertised: the server then parks within a
            // megabyte or so instead of after however much this box's autotuning decides to buffer.
            client.ReceiveBufferSize = 4096;
            client.Connect("127.0.0.1", port);
            client.GetStream().Write("GET / HTTP/1.1\r\n\r\n"u8);

            // Deliberately never reads. Holding the socket open is the whole reproduction.
            Assert.True(report.Task.Wait(20_000), "the handler never reported - its flush is still parked");
            Assert.Equal("", report.Task.Result);
        });

        runner.Test("tcp/send: 0 leaves a stalled flush parked", () =>
        {
            // The control, and the proof that the test above measures the sweep rather than some
            // other teardown: with the clock off, the same reproduction must NOT come back.
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = StartWith(readMs: 0, sendMs: 0, StalledFlushHandler(report));

            using var client = new TcpClient();
            client.ReceiveBufferSize = 4096;
            client.Connect("127.0.0.1", port);
            client.GetStream().Write("GET / HTTP/1.1\r\n\r\n"u8);

            Assert.True(!report.Task.Wait(3_000),
                "a flush was released with no send timeout configured - something else is reaping it");
        });
    }

    /// <summary>
    /// Reads until this connection delivers actual bytes, and says whether it ever did.
    /// </summary>
    /// <remarks>
    /// The harness proves a server is listening by connecting a TcpClient and dropping it
    /// (TestServer.WaitForListen), so every server here serves one connection that sends nothing
    /// and closes at once. A handler that reported on that one was not measuring the test's
    /// connection at all - and on the send path it was worse than useless: a flush on an
    /// already-closed connection takes FlushAsync's _closed early-out and returns instantly, so the
    /// probe's handler "absorbed" 128 MiB without a single byte reaching a socket, and reported
    /// that no flush ever parked.
    /// </remarks>
    private static async Task<bool> IsThisTestsConnection(TcpConnection conn)
    {
        while (true)
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

            if (received)
            {
                return true;
            }
            if (snapshot.IsClosed)
            {
                return false;   // the probe
            }
            conn.ResetRead();
        }
    }

    /// <summary>Reads exactly <paramref name="count"/> bytes as ASCII, or throws on EOF or timeout.</summary>
    private static string ReadExactly(NetworkStream stream, int count)
    {
        var buffer = new byte[count];
        int got = 0;
        while (got < count)
        {
            int n = stream.Read(buffer, got, count - got);
            if (n == 0)
            {
                throw new IOException($"EOF after {got} of {count} bytes");
            }
            got += n;
        }
        return Encoding.ASCII.GetString(buffer);
    }

    /// <summary>Answers every read with two bytes, so a test can keep a connection demonstrably alive.</summary>
    private static async Task EchoHandler(Reactor reactor, TcpConnection conn)
    {
        try
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

                conn.Write("ok"u8);
                await conn.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    /// <summary>
    /// Writes until one flush stops coming back, then waits on it. Reports "" once that flush is
    /// released, or whatever went wrong instead - and never reports at all while it stays parked,
    /// which is what the control test asserts.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> StalledFlushHandler(TaskCompletionSource<string> report)
        => async (_, conn) =>
        {
            try
            {
                if (!await IsThisTestsConnection(conn))
                {
                    return;
                }

                // Chunked rather than one guessed-at size: how much a loopback pair absorbs before
                // the send stops completing is a property of the box, not a constant.
                byte[] chunk = new byte[256 * 1024];
                Task? parked = null;
                long written = 0;

                for (int attempt = 0; attempt < 128 && parked is null; attempt++)
                {
                    conn.Write(chunk);
                    Task flush = conn.FlushAsync().AsTask();

                    // A deadline, not a timing assertion: a flush that has not come back is the
                    // state under test, and one that has simply costs another chunk.
                    if (await Task.WhenAny(flush, Task.Delay(500)) != flush)
                    {
                        parked = flush;
                    }
                    else
                    {
                        written += chunk.Length;
                    }
                }

                if (parked is null)
                {
                    report.TrySetResult(
                        $"the peer drained {written / (1024 * 1024)} MiB; no flush ever stayed in flight");
                    return;
                }

                await parked;
                report.TrySetResult("");
            }
            catch (Exception e)
            {
                report.TrySetResult($"{e.GetType().Name}: {e.Message}");
            }
            finally
            {
                conn.DecRef();
            }
        };

    private static int StartWith(int readMs, int sendMs, Func<Reactor, TcpConnection, Task> handle)
        => TestServer.StartConfigured(handle, new ServerConfig
        {
            RecvBufferSize = 4096,
            RecvSlots = 256,
            Tcp = new TcpOptions
            {
                WriteSlabSize = 256 * 1024,
                PoolMax = 64,
                RecvQueueEntries = 64,
                ReadTimeoutMs = readMs,
                SendTimeoutMs = sendMs,
            },
        }).Port;
}
