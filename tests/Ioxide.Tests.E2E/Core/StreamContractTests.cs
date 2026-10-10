using System.Net.Sockets;
using ioxide;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TcpConnectionStream"/> against the <see cref="Stream"/> contract: a read that returns 0
/// is the peer's clean end, and nothing else may look like one.
/// </summary>
internal static class StreamContractTests
{
    public static void Register(Runner runner)
    {
        runner.Test("stream: a recv-queue overflow ends the read with an error, not a clean end", () =>
        {
            // The overflow dropped data, so the close after it is not the peer's: read as a clean end, a
            // truncated body passes for a whole one. The pipe readers report it as an error since #257.
            string outcome = ReadToTheEnd(client =>
            {
                client.GetStream().Write(new byte[64]);
                client.GetStream().Write(new byte[4096]);   // 64-byte buffers: 64 deliveries into an 8-slot queue
            });

            Assert.True(outcome.StartsWith("an error", StringComparison.Ordinal) && outcome.Contains("overflowed"),
                $"the overflow reached the stream's reader as {outcome}");
        });

        runner.Test("stream: control: a peer's close still reads as a clean end", () =>
        {
            // Same server, a peer that sends what fits the queue and closes: every byte, then 0.
            string outcome = ReadToTheEnd(client =>
            {
                client.GetStream().Write(new byte[64]);
                client.GetStream().Write(new byte[384]);    // 6 deliveries: inside the 8-slot queue
                client.Client.Shutdown(SocketShutdown.Send);
            });

            Assert.Equal("a clean end after 448 bytes", outcome);
        });
    }

    /// <summary>
    /// A handler that reads one delivery, stops reading until its connection closes, then reads to the
    /// end and says how that went. <paramref name="drive"/> is the peer.
    /// </summary>
    private static string ReadToTheEnd(Action<TcpClient> drive)
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (reactor, conn) =>
        {
            var stream = new TcpConnectionStream(conn);
            try
            {
                var buffer = new byte[64];
                int n = await stream.ReadAsync(buffer);
                if (n == 0)
                {
                    return;   // the harness's listen probe
                }
                long total = n;

                // Not reading while the rest arrives, so it queues until the peer closes or it overflows.
                var timer = new RingTimer(reactor);
                for (int i = 0; i < 1_000 && !conn.IsClosed; i++)
                {
                    await timer.DelayAsync(10);
                }
                if (!conn.IsClosed)
                {
                    outcome.TrySetResult("the connection never closed");
                    return;
                }

                while ((n = await stream.ReadAsync(buffer)) > 0)
                {
                    total += n;
                }
                outcome.TrySetResult($"a clean end after {total} bytes");
            }
            catch (IOException e)
            {
                outcome.TrySetResult("an error: " + e.Message);
            }
            finally
            {
                stream.Dispose();
                conn.DecRef();
            }
        }, new ServerConfig
        {
            RecvBufferSize = 64,
            RecvSlots = 256,
            Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 8 },
        }).Port;

        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        drive(client);

        Assert.True(outcome.Task.Wait(TimeSpan.FromSeconds(20)), "the handler never finished reading");
        return outcome.Task.Result;
    }
}
