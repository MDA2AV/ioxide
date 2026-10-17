using System.Net.Sockets;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// <see cref="TcpConnectionStream"/> against the <see cref="Stream"/> contract: a read that returns 0
/// is the peer's clean end, and nothing else may look like one.
/// </summary>
/// <remarks>
/// ioxide's first test here floods an 8-entry recv queue until it overflows and drops data, and
/// asserts the close after that reads as an error. epoxide's reader pulls, so the same flood is
/// never dropped: it translates to a reader that falls behind getting every byte and then the clean
/// end, against a control that sends only what fits the queue.
/// </remarks>
internal static class StreamContractTests
{
    public static void Register(Runner runner)
    {
        runner.Test("stream: a reader that falls behind gets every byte, then the peer's clean end", () =>
        {
            // 64 deliveries' worth against an 8-slot queue, behind a reader that is not reading.
            string outcome = ReadToTheEnd(client =>
            {
                client.GetStream().Write(new byte[64]);
                client.GetStream().Write(new byte[4096]);
                client.Client.Shutdown(SocketShutdown.Send);
            });

            Assert.Equal("a clean end after 4160 bytes", outcome);
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
    /// A handler that reads one delivery, stops reading while the peer sends the rest and closes, then
    /// reads to the end and says how that went. <paramref name="drive"/> is the peer.
    /// </summary>
    /// <remarks>
    /// ioxide's handler waited for <see cref="TcpConnection.IsClosed"/> before reading on. epoxide
    /// sees the peer's FIN only when it reads, so a reader that has stopped never sees IsClosed: the
    /// pause is a fixed one instead, long enough for everything the peer sent to be waiting.
    /// </remarks>
    private static string ReadToTheEnd(Action<TcpClient> drive)
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (reactor, conn) =>
        {
            var stream = new TcpConnectionStream(conn);
            long total = 0;
            try
            {
                var buffer = new byte[64];
                int n = await stream.ReadAsync(buffer);
                if (n == 0)
                {
                    return;   // the harness's listen probe
                }
                total = n;

                // Not reading while the rest arrives, so it waits in the socket behind this reader.
                await new ReactorTimer(reactor).DelayAsync(500);

                while ((n = await stream.ReadAsync(buffer)) > 0)
                {
                    total += n;
                }
                outcome.TrySetResult($"a clean end after {total} bytes");
            }
            catch (IOException e)
            {
                outcome.TrySetResult($"an error after {total} bytes: {e.Message}");
            }
            finally
            {
                stream.Dispose();
                conn.DecRef();
            }
        }, new ServerConfig
        {
            RecvBufferSize = 64,
            Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 8 },
        }).Port;

        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        drive(client);

        Assert.True(outcome.Task.Wait(TimeSpan.FromSeconds(20)), "the handler never finished reading");
        return outcome.Task.Result;
    }
}
