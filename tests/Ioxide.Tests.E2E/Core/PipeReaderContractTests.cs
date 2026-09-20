using System.IO.Pipelines;
using System.Buffers;
using System.Net.Sockets;
using System.Text;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TcpConnectionPipeReader"/> against the PipeReader contract, and against the ring it
/// is built on: does <c>AdvanceTo(consumed, examined)</c> mean what Pipelines says it means, and do
/// recv buffers go back as consumption moves through them (#226).
/// </summary>
/// <remarks>
/// Both halves matter for a reader that hands out ring memory rather than copies. Getting
/// <c>examined</c> wrong is a spin - ReadAsync hands back the same bytes forever; getting
/// <c>consumed</c> wrong is either a leak (the buffer never returns to the group) or memory handed
/// back while the caller still holds a slice of it.
///
/// Every handler here ignores its first connection when that connection sends nothing and closes:
/// TestServer proves a port is listening by connecting and dropping, so each server serves one
/// probe that is not the test's.
/// </remarks>
internal static class PipeReaderContractTests
{
    public static void Register(Runner runner)
    {
        runner.Test("pipereader: examined-to-the-end parks the next read instead of respinning it", () =>
        {
            // The contract: having examined everything held, ReadAsync must not come back until
            // there is something NEW. A reader that ignores examined returns the same bytes
            // immediately and an ordinary "read until I have a full frame" loop becomes a spin.
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                try
                {
                    ReadResult first = await reader.ReadAsync();
                    if (first.Buffer.IsEmpty && first.IsCompleted)
                    {
                        return;   // the harness probe
                    }

                    string firstSeen = Text(first.Buffer);

                    // Consumed nothing, examined everything.
                    reader.AdvanceTo(first.Buffer.Start, first.Buffer.End);

                    // Must not complete until the client sends its second chunk.
                    // Shorter than the pause the client takes before its second chunk, so a read
                    // that has not come back by here is parked rather than merely slow.
                    Task<ReadResult> second = reader.ReadAsync().AsTask();
                    bool parked = await Task.WhenAny(second, Task.Delay(300)) != second;

                    ReadResult r = await second;
                    string secondSeen = Text(r.Buffer);
                    reader.AdvanceTo(r.Buffer.End);

                    report.TrySetResult(parked
                        ? $"ok:{firstSeen}:{secondSeen}"
                        : $"the second read returned without new bytes: '{secondSeen}'");
                }
                catch (Exception e)
                {
                    report.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            NetworkStream stream = client.GetStream();

            stream.Write("AB"u8);
            Thread.Sleep(900);      // comfortably past the handler's 300ms deadline
            stream.Write("C"u8);

            Assert.True(report.Task.Wait(10_000), "the handler never reported");

            // Unconsumed bytes must come back with the new ones appended, not be dropped.
            Assert.Equal("ok:AB:ABC", report.Task.Result);
        });

        runner.Test("pipereader: consuming part of one recv leaves the rest readable", () =>
        {
            // Header and body arriving in a single recv, with the handler consuming only the header.
            // The held sequence then starts mid-segment, which is where AdvanceTo's offsets have to
            // be rebased onto the sequence start - GetOffset counts from the segment's RunningIndex,
            // not from the sequence's logical start, so without the rebase the byte counters go
            // negative and the next read parks forever on bytes that already arrived.
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                try
                {
                    ReadResult first = await reader.ReadAsync();
                    if (first.Buffer.IsEmpty && first.IsCompleted)
                    {
                        return;
                    }

                    // Wait until the whole "HEAD|BODY" is in one buffer.
                    while (first.Buffer.Length < 9)
                    {
                        reader.AdvanceTo(first.Buffer.Start, first.Buffer.End);
                        first = await reader.ReadAsync();
                    }

                    string whole = Text(first.Buffer);

                    // Consume the header only; the body stays held, mid-segment.
                    reader.AdvanceTo(first.Buffer.GetPosition(5), first.Buffer.GetPosition(5));

                    // The body is unexamined, so this must complete from what is already held.
                    Task<ReadResult> again = reader.ReadAsync().AsTask();
                    bool immediate = await Task.WhenAny(again, Task.Delay(2_000)) == again;

                    if (!immediate)
                    {
                        report.TrySetResult($"parked on bytes already held (saw '{whole}')");
                        return;
                    }

                    ReadResult rest = await again;
                    string body = Text(rest.Buffer);
                    reader.AdvanceTo(rest.Buffer.End);

                    report.TrySetResult($"{whole}|{body}");
                }
                catch (Exception e)
                {
                    report.TrySetResult($"{e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            });

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.GetStream().Write("HEAD|BODY"u8);

            Assert.True(report.Task.Wait(10_000), "the handler never reported");
            Assert.Equal("HEAD|BODY|BODY", report.Task.Result);
        });

        runner.Test("pipereader: recv buffers go back to the ring as consumption passes them", () =>
        {
            // The direct form of "do we release the ring buffers as we advance". The buffer group is
            // deliberately tiny: if a consumed buffer did not return, this exhausts the group within
            // a handful of messages and the connection stalls or is torn down. Surviving far more
            // round trips than the group has slots is the assertion.
            const int slots = 8;
            const int rounds = 2_000;

            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                int served = 0;
                bool isProbe = true;
                try
                {
                    while (true)
                    {
                        ReadResult result = await reader.ReadAsync();

                        if (result.Buffer.IsEmpty && result.IsCompleted)
                        {
                            break;
                        }
                        isProbe = false;

                        // Consume everything: every slice becomes fully consumed, so every buffer
                        // behind it must be handed back.
                        long n = result.Buffer.Length;
                        reader.AdvanceTo(result.Buffer.End);

                        for (long i = 0; i < n; i++)
                        {
                            conn.Write("."u8);
                        }
                        await conn.FlushAsync();

                        served += (int)n;
                        if (result.IsCompleted)
                        {
                            break;
                        }
                    }

                    if (!isProbe)
                    {
                        report.TrySetResult($"served {served}");
                    }
                }
                catch (Exception e)
                {
                    report.TrySetResult($"{e.GetType().Name}: {e.Message} (after {served})");
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            }, new ServerConfig
            {
                RecvBufferSize = 512,
                RecvSlots = slots,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            }).Port;

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 15_000;
            NetworkStream stream = client.GetStream();

            var one = new byte[1];
            for (int i = 0; i < rounds; i++)
            {
                stream.Write("x"u8);
                Assert.Equal(1, stream.Read(one, 0, 1));
            }

            client.Close();
            Assert.True(report.Task.Wait(10_000), "the handler never reported");

            // Many times the slot count, so the group must have been recycled repeatedly.
            Assert.Equal($"served {rounds}", report.Task.Result);
        });
    }

    private static string Text(in ReadOnlySequence<byte> buffer) => Encoding.ASCII.GetString(buffer.ToArray());
}
