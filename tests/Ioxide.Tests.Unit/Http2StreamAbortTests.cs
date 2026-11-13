using System.Buffers.Binary;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// An abort made from another task than the handler's own flow: a side task pumping an upstream,
/// a timeout. Each step is driven by hand over the strict transport, so the interleavings a reactor
/// makes once in a while are made every run.
/// </summary>
internal static class Http2StreamAbortTests
{
    private const byte RstStream = 0x3;

    public static void Register(Runner runner)
    {
        // A duplex proxy: the main flow reads the upload, and a side task pumps the upstream and aborts once it fails.
        runner.Test("h2 abort: one made from a side task returns, though the handler ends inside it and its writer goes to the next stream", () =>
        {
            using var client = new StrictClient();

            var upstreamFailed = new TaskCompletionSource();
            var aborted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var pump = new TaskCompletionSource();
            var writers = new Dictionary<int, Http2ResponseWriter>();
            bool abortedWhenRented = true;

            Task run = client.Connection.RunAsync(async (request, body, writer) =>
            {
                writers[request.StreamId] = writer;
                writer.WriteHeaders(new Http2Response { Status = 200 });
                switch (request.StreamId)
                {
                    case 1:
                        _ = AbortWhenAsync(upstreamFailed.Task, writer, aborted);
                        try
                        {
                            await body.ReadAsync();   // what came with the headers
                            await body.ReadAsync();   // the rest is held back: parked here when the side task aborts
                        }
                        catch (IOException)
                        {
                            // Cut off by the abort, so the handler ends inside the side task's call.
                        }
                        return;

                    case 3:
                        await pump.Task;
                        Push(writer, 1);
                        await writer.FlushAsync();    // a transport flush the test holds
                        return;

                    default:
                        abortedWhenRented = aborted.Task.IsCompleted;
                        Push(writer, 20_000);         // past CoalesceLimit: a real flush, queued behind the held one
                        await writer.FlushAsync();
                        return;
                }
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.Feed([.. Http2FlowControlTests.Open(), .. Post(1), .. Data(1, 5), .. Http2FlowControlTests.Get(3)]);
            client.ReleaseFlush();                       // the pass flush
            pump.SetResult();                            // stream 3 becomes the pump, and its flush is held
            Assert.Equal(1, client.PendingFlushes);

            upstreamFailed.SetResult();                  // the abort wakes the parked read, which ends the handler
            client.Feed(Http2FlowControlTests.Get(5));   // the next stream, on the writer stream 1 let go
            Assert.True(writers.TryGetValue(5, out Http2ResponseWriter? next) && ReferenceEquals(next, writers[1]),
                "precondition: stream 5 was meant to get stream 1's writer");
            Assert.True(!abortedWhenRented, "precondition: the abort was meant to be still waiting when stream 5 took the writer");

            client.Drain();
            Assert.True(aborted.Task.Wait(2_000), "the side task's AbortAsync never returned: the stream its writer went to took its wait over");
            client.Close(run);
        });

        runner.Test("h2 abort: a flush waiting for its turn to write when another task aborts still returns, and the next reports the peer gone", () =>
        {
            using var client = new StrictClient();

            Http2ResponseWriter? writer1 = null;
            var gate = new TaskCompletionSource();
            var outcomes = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer1 = writer;
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await gate.Task;                         // resumed outside the pass, its flush in flight
                Push(writer, 1);
                string first = await FlushOutcome(writer);   // queued behind it: waits for its turn
                Push(writer, 1);
                outcomes.TrySetResult($"{first}, then {await FlushOutcome(writer)}");
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);                      // the pass flush is in flight
            gate.SetResult();
            Assert.True(!outcomes.Task.IsCompleted, "precondition: the flush was meant to be waiting for its turn");

            Task abort = writer1!.AbortAsync().AsTask(); // a timeout's, say
            List<Frame> frames = client.Drain();

            Assert.True(abort.Wait(2_000), "the abort never returned");
            Assert.True(outcomes.Task.Wait(2_000), "the flush waiting for its turn never returned: the abort took its wait over");
            Assert.Equal("flushed, then peer gone", outcomes.Task.Result);
            Assert.Equal("HEADERS, DATA, RST_STREAM 0x2", Describe(frames, 1));
            client.Close(run);
        });

        runner.Test("h2 abort: a flush waiting for credit when another task aborts wakes, and reports the peer gone", () =>
        {
            using var client = new StrictClient();

            Http2ResponseWriter? writer1 = null;
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer1 = writer;
                writer.WriteHeaders(new Http2Response { Status = 200 });
                Push(writer, 70_000);                    // past the peer's 65535-byte window
                outcome.TrySetResult(await FlushOutcome(writer));
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);
            client.Drain();                              // the headers and a window of the body: the flush waits for credit
            Assert.True(!outcome.Task.IsCompleted, "precondition: the flush was meant to be waiting for credit");

            Task abort = writer1!.AbortAsync().AsTask(); // a timeout's, on a peer that stopped reading
            List<Frame> frames = client.Drain();

            Assert.True(abort.Wait(2_000), "the abort never returned");
            Assert.True(outcome.Task.Wait(2_000), "the flush waiting for credit slept through the abort, which the peer's own reset wakes");
            Assert.Equal("peer gone", outcome.Task.Result);
            Assert.Equal("RST_STREAM 0x2", Describe(frames, 1));
            client.Close(run);
        });

        // A stream copied into the response reads into GetMemory, so the buffer is out across that read.
        runner.Test("h2 abort: a buffer from GetMemory held across an await when another task aborts is still the handler's to fill and advance", () =>
        {
            using var client = new StrictClient();

            Http2ResponseWriter? writer1 = null;
            var read = new TaskCompletionSource();
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer1 = writer;
                writer.WriteHeaders(new Http2Response { Status = 200 });
                Memory<byte> memory = writer.GetMemory(5);
                await read.Task;                         // the read into it, from a file or an upstream
                "late!"u8.CopyTo(memory.Span);
                try
                {
                    writer.Advance(5);
                    outcome.TrySetResult(await FlushOutcome(writer));
                }
                catch (Exception e)
                {
                    outcome.TrySetResult(e.GetType().Name);
                }
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);
            client.Drain();

            Task abort = writer1!.AbortAsync().AsTask();
            client.Drain();
            Assert.True(abort.Wait(2_000), "the abort never returned");

            read.SetResult();
            Assert.True(outcome.Task.Wait(2_000), "the handler never got past its read");
            Assert.Equal("peer gone", outcome.Task.Result);
            client.Close(run);
        });
    }

    private static async Task AbortWhenAsync(Task failed, Http2ResponseWriter writer, TaskCompletionSource aborted)
    {
        await failed;
        await writer.AbortAsync();
        aborted.TrySetResult();
    }

    private static async Task<string> FlushOutcome(Http2ResponseWriter writer)
    {
        try
        {
            return (await writer.FlushAsync()).IsCompleted ? "peer gone" : "flushed";
        }
        catch (Exception e)
        {
            return e.GetType().Name;
        }
    }

    private static void Push(Http2ResponseWriter writer, int length)
    {
        writer.GetSpan(length)[..length].Fill((byte)'x');
        writer.Advance(length);
    }

    private static byte[] Post(int streamId) => Http2FlowControlTests.FrameBytes(0x1, 0x4, streamId, [0x83, 0x86, 0x84]);

    private static byte[] Data(int streamId, int length) => Http2FlowControlTests.FrameBytes(0x0, 0x0, streamId, new byte[length]);

    // The stream's frames in wire order, a run of DATA folded into one: how the window cut the body is not the point.
    private static string Describe(List<Frame> frames, int streamId)
    {
        var described = new List<string>();
        foreach (Frame frame in frames.Where(f => f.StreamId == streamId))
        {
            string name = frame.Type switch
            {
                Frame.Headers => frame.EndStream ? "HEADERS END_STREAM" : "HEADERS",
                Frame.Data => frame.EndStream ? "DATA END_STREAM" : "DATA",
                RstStream => $"RST_STREAM 0x{BinaryPrimitives.ReadUInt32BigEndian(frame.Payload):x}",
                _ => $"frame 0x{frame.Type:x}",
            };
            if (name == "DATA" && described.Count > 0 && described[^1] == "DATA")
            {
                continue;
            }
            described.Add(name);
        }
        return string.Join(", ", described);
    }
}
