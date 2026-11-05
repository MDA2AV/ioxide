

using System.IO.Pipelines;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// The HTTP/2 write queue: staging and flushing take turns on the connection's pipe, so a handler
/// that completes while a transport flush is in flight queues its frames and they leave - together
/// with every other completion from that window - on the single flush after it.
///
/// The fake transport here enforces the same contract as the real TcpConnection: any write while a
/// flush is in flight throws, and so does a second flush. That is the constraint the queue exists
/// to solve, so a test that passed against a lenient fake would prove nothing.
/// </summary>
internal static class Http2OutputQueueTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 queue: a pass's responses still leave on one flush", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => Http2Response.Text("hi"));

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1, 3);

            // One pass: SETTINGS ack plus both responses, staged together, flushed once.
            Assert.Equal(1, client.PendingFlushes);
            byte[] pass = client.ReleaseFlush();

            List<Frame> frames = Frame.Walk(pass);
            Assert.True(frames.Any(f => f.Type == 0x4 && (f.Flags & 0x1) != 0), "settings ack in pass flush");
            AssertResponse(frames, streamId: 1);
            AssertResponse(frames, streamId: 3);

            client.Close(run);
        });

        runner.Test("h2 queue: completions during a flush share the next one", () =>
        {
            using var client = new StrictClient();

            var parked = new Dictionary<int, TaskCompletionSource<Http2Response>>();
            Task run = client.Connection.RunAsync(request =>
            {
                var tcs = new TaskCompletionSource<Http2Response>();
                parked[request.StreamId] = tcs;
                return new ValueTask<Http2Response>(tcs.Task);
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1, 3);

            // The pass flushed only the SETTINGS ack; both handlers are parked. Complete them
            // while that flush is still in flight - exactly where the old code threw
            // "Cannot write while flush is in progress" and killed the connection.
            Assert.Equal(1, client.PendingFlushes);
            parked[1].SetResult(Http2Response.Text("first"));
            parked[3].SetResult(Http2Response.Text("second"));

            Assert.Equal(1, client.PendingFlushes);      // both queued; nothing new in flight
            client.ReleaseFlush();                       // the ack

            // ONE flush now carries both responses - the write the queue exists to coalesce.
            Assert.Equal(1, client.PendingFlushes);
            List<Frame> frames = Frame.Walk(client.ReleaseFlush());
            AssertResponse(frames, streamId: 1);
            AssertResponse(frames, streamId: 3);

            client.Close(run);
        });

        runner.Test("h2 queue: a streamed body resumed outside the pass keeps frame order", () =>
        {
            using var client = new StrictClient();

            var gate = new TaskCompletionSource();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                Push(writer, "live");
                await writer.FlushAsync();               // inside the pass: rides the pass flush
                await gate.Task;                         // park past the pass, like a slow upstream
                Push(writer, "wire");
                await writer.FlushAsync();               // outside: a real transport write
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);

            List<Frame> pass = Frame.Walk(client.ReleaseFlush());
            Assert.True(pass.Any(f => f.Type == 0x1 && f.StreamId == 1), "HEADERS rode the pass flush");
            Assert.True(pass.Any(f => f is { Type: 0x0, StreamId: 1, Length: 4, EndStream: false }),
                "first chunk rode the pass flush, stream open");

            gate.SetResult();                            // resume: chunk, then END_STREAM on complete
            List<Frame> chunk = Frame.Walk(client.ReleaseFlush());
            Assert.True(chunk.Any(f => f is { Type: 0x0, StreamId: 1, Length: 4, EndStream: false }),
                "second chunk flushed on resume");

            List<Frame> fin = Frame.Walk(client.ReleaseFlush());
            Assert.True(fin.Any(f => f is { Type: 0x0, StreamId: 1, Length: 0, EndStream: true }),
                "completion sent END_STREAM");

            client.Close(run);
        });

        runner.Test("h2 queue: a faulted flush wakes parked writers instead of stranding them", () =>
        {
            using var client = new StrictClient();

            var parked = new Dictionary<int, TaskCompletionSource<Http2Response>>();
            Task run = client.Connection.RunAsync(request =>
            {
                var tcs = new TaskCompletionSource<Http2Response>();
                parked[request.StreamId] = tcs;
                return new ValueTask<Http2Response>(tcs.Task);
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);

            // The completion queues behind the in-flight ack flush and parks on its turn. Then the
            // transport dies. The waiter must wake and the connection must finish, not hang.
            parked[1].SetResult(Http2Response.Text("never sent"));
            client.FaultFlush();

            Assert.True(run.Wait(5_000), "connection wound down after the transport fault");
        });

        runner.Test("h2 queue: a faulted flush wakes the writer whose bytes it carried", () =>
        {
            using var client = new StrictClient();

            var gate = new TaskCompletionSource();
            var woke = new TaskCompletionSource<string>();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await gate.Task;                         // resumed outside the pass, its flush in flight
                Push(writer, "lost");
                woke.SetResult(await FlushOutcome(writer));   // queued behind it: its turn is the flush after
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);                      // the pass flush is in flight
            gate.SetResult();                            // the chunk queues, and the writer waits for its turn
            client.ReleaseFlush();                       // the pump sends the chunk: the writer's turn
            client.FaultFlush();                         // and that flush faults

            Assert.True(woke.Task.Wait(5_000), "the writer whose chunk the faulted flush carried never woke");
            Assert.Equal("peer gone", woke.Task.Result);
            Assert.True(run.Wait(5_000), "connection wound down after the transport fault");
        });

        // The fault reaches the writer that pumps, not the read loop, so no teardown releases stream 1's wait for credit.
        runner.Test("h2 queue: a flush waiting for credit hears the peer gone when the turn it waits on faults", () =>
        {
            using var client = new StrictClient();

            var gates = new Dictionary<int, TaskCompletionSource> { [1] = new(), [3] = new() };
            var outcome = new TaskCompletionSource<string>();
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                int id = request.StreamId;
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await gates[id].Task;
                Push(writer, id == 1 ? "xy" : "x");
                string result = await FlushOutcome(writer);
                if (id == 1)
                {
                    outcome.TrySetResult(result);
                }
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.Feed([.. Http2FlowControlTests.Open((Http2FlowControlTests.InitialWindowSize, 0)),
                .. Http2FlowControlTests.Get(1), .. Http2FlowControlTests.Get(3),
                .. Http2FlowControlTests.WindowUpdate(3, 1_000), .. Http2FlowControlTests.WindowUpdate(1, 1)]);
            client.Drain();                              // the pass is out; the read loop waits for input
            gates[3].SetResult();                        // stream 3 flushes first, so it is the pump
            gates[1].SetResult();                        // stream 1 queues its one byte of credit, then waits for more
            client.ReleaseFlush();                       // stream 3's flush; the pump's next turn carries stream 1's byte
            client.FaultFlush();                         // and that flush faults

            Assert.True(outcome.Task.IsCompleted, "stream 1's flush still waited for credit after its turn faulted");
            Assert.Equal("peer gone", outcome.Task.Result);
            client.Close(run);
        });

        runner.Test("h2 queue: a streamed flush that waits for the pump's turn allocates nothing", () =>
        {
            using var client = new StrictClient();

            TaskCompletionSource[] gates = [new(), new(), new(), new()];
            long[] allocated = new long[gates.Length];
            bool[] waited = new bool[gates.Length];
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                for (int i = 0; i < gates.Length; i++)
                {
                    await gates[i].Task;                 // resumed outside the pass, its flush in flight
                    Push(writer, "x");

                    long before = GC.GetAllocatedBytesForCurrentThread();
                    ValueTask<FlushResult> flush = writer.FlushAsync();   // queued behind it: waits for its turn
                    allocated[i] = GC.GetAllocatedBytesForCurrentThread() - before;
                    waited[i] = !flush.IsCompleted;

                    await flush;
                }
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);                      // the pass flush is in flight
            for (int i = 0; i < gates.Length; i++)
            {
                if (i > 0)
                {
                    client.Feed(Ping());                 // a pass whose flush, the PING ack, is in flight
                }
                gates[i].SetResult();
                client.ReleaseFlush();                   // the flush in flight; the pump then sends the chunk
                client.ReleaseFlush();                   // the chunk's flush: the writer's turn
            }
            client.Drain();                              // END_STREAM
            client.Close(run);

            // The first wait grows the connection's queue; every wait after it reuses everything.
            for (int i = 1; i < allocated.Length; i++)
            {
                Assert.True(waited[i], $"flush {i} did not wait for its turn, so it measured nothing");
                Assert.True(allocated[i] == 0, $"flush {i} allocated {allocated[i]} B while it waited for its turn");
            }
        });

        // The stream window stays shut while the connection opens a byte at a time: every wait for credit is one flush's.
        runner.Test("h2 queue: a flush that waits for credit again and again keeps one frame, and resumes inline", () =>
        {
            using var client = new StrictClient();

            int thread = Environment.CurrentManagedThreadId;
            var resumed = new TaskCompletionSource<int>();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                Push(writer, "x");
                await writer.FlushAsync();
                resumed.SetResult(Environment.CurrentManagedThreadId);
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.Feed([.. Http2FlowControlTests.Open((Http2FlowControlTests.InitialWindowSize, 0)), .. Http2FlowControlTests.Get(1)]);
            client.Drain();

            byte[] connectionByte = Http2FlowControlTests.WindowUpdate(0, 1);
            for (int i = 0; i < 1_000; i++)
            {
                client.Feed(connectionByte);
                client.Drain();
            }

            long before = GC.GetTotalMemory(forceFullCollection: true);
            for (int i = 0; i < 20_000; i++)
            {
                client.Feed(connectionByte);
                client.Drain();
            }
            long retained = GC.GetTotalMemory(forceFullCollection: true) - before;

            client.Feed(Http2FlowControlTests.WindowUpdate(1, 1));   // the stream's credit: the chunk goes, the flush ends
            client.Drain();

            Assert.True(resumed.Task.Wait(5_000), "the flush never completed");
            Assert.True(retained < 256 * 1024, $"20,000 waits for credit inside one flush retained {retained} B");
            Assert.Equal(thread, resumed.Task.Result);
            client.Close(run);
        });
    }

    private static byte[] Ping() => [0, 0, 8, 0x6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

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

    private static void Push(Http2ResponseWriter writer, string text)
    {
        Span<byte> span = writer.GetSpan(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            span[i] = (byte)text[i];
        }
        writer.Advance(text.Length);
    }

    private static void AssertResponse(List<Frame> frames, int streamId)
    {
        Assert.True(frames.Any(f => f.Type == 0x1 && f.StreamId == streamId),
            $"HEADERS for stream {streamId}");
        Assert.True(frames.Any(f => f is { Type: 0x0, EndStream: true } && f.StreamId == streamId),
            $"DATA with END_STREAM for stream {streamId}");
    }

}
