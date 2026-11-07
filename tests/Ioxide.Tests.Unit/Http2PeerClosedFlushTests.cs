using System.IO.Pipelines;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// A flush that reports the peer closed. Over TCP a dead peer never makes a flush throw: the pipe writer's
/// FlushAsync returns IsCompleted and drops what was staged, so that result is the only word a connection
/// gets before its read sees the close, and its streamed writers have to hear it.
/// </summary>
internal static class Http2PeerClosedFlushTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 streamed: a flush that reports the peer closed tells its writer, and every flush after it", () =>
        {
            using var client = new StrictClient();

            var gate = new TaskCompletionSource();
            var completed = new List<bool>();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await gate.Task;                         // past the pass, so each flush is a real write
                for (int i = 0; i < 3; i++)
                {
                    Stage(writer.GetSpan(4), 4);
                    writer.Advance(4);
                    completed.Add((await writer.FlushAsync()).IsCompleted);
                }
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);
            client.ReleaseFlush();                       // the pass
            gate.SetResult();
            client.ReleaseFlush();                       // delivered
            client.ReportPeerClosed();

            Assert.Equal("False True True", string.Join(' ', completed));
            client.Close(run);
        });

        runner.Test("h2 streamed: a writer waiting for the pump's turn hears the peer closed too", () =>
        {
            using var client = new StrictClient();

            var gates = new Dictionary<int, TaskCompletionSource> { [1] = new(), [3] = new() };
            var completed = new Dictionary<int, bool>();
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await gates[request.StreamId].Task;
                Stage(writer.GetSpan(4), 4);
                writer.Advance(4);
                completed[request.StreamId] = (await writer.FlushAsync()).IsCompleted;
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1, 3);
            client.ReleaseFlush();                       // the pass

            gates[1].SetResult();                        // the pump: its flush is in flight
            gates[3].SetResult();                        // queued behind it, waiting for the next turn
            Assert.Equal(1, client.PendingFlushes);

            client.ReportPeerClosed();

            Assert.True(completed.TryGetValue(1, out bool pump) && pump, "the pump's writer did not hear the peer closed");
            Assert.True(completed.TryGetValue(3, out bool queued) && queued, "the writer waiting for its turn did not hear the peer closed");
            Assert.Equal(0, client.PendingFlushes);
            client.Close(run);
        });

        runner.Test("h2 streamed: a writer out of credit hears the peer closed, on its own flush or another's", () =>
        {
            using var client = new StrictClient();

            var gates = new Dictionary<int, TaskCompletionSource> { [1] = new(), [3] = new(), [5] = new() };
            var completed = new Dictionary<int, bool>();
            Task run = client.Connection.RunAsync(async (request, writer) =>
            {
                await gates[request.StreamId].Task;
                writer.WriteHeaders(new Http2Response { Status = 200 });
                if (request.StreamId != 5)
                {
                    const int pastTheWindow = 70_000;    // the peer's window is 65,535, and shared
                    Stage(writer.GetSpan(pastTheWindow), pastTheWindow);
                    writer.Advance(pastTheWindow);
                }
                completed[request.StreamId] = (await writer.FlushAsync()).IsCompleted;
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1, 3, 5);
            client.ReleaseFlush();                       // the pass

            gates[1].SetResult();                        // takes the whole connection window
            client.ReleaseFlush();                       // delivered, and now it waits for credit
            Assert.True(!completed.ContainsKey(1), "the first writer was expected to wait for credit");

            gates[3].SetResult();                        // no credit either, and nothing staged but its headers
            gates[5].SetResult();
            Assert.Equal(1, client.PendingFlushes);
            client.ReportPeerClosed();

            foreach (int stream in new[] { 1, 3, 5 })
            {
                Assert.True(completed.TryGetValue(stream, out bool heard) && heard, $"stream {stream}'s writer did not hear the peer closed");
            }
            client.Close(run);
        });

        runner.Test("h2: a pass's flush that reports the peer closed ends the connection, without waiting for its read", () =>
        {
            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(_ => Http2Response.Text("hi"));

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);
            client.ReportPeerClosed();

            Assert.True(client.Connection.IsBroken, "the connection does not know its peer is gone");
            Assert.True(run.IsCompleted, "the connection is still waiting on a read");
            client.Close(run);
        });

        runner.Test("nghttp2 streamed: a flush that reports the peer closed tells its writer, and every flush after it", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var gate = new TaskCompletionSource();
            var completed = new List<bool>();
            Task run = connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                await gate.Task;
                for (int i = 0; i < 3; i++)
                {
                    Stage(writer.GetSpan(4), 4);
                    writer.Advance(4);
                    completed.Add((await writer.FlushAsync()).IsCompleted);
                }
            });

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed(Get(1));
            client.Drain();
            gate.SetResult();
            client.ReleaseFlush();                       // delivered
            client.ReportPeerClosed();

            Assert.Equal("False True True", string.Join(' ', completed));
            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2 streamed: a writer waiting for nghttp2 to catch up hears the peer closed on another's flush", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var gates = new Dictionary<int, TaskCompletionSource> { [1] = new(), [3] = new() };
            var completed = new Dictionary<int, bool>();
            Task run = connection.RunAsync(async (request, writer) =>
            {
                await gates[request.StreamId].Task;
                writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                if (request.StreamId == 1)
                {
                    const int pastWhatItHolds = 256 * 1024;   // the window takes 65,535, then a flush may run 64 KiB ahead
                    Stage(writer.GetSpan(pastWhatItHolds), pastWhatItHolds);
                    writer.Advance(pastWhatItHolds);
                }
                completed[request.StreamId] = (await writer.FlushAsync()).IsCompleted;
            });

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed([.. Get(1), .. Get(3)]);
            client.Drain();

            gates[1].SetResult();
            client.Drain();                              // all the window allows: it now waits for nghttp2 to catch up
            Assert.True(!completed.ContainsKey(1), "the first writer was expected to wait for nghttp2");

            gates[3].SetResult();
            Assert.Equal(1, client.PendingFlushes);
            client.ReportPeerClosed();

            foreach (int stream in new[] { 1, 3 })
            {
                Assert.True(completed.TryGetValue(stream, out bool heard) && heard, $"stream {stream}'s writer did not hear the peer closed");
            }
            client.Close(run);
            connection.Dispose();
        });

        runner.Test("nghttp2: a pass's flush that reports the peer closed ends the connection, without waiting for its read", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);
            Task run = connection.RunAsync(_ => new ValueTask<Nghttp2Response>(new Nghttp2Response { Body = "hi"u8.ToArray() }));

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();
            client.Feed(Get(1));
            client.ReportPeerClosed();

            Assert.True(connection.IsBroken, "the connection does not know its peer is gone");
            Assert.True(run.IsCompleted, "the connection is still waiting on a read");
            client.Close(run);
            connection.Dispose();
        });
    }

    private static void Stage(Span<byte> span, int bytes) => span[..bytes].Fill((byte)'x');

    // A GET with END_STREAM: :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Get(int streamId)
    {
        byte[] block = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
        return Http2FlowControlTests.FrameBytes(0x1, 0x5, streamId, block);
    }
}
