using System.IO.Pipelines;
using System.Runtime.InteropServices;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>A response given after the peer reset its stream leaves nothing behind in the shim.</summary>
internal static class Nghttp2ResetResponseTests
{
    public static void Register(Runner runner)
    {
        runner.Test("nghttp2: a buffered response to a stream its peer reset while the handler ran is not kept", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            TaskCompletionSource<Nghttp2Response>? parked = null;
            Task run = connection.RunAsync(_ =>
            {
                parked = new TaskCompletionSource<Nghttp2Response>();
                return new ValueTask<Nghttp2Response>(parked.Task);
            });
            var response = new Nghttp2Response { Body = new byte[64 * 1024] };

            client.SendRequests();                       // preface and SETTINGS
            client.Drain();

            const int warm = 20, total = 220;
            long before = 0;
            for (int i = 0; i < total; i++)
            {
                int id = 1 + (2 * i);
                client.Feed(Get(id));
                client.Drain();
                client.Feed(Http2FlowControlTests.RstStream(id, 8));   // CANCEL, while the handler is parked
                client.Drain();
                parked!.SetResult(response);
                client.Drain();
                if (i == warm - 1)
                {
                    before = NativeHeapInUse();
                }
            }
            long grown = NativeHeapInUse() - before;

            client.Close(run);
            connection.Dispose();
            Assert.True(grown < 2 * 1024 * 1024,
                $"{total - warm} responses of 64 KiB to reset streams left {grown / 1024} KiB on the native heap");
        });

        runner.Test("nghttp2: a streamed response to a stream reset in the same read as its end hears the peer gone", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var go = new TaskCompletionSource();
            var outcome = new TaskCompletionSource<string>();
            Task run = connection.RunAsync(async (_, writer) =>
            {
                await go.Task;
                for (int k = 0; k < 8; k++)              // past the 64 KiB a flush may run ahead of nghttp2
                {
                    writer.GetSpan(16 * 1024)[..(16 * 1024)].Fill((byte)'x');
                    writer.Advance(16 * 1024);
                }
                FlushResult flushed = await writer.FlushAsync();
                outcome.SetResult(flushed.IsCompleted ? "peer gone" : "flushed");
            });

            client.SendRequests();
            client.Drain();
            client.Feed([.. Get(1), .. Http2FlowControlTests.RstStream(1, 8)]);   // its writer is made after the reset
            client.Drain();
            go.SetResult();
            client.Drain();

            Assert.True(outcome.Task.IsCompleted, "the flush of a stream nghttp2 had already closed never returned");
            Assert.Equal("peer gone", outcome.Task.Result);
            client.Close(run);
            connection.Dispose();
        });
    }

    // A GET with END_STREAM: :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static byte[] Get(int streamId)
    {
        byte[] block = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
        return Http2FlowControlTests.FrameBytes(0x1, 0x5, streamId, block);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MallInfo2
    {
        public nuint Arena, Ordblks, Smblks, Hblks, Hblkhd, Usmblks, Fsmblks, Uordblks, Fordblks, Keepcost;
    }

    [DllImport("libc", EntryPoint = "mallinfo2")]
    private static extern MallInfo2 GetMallInfo2();

    // What malloc has handed out and not had back, which is where the shim keeps a response's body.
    private static long NativeHeapInUse()
    {
        MallInfo2 info = GetMallInfo2();
        return (long)info.Uordblks + (long)info.Hblkhd;
    }
}
