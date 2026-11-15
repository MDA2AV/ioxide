using System.Buffers;
using ioxide;
using ioxide.http3;

namespace Ioxide.Tests;

/// <summary>
/// ioxide.http3 asks a client to stop uploading the rest of a body its handler answered without reading (RFC 9114 4.1):
/// STOP_SENDING with H3_NO_ERROR once the response is handed over, and nothing for a request that ended, was reset or lost
/// its connection. Checked on a transport that logs what the stack asks of it, in order.
/// </summary>
internal static class Http3EarlyAnswerTests
{
    // Past the inline limit, so a buffered answer is two sends: its head, then its body with the fin.
    private static readonly byte[] Answer = new byte[8 * 1024];

    // A DATA frame promising 1000 bytes, 100 of them here: the rest is still to come when the handler answers.
    private static readonly byte[] StillArriving = [.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(1000), .. new byte[100]];
    private static readonly byte[] Whole = [.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(100), .. new byte[100]];

    private const ulong H3RequestCancelled = 0x10c;

    public static void Register(Runner runner)
    {
        runner.Test("h3 early answer (ioxide.http3, recorded): a buffered answer to an upload still arriving is followed by STOP_SENDING(H3_NO_ERROR)", () =>
            Assert.Equal("send, send+fin, stop 0x100", End(Start(StillArriving, ended: false, Buffered))));

        runner.Test("h3 early answer (ioxide.http3, recorded): the 500 of a buffered handler that threw is followed by STOP_SENDING(H3_NO_ERROR)", () =>
            Assert.Equal("send+fin, stop 0x100", End(Start(StillArriving, ended: false, c => c.RunAsync(ThrowsAtOnce)))));

        runner.Test("h3 early answer (ioxide.http3, recorded): a buffered answer its handler awaited is followed by STOP_SENDING(H3_NO_ERROR)", () =>
        {
            var answered = new TaskCompletionSource();
            Served served = Start(StillArriving, ended: false, c => c.RunAsync(async (_, _) =>
            {
                await answered.Task;
                return new Http3Response { Status = 413, Body = Answer };
            }));
            answered.SetResult();
            Assert.Equal("send, send+fin, stop 0x100", End(served));
        });

        runner.Test("h3 early answer (ioxide.http3, recorded): a streamed answer to an upload still arriving is followed by STOP_SENDING(H3_NO_ERROR)", () =>
            Assert.Equal("send, send+fin, stop 0x100", End(Start(StillArriving, ended: false, Streamed))));

        runner.Test("h3 early answer (ioxide.http3, recorded): the 500 of a streamed handler that failed before its headers is followed by STOP_SENDING(H3_NO_ERROR)", () =>
            Assert.Equal("send, send+fin, stop 0x100", End(Start(StillArriving, ended: false,
                c => c.RunAsync((_, _, _) => throw new InvalidOperationException("the handler failed before its headers"))))));

        runner.Test("h3 early answer (ioxide.http3, recorded): a client that refused the answer is still asked to stop uploading once its handler returns", () =>
        {
            var refused = new TaskCompletionSource();
            Served served = Start(StillArriving, ended: false, c => c.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http3Response { Status = 413 });
                writer.Write(Answer);
                await writer.FlushAsync();
                await refused.Task;
            }));
            served.Quic.OnSendRefused!(0);   // how the engine reports the client's STOP_SENDING
            refused.SetResult();
            Assert.Equal("send, send, stop 0x100", End(served));
        });

        foreach (bool streamed in new[] { false, true })
        {
            Func<Http3Connection, Task> serve = streamed ? Streamed : Buffered;
            runner.Test($"control: h3 (ioxide.http3, recorded) a {(streamed ? "streamed" : "buffered")} answer to an upload that ended is not followed by STOP_SENDING", () =>
                Assert.Equal("send, send+fin", End(Start(Whole, ended: true, serve))));
        }

        runner.Test("h3 early answer (ioxide.http3, recorded): an upload the client reset gets no STOP_SENDING once its handler answers", () =>
        {
            var answered = new TaskCompletionSource();
            Served served = Start(StillArriving, ended: false, c => c.RunAsync(async (_, _) =>
            {
                await answered.Task;
                return new Http3Response { Status = 413, Body = Answer };
            }));
            Assert.True(served.Quic.EnqueueStreamEvent(0, QuicStreamEvent.Reset, H3RequestCancelled), "the recv ring refused the reset");
            served.Quic.SignalDataArrived();
            answered.SetResult();
            Assert.Equal("send, send+fin", End(served));
        });

        runner.Test("h3 early answer (ioxide.http3, recorded): a streamed handler that fails after its headers is reset once, and gets no STOP_SENDING", () =>
            Assert.Equal("send, send, reset 0x102", End(Start(StillArriving, ended: false, c => c.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http3Response { Status = 200 });
                writer.Write(Answer);
                await writer.FlushAsync();
                throw new InvalidOperationException("the handler failed after its headers");
            })))));

        runner.Test("h3 early answer (ioxide.http3, recorded): a request that arrives with its connection's close gets no STOP_SENDING", () =>
        {
            var quic = new OrderQuic();
            Assert.True(quic.EnqueueStreamData(0, StillArriving, fin: false), "the recv ring refused the request");
            quic.MarkClosed();
            Task run = Buffered(new Http3Connection(quic));
            Assert.True(run.Wait(5000), "the run loop never ended");
            Assert.Equal("send, send+fin", string.Join(", ", quic.Calls));
        });
    }

    private static Task Buffered(Http3Connection connection)
        => connection.RunAsync((_, _) => new ValueTask<Http3Response>(new Http3Response { Status = 413, Body = Answer }));

    private static Task Streamed(Http3Connection connection)
        => connection.RunAsync((_, _, writer) =>
        {
            writer.WriteHeaders(new Http3Response { Status = 413 });
            writer.Write(Answer);
            return ValueTask.CompletedTask;
        });

    private static ValueTask<Http3Response> ThrowsAtOnce(Http3Request request, Http3BodyReader body)
        => throw new InvalidOperationException("the handler failed before it returned");

    private readonly record struct Served(OrderQuic Quic, Task Run);

    // Stream 0's request, served at once: with no reactor every await here completes inline, on this thread.
    private static Served Start(byte[] request, bool ended, Func<Http3Connection, Task> serve)
    {
        var quic = new OrderQuic();
        Assert.True(quic.EnqueueStreamData(0, request, ended), "the recv ring refused the request");
        quic.SignalDataArrived();
        return new Served(quic, serve(new Http3Connection(quic)));
    }

    private static string End(Served served)
    {
        served.Quic.MarkClosed();
        Assert.True(served.Run.Wait(5000), "the run loop never ended");
        return string.Join(", ", served.Quic.Calls);
    }

    // What the stack asks of its transport on stream 0, in order. The read surface is the real base one.
    private sealed class OrderQuic : QuicConnection
    {
        public readonly List<string> Calls = [];
        private long _nextUni = 3;

        public OrderQuic()
        {
            NegotiatedProtocol = "h3";
        }

        public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos) { }
        public override long GetNextTimeout(long nowMs) => long.MaxValue;
        public override void OnTimer(long nowMs) { }
        public override void OnEvicted(QuicEvictReason reason) { }

        public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin)
        {
            if (streamId == 0)
            {
                Calls.Add(fin ? "send+fin" : "send");
            }
        }

        public override void ResetStream(long streamId, ulong applicationErrorCode) => Calls.Add($"reset 0x{applicationErrorCode:x}");

        public override void StopReading(long streamId, ulong applicationErrorCode) => Calls.Add($"stop 0x{applicationErrorCode:x}");

        public override long OpenUniStream()
        {
            long id = _nextUni;
            _nextUni += 4;
            return id;
        }

        public override void Close(ulong applicationErrorCode)
        {
            Calls.Add($"close 0x{applicationErrorCode:x}");
            MarkClosed();
        }
    }
}
