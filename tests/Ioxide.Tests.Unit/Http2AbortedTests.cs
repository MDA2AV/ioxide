using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// A response writer's Aborted token and the ends a streamed response can have. The token is cancelled
/// when the stream is reset or the connection goes while its handler runs, and never for a response
/// that ends; trailers carry END_STREAM, and a response can end on its headers.
/// </summary>
internal static class Http2AbortedTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 aborted: a reset cancels the token of a handler waiting on something else", () =>
        {
            CancellationToken token = default;
            using var peer = new Peer((_, _, writer) =>
            {
                token = writer.Aborted;
                return UntilCancelled(token);
            });

            peer.Feed(Request(1, endStream: true));
            Assert.True(!token.IsCancellationRequested, "the token was cancelled before anything was reset");
            peer.Feed(Http2FlowControlTests.RstStream(1, 8));
            Assert.True(token.IsCancellationRequested, "the peer reset the stream, and the handler's token never heard");
        });

        runner.Test("h2 aborted: a flush the reset ends finds the token already cancelled", () =>
        {
            string outcome = "the flush never returned";
            using var peer = new Peer(async (_, _, writer) =>
            {
                CancellationToken token = writer.Aborted;
                writer.WriteHeaders(new Http2Response());
                Fill(writer, 200_000);   // far past the peer's window: the flush waits on credit
                FlushResult flushed = await writer.FlushAsync();
                outcome = (flushed.IsCompleted, token.IsCancellationRequested) switch
                {
                    (true, true) => "peer gone, token cancelled",
                    (true, false) => "peer gone, token not yet cancelled",
                    _ => "flushed",
                };
            });

            peer.Feed(Request(1, endStream: true));
            peer.Feed(Http2FlowControlTests.RstStream(1, 8));
            Assert.Equal("peer gone, token cancelled", outcome);
        });

        runner.Test("h2 aborted: a connection that goes cancels the token of a handler waiting on something else", () =>
        {
            CancellationToken token = default;
            var peer = new Peer((_, _, writer) =>
            {
                token = writer.Aborted;
                return UntilCancelled(token);
            });

            peer.Feed(Request(1, endStream: true));
            peer.Dispose();   // the client's side ends, and the connection tears down
            Assert.True(token.IsCancellationRequested, "the connection went, and the handler's token never heard");
        });

        runner.Test("h2 aborted: a handler that returns on hearing the connection go still has its token cancelled", () =>
        {
            CancellationToken token = default;
            var peer = new Peer(async (_, body, writer) =>
            {
                token = writer.Aborted;
                try
                {
                    await body.ReadAsync();   // the teardown ends this first, and the handler returns before any token is cancelled
                }
                catch (IOException)
                {
                }
            });

            peer.Feed(Request(1, endStream: false));
            peer.Dispose();
            Assert.True(token.IsCancellationRequested, "the handler returned on its cut-off body, and its token was never cancelled");
        });

        runner.Test("h2 aborted: a token taken after its stream was reset is cancelled at once", () =>
        {
            CancellationToken token = default;
            using var peer = new Peer((_, _, writer) =>
            {
                token = writer.Aborted;
                return Task.CompletedTask;
            });

            // One read: the reset is in before the handler runs.
            peer.Feed([.. Request(1, endStream: true), .. Http2FlowControlTests.RstStream(1, 8)]);
            Assert.True(token.IsCancellationRequested, "a token taken on a stream already reset was never cancelled");
        });

        runner.Test("h2 aborted: a response that ends never cancels its token", () =>
        {
            CancellationToken token = default;
            using var peer = new Peer(async (request, _, writer) =>
            {
                if (request.StreamId == 1)
                {
                    token = writer.Aborted;
                }
                writer.WriteHeaders(new Http2Response());
                await writer.CompleteAsync(Trailer("x-t", "1"));
            });

            peer.Feed(Request(1, endStream: true));
            peer.Feed(Request(3, endStream: true));   // a later stream, once stream 1's close has gone by
            Assert.True(!token.IsCancellationRequested, "a response that ended cancelled its handler's token");
        });

        runner.Test("h2 aborted: the next stream on a pooled writer gets a token of its own", () =>
        {
            var tokens = new Dictionary<int, CancellationToken>();
            using var peer = new Peer((request, _, writer) =>
            {
                tokens[request.StreamId] = writer.Aborted;
                return UntilCancelled(tokens[request.StreamId]);
            });

            peer.Feed(Request(1, endStream: true));
            peer.Feed(Http2FlowControlTests.RstStream(1, 8));   // its handler returns, and its writer goes back to the pool
            peer.Feed(Request(3, endStream: true));
            Assert.True(tokens[1].IsCancellationRequested, "stream 1 was reset, and its token never heard");
            Assert.True(!tokens[3].IsCancellationRequested, "stream 3 was handed stream 1's cancelled token by the pooled writer");

            peer.Feed(Http2FlowControlTests.RstStream(3, 8));
            Assert.True(tokens[3].IsCancellationRequested, "stream 3 was reset, and its token never heard");
        });

        runner.Test("h2 trailers: END_STREAM rides the trailer HEADERS, never the last DATA", () =>
        {
            using var peer = new Peer(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response());
                Fill(writer, 100);
                await writer.CompleteAsync(Trailer("x-t", "1"));
            });

            List<Frame> frames = peer.Feed(Request(1, endStream: true));
            Assert.True(frames is [{ Type: Frame.Headers, EndStream: false }, .., { Type: Frame.Headers, EndStream: true }],
                $"expected HEADERS, the body, then trailers ending the stream: {Describe(frames)}");
            Assert.True(frames.All(f => f.Type != Frame.Data || !f.EndStream), $"a DATA frame ended the stream ahead of its trailers: {Describe(frames)}");
            Assert.Equal(100, Frame.Body(frames, 1).Length);
        });

        runner.Test("h2 trailers: a body past the stream window sends its trailers only after its last byte", () =>
        {
            using var peer = new Peer(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http2Response());
                Fill(writer, 100_000);   // past the peer's 65,535 bytes of stream and connection window
                await writer.CompleteAsync(Trailer("x-t", "1"));
            });

            List<Frame> stalled = peer.Feed(Request(1, endStream: true));
            Assert.True(!stalled.Any(f => f.EndStream), $"the stream ended before the rest of its body had credit: {Describe(stalled)}");

            List<Frame> rest = peer.Feed([.. Http2FlowControlTests.WindowUpdate(0, 100_000), .. Http2FlowControlTests.WindowUpdate(1, 100_000)]);
            Assert.True(rest is [.., { Type: Frame.Headers, EndStream: true }], $"the trailers did not end the stream once credited: {Describe(rest)}");
            Assert.Equal(100_000, Frame.Body([.. stalled, .. rest], 1).Length);
        });

        runner.Test("h2 headers only: a response that ends on its headers is one HEADERS frame with END_STREAM", () =>
        {
            using var peer = new Peer((_, _, writer) => writer.CompleteAsync(new Http2Response { Status = 204 }).AsTask());

            List<Frame> frames = peer.Feed(Request(1, endStream: true));
            Assert.True(frames is [{ Type: Frame.Headers, EndStream: true }], $"expected one HEADERS with END_STREAM: {Describe(frames)}");
        });
    }

    // Waits on the token alone, as a handler waiting on a database or a feed would.
    private static async Task UntilCancelled(CancellationToken token)
    {
        var cancelled = new TaskCompletionSource();
        using (token.Register(() => cancelled.TrySetResult()))
        {
            await cancelled.Task;
        }
    }

    // POST / on :scheme http; END_STREAM when no body is to come.
    private static byte[] Request(int streamId, bool endStream)
        => Http2FlowControlTests.FrameBytes(0x1, endStream ? (byte)0x5 : (byte)0x4, streamId, [0x83, 0x86, 0x84]);

    private static KeyValueList Trailer(string name, string value)
    {
        var trailers = new KeyValueList();
        trailers.Add(Encoding.ASCII.GetBytes(name), Encoding.ASCII.GetBytes(value));
        return trailers;
    }

    private static void Fill(Http2ResponseWriter writer, int bytes)
    {
        writer.GetSpan(bytes)[..bytes].Fill((byte)'x');
        writer.Advance(bytes);
    }

    private static string Describe(List<Frame> frames)
        => string.Join(", ", frames.Select(f => $"{f.Type}/{f.Length}{(f.EndStream ? "/END" : "")}"));

    /// <summary>
    /// A connection over <see cref="StrictClient"/>, with no reactor: each feed is parsed, dispatched and
    /// answered inline, so what it returns is everything the server sent for it.
    /// </summary>
    private sealed class Peer : IDisposable
    {
        private readonly StrictClient _client = new();
        private readonly Task _run;
        private bool _closed;

        public Peer(Func<Http2Request, Http2BodyReader, Http2ResponseWriter, Task> handler)
        {
            _run = _client.Connection.RunAsync((request, body, writer) => new ValueTask(handler(request, body, writer)));
            _client.SendRequests();   // preface and SETTINGS
            _client.Drain();
        }

        /// <summary>Feed bytes in and return the HEADERS and DATA frames the server sent in answer.</summary>
        public List<Frame> Feed(byte[] bytes)
        {
            _client.Feed(bytes);
            return [.. _client.Drain().Where(frame => frame.Type is Frame.Headers or Frame.Data)];
        }

        public void Dispose()
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
            _client.Close(_run);
            _client.Dispose();
        }
    }
}
