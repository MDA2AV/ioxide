using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.nghttp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// Streamed request bodies on the nghttp2 server (<see cref="Nghttp2Options.StreamRequestBodies"/>),
/// driven by a raw client that keeps to the server's flow-control windows.
///
/// The session runs with nghttp2's automatic WINDOW_UPDATE off, so the only credit a peer gets back
/// is what the server consumes, and every DATA byte must be consumed exactly once. A byte that never
/// is shrinks the connection window for good. These tests make each way of leaking it stall an
/// upload: the window is 65535 bytes, so an upload past it completes only if credit keeps coming
/// back, and one the server should be holding stalls at the window instead of running ahead.
/// </summary>
internal static class Nghttp2StreamedRequestTests
{
    // RFC 9113's initial connection window, which nghttp2 leaves as it is: the most a peer may send
    // ahead of what the server has consumed, on every stream together.
    private const int ConnectionWindow = 65535;

    private const int Large = 4 * 1024 * 1024;
    private const int Frame = 16384;
    private const uint NoError = 0x0, InternalError = 0x2, Cancel = 0x8;

    /// <summary>What one handler saw of its body. Broken is the first offset off the pattern, -1 for none.</summary>
    private readonly record struct Seen(int Stream, string Path, long Bytes, int Chunks, long Broken, bool Streamed);

    public static void Register(Runner runner)
    {
        foreach (bool streamedResponse in new[] { false, true })
        {
            bool sr = streamedResponse;
            string flavor = sr ? "RunAsync" : "RunBufferedAsync";

            runner.Test($"nghttp2 streamed request ({flavor}): a 4 MiB upload read a chunk at a time arrives whole and in order", () =>
            {
                var seen = new ConcurrentQueue<Seen>();
                using var client = new H2cClient(Start(seen, sr), timeoutMs: 30_000);
                client.Open();

                (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 1, Large, path: "/read");

                Assert.True(end == H2cClient.UploadEnd.Answered && sent == Large,
                    $"the upload ended {end} (error 0x{error:x}) after {sent} of {Large} bytes");
                Seen read = Single(seen, 1);
                Assert.True(read.Streamed && read.Bytes == Large && read.Broken < 0,
                    $"the handler read {Describe(seen)}, not {Large} bytes in order");
                Assert.True(read.Chunks > 1, $"the body reached the handler in {read.Chunks} chunk, not streamed");
            });

            runner.Test($"nghttp2 streamed request ({flavor}): uploads a handler never reads give their connection credit back",
                () => UnreadUploadsGiveCreditBack(sr));
        }

        runner.Test("nghttp2 streamed request: a handler that has not read holds its peer to one window, and the upload completes once it reads", () =>
        {
            // "/hold" reads nothing until "/go" arrives on the same connection. HEADERS are not flow
            // controlled, so the release still gets through once the window is spent.
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false), timeoutMs: 30_000);
            client.Open();

            long stalledAt = -1;
            (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 1, Large, path: "/hold",
                onStall: at =>
                {
                    stalledAt = at;
                    client.Request(streamId: 3, path: "/go");
                });

            Assert.True(stalledAt >= 0,
                $"the client never stalled: the server took {sent} bytes while its handler read none");
            Assert.True(stalledAt == ConnectionWindow,
                $"the server took {stalledAt} bytes before its handler read any, not one {ConnectionWindow}-byte window");
            Assert.True(end == H2cClient.UploadEnd.Answered && sent == Large,
                $"once the handler read, the upload ended {end} (error 0x{error:x}) after {sent} of {Large} bytes");
            Seen held = Single(seen, 1);
            Assert.True(held.Bytes == Large && held.Broken < 0, $"the handler read {Describe(seen)}, not {Large} bytes in order");
        });

        foreach ((uint code, string name) in new[] { (Cancel, "CANCEL"), (NoError, "NO_ERROR") })
        {
            uint resetCode = code;
            runner.Test($"nghttp2 streamed request: a peer RST_STREAM ({name}) mid-body ends the handler's read, and the connection serves on", () =>
            {
                var seen = new ConcurrentQueue<Seen>();
                using var client = new H2cClient(Start(seen, streamedResponse: false), timeoutMs: 30_000);
                client.Open();

                client.OpenPost(streamId: 1, "/read");
                client.SendData(streamId: 1, offset: 0, Frame);
                client.SendData(streamId: 1, offset: Frame, Frame);

                // nghttp2 returns credit once half its window is consumed, so this is the handler
                // having read all of it, and parked on its next read when the reset lands.
                Assert.True(client.AwaitConnectionWindow(ConnectionWindow), "the handler never read the first 32768 bytes");
                client.ResetStream(streamId: 1, resetCode);

                const int After = 256 * 1024;
                (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 3, After, path: "/read");
                Assert.True(end == H2cClient.UploadEnd.Answered && sent == After,
                    $"after a stream was reset mid-body the next upload ended {end} (error 0x{error:x}) after {sent} of {After} bytes");

                // Ended by the reset, so it was recorded before the upload after it could be answered.
                Seen reset = Single(seen, 1);
                Assert.True(reset.Bytes == 2 * Frame && reset.Broken < 0,
                    $"the reset stream's handler saw {Describe(seen)}, not its {2 * Frame} bytes and then the end");
            });
        }

        runner.Test("nghttp2 streamed request: trailers after the handler has answered never reach a handler as a request", () =>
        {
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false), timeoutMs: 30_000);
            client.Open();

            client.OpenPost(streamId: 1, "/unread");
            Assert.True(client.AwaitResponse(streamId: 1), "the server did not answer the upload");

            // The stream is still open from the client's side: its body and then its trailers follow.
            client.SendData(streamId: 1, offset: 0, 100);
            client.WriteFrame(0x1, flags: 0x5, streamId: 1, ReadOnlySpan<byte>.Empty);   // trailers + END_STREAM

            client.Request(streamId: 3, path: "/go");
            Assert.True(client.AwaitResponse(streamId: 3), "the connection stopped serving after the trailers");
            Assert.True(seen.Count(s => s.Stream == 1) == 1, $"the trailers reached a handler as a request: {Describe(seen)}");
        });

        runner.Test("nghttp2 streamed request: a body left unread when its stream is reset gives its connection credit back", () =>
        {
            // A whole window queued behind "/hold" when the peer abandons the stream: if those bytes
            // were not credited, no DATA could follow on any stream of the connection.
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false), timeoutMs: 30_000);
            client.Open();

            client.OpenPost(streamId: 1, "/hold");
            for (int at = 0; at < ConnectionWindow; at += Frame)
            {
                client.SendData(streamId: 1, offset: at, Math.Min(Frame, ConnectionWindow - at));
            }
            client.ResetStream(streamId: 1, Cancel);
            client.Request(streamId: 3, path: "/go");

            const int After = 256 * 1024;
            (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 5, After, path: "/read");
            Assert.True(end == H2cClient.UploadEnd.Answered && sent == After,
                $"after a reset stream left {ConnectionWindow} bytes unread, the next upload ended {end} "
                + $"(error 0x{error:x}) after {sent} of {After} bytes: their credit never came back");

            Seen held = Single(seen, 1);
            Assert.True(held.Bytes == 0, $"the reset stream's handler still read a body its peer abandoned: {Describe(seen)}");
        });

        runner.Test("nghttp2 streamed request: a handler that fails mid-upload has its stream reset, and the connection keeps its credit", () =>
        {
            // "/fail" sends its headers, then fails once "/go" releases it, with a window of its body
            // still unread - so its stream is reset by the server rather than by the peer.
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: true), timeoutMs: 30_000);
            client.Open();

            (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 1, Large, path: "/fail",
                onStall: _ => client.Request(streamId: 3, path: "/go"));
            Assert.True(end == H2cClient.UploadEnd.Reset && error == InternalError,
                $"the failed handler's stream ended {end} (error 0x{error:x}) after {sent} bytes, not RST_STREAM INTERNAL_ERROR");

            const int After = 256 * 1024;
            (end, error, sent) = client.Upload(streamId: 5, After, path: "/read");
            Assert.True(end == H2cClient.UploadEnd.Answered && sent == After,
                $"after the server reset a stream mid-upload the next upload ended {end} (error 0x{error:x}) "
                + $"after {sent} of {After} bytes");
        });

        runner.Test("nghttp2 streamed request: a body nghttp2 resets for overrunning its content-length ends the handler's read", () =>
        {
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false), timeoutMs: 30_000);
            client.Open();

            // Settles the SETTINGS exchange, so the client has nothing left to send that could start a pass.
            client.Request(streamId: 1, path: "/go");
            Assert.True(client.AwaitResponse(streamId: 1), "the server did not answer a plain request");

            client.InOneWrite(() =>
            {
                client.OpenPost(streamId: 3, "/read", contentLength: 10);
                client.SendData(streamId: 3, offset: 0, 20);
            });

            // nghttp2 resets the stream itself, and it only closes as that RST_STREAM goes out: in the
            // drain, after the pass that read the DATA has dispatched. The client stays silent from
            // here, so no later pass can be what ends the handler's read.
            Assert.True(client.AwaitAnyOf([H2cClient.RstStream], streamId: 3) == H2cClient.RstStream,
                "nghttp2 did not reset a body longer than its content-length");
            Assert.True(WaitFor(() => seen.Any(s => s.Stream == 3)), $"the handler's read never ended: {Describe(seen)}");
            Assert.True(Single(seen, 3).Bytes == 0, $"the handler read bytes nghttp2 refused: {Describe(seen)}");
        });

        runner.Test("nghttp2 streamed request: the chunk a handler holds stays its own when the connection goes away under it", () =>
        {
            // The handler takes a chunk, holds it across the teardown, then looks for its buffer in the
            // pool: a chunk is the handler's until its next read or its return, whatever the peer does.
            var verdict = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(async (reactor, conn) =>
            {
                var torn = new TaskCompletionSource();
                try
                {
                    await new Nghttp2Connection(conn, new Nghttp2Options { StreamRequestBodies = true })
                        .RunAsync(async (request, writer) =>
                        {
                            ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
                            writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                            await writer.FlushAsync();   // tells the client the chunk is taken
                            await torn.Task;
                            verdict.TrySetResult(MemoryMarshal.TryGetArray(chunk, out ArraySegment<byte> held) && InPool(held.Array!)
                                ? "its buffer was back in the pool" : "it was still its own");
                        });
                }
                finally
                {
                    conn.DecRef();
                    torn.TrySetResult();
                }
            });

            using (var client = new H2cClient(port, timeoutMs: 30_000))
            {
                client.Open();
                client.OpenPost(streamId: 1, "/keep");
                client.SendData(streamId: 1, offset: 0, Frame);
                Assert.True(client.AwaitResponse(streamId: 1), "the handler never took a chunk");
            }

            Assert.True(verdict.Task.Wait(10_000), "the handler never resumed after its connection went away");
            Assert.True(verdict.Task.Result == "it was still its own",
                $"the connection went away under a handler holding a chunk, and {verdict.Task.Result}");
        });

        runner.Test("nghttp2 streamed request: a handler parked on its body when the connection goes away reads the end of it", () =>
        {
            var verdict = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(async (reactor, conn) =>
            {
                try
                {
                    await new Nghttp2Connection(conn, new Nghttp2Options { StreamRequestBodies = true })
                        .RunBufferedAsync(async request =>
                        {
                            long bytes = 0;
                            ReadOnlyMemory<byte> chunk;
                            while (!(chunk = await request.BodyReader!.ReadAsync()).IsEmpty)
                            {
                                bytes += chunk.Length;
                            }
                            verdict.TrySetResult(bytes);
                            return new Nghttp2Response { Status = 200 };
                        });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using (var client = new H2cClient(port, timeoutMs: 30_000))
            {
                client.Open();
                client.OpenPost(streamId: 1, "/park");
                client.SendData(streamId: 1, offset: 0, Frame);
                client.SendData(streamId: 1, offset: Frame, Frame);

                // nghttp2 returns credit once half its window is consumed, so this is the handler
                // having read all of it, and parked on its next read when the connection goes away.
                Assert.True(client.AwaitConnectionWindow(ConnectionWindow), "the handler never read the first 32768 bytes");
            }

            Assert.True(verdict.Task.Wait(10_000), "the handler parked on its body never woke when its connection went away");
            Assert.True(verdict.Task.Result == 2 * Frame, $"the handler read {verdict.Task.Result} bytes, not {2 * Frame} and then the end");
        });

        runner.Test("nghttp2 streamed request: a padded upload reaches the handler without its padding, and the padding's credit comes back", () =>
        {
            // 255 bytes of padding per frame comes to more than a window over 4 MiB, so padding that
            // was never credited would stall the upload on its own.
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false), timeoutMs: 30_000);
            client.Open();

            (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 1, Large, path: "/read", padding: 255);

            Assert.True(end == H2cClient.UploadEnd.Answered && sent == Large,
                $"the padded upload ended {end} (error 0x{error:x}) after {sent} of {Large} bytes");
            Seen read = Single(seen, 1);
            Assert.True(read.Bytes == Large && read.Broken < 0, $"the handler read {Describe(seen)}, not {Large} bytes in order");
        });

        runner.Test("nghttp2 streamed request: MaxRequestBytes does not cap a streamed body", () =>
        {
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false, maxRequestBytes: Large / 4), timeoutMs: 30_000);
            client.Open();

            (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 1, Large, path: "/read");

            Assert.True(end == H2cClient.UploadEnd.Answered && sent == Large,
                $"a {Large}-byte streamed body against a {Large / 4}-byte cap ended {end} (error 0x{error:x}) after {sent} bytes");
            Seen read = Single(seen, 1);
            Assert.True(read.Streamed && read.Bytes == Large && read.Broken < 0, $"the handler read {Describe(seen)}");
        });

        runner.Test("nghttp2 streamed request: control: with StreamRequestBodies off the body arrives whole, and one past MaxRequestBytes is still reset", () =>
        {
            const int Cap = Large / 4;
            var seen = new ConcurrentQueue<Seen>();
            using var client = new H2cClient(Start(seen, streamedResponse: false, streamBodies: false, maxRequestBytes: Cap),
                timeoutMs: 30_000);
            client.Open();

            (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: 1, Cap, path: "/read");
            Assert.True(end == H2cClient.UploadEnd.Answered && sent == Cap,
                $"a {Cap}-byte body against a {Cap}-byte cap ended {end} (error 0x{error:x}) after {sent} bytes");
            Seen whole = Single(seen, 1);
            Assert.True(!whole.Streamed && whole.Bytes == Cap && whole.Broken < 0,
                $"the handler saw {Describe(seen)}, not a {Cap}-byte body in Body");

            (end, error, sent) = client.Upload(streamId: 3, Large, path: "/read");
            Assert.True(end == H2cClient.UploadEnd.Reset && error == H2cClient.EnhanceYourCalm,
                $"a {Large}-byte body against a {Cap}-byte cap ended {end} (error 0x{error:x}) after {sent} bytes");
            Assert.True(seen.All(s => s.Stream != 3), $"the handler saw the oversized stream: {Describe(seen)}");
        });
    }

    // Each upload fits the connection window and five cross it, so only credit that never comes
    // back can wedge them.
    private const int UploadBytes = 40 * 1024;
    private const int Uploads = 5;

    /// <summary>
    /// Uploads on three connections to one server: "/read" reads every body to its end, "/unread"
    /// answers without touching one, and "/unread-after-a-wait" leaves it after a wait on the ring.
    /// </summary>
    private static void UnreadUploadsGiveCreditBack(bool streamedResponse)
    {
        Assert.True(Uploads * (long)UploadBytes > ConnectionWindow && UploadBytes < ConnectionWindow,
            "the uploads must cross the connection window while each fits it");

        var seen = new ConcurrentQueue<Seen>();
        int port = Start(seen, streamedResponse);

        foreach (string path in new[] { "/read", "/unread", "/unread-after-a-wait" })
        {
            using var client = new H2cClient(port, timeoutMs: 15_000);
            client.Open();

            for (int i = 1; i <= Uploads; i++)
            {
                (H2cClient.UploadEnd end, uint error, long sent) = client.Upload(streamId: (2 * i) - 1, UploadBytes, path: path);
                Assert.True(end == H2cClient.UploadEnd.Answered && sent == UploadBytes,
                    $"{path}: upload {i} of {Uploads}, {(i - 1) * UploadBytes / 1024} KiB already sent, ended {end} "
                    + $"(error 0x{error:x}) after {sent} of {UploadBytes} bytes");
            }
        }

        Assert.Equal(Uploads * (long)UploadBytes, seen.Where(s => s.Path == "/read").Sum(s => s.Bytes));
        Assert.Equal(2 * Uploads, seen.Count(s => s.Path.StartsWith("/unread", StringComparison.Ordinal)));
    }

    /// <summary>
    /// A server over <see cref="Nghttp2Connection"/>, either flavor, recording what each handler saw.
    /// "/read" reads its body to the end; "/hold" does the same once "/go" on its connection releases
    /// it; "/unread" answers without reading, and "/unread-after-a-wait" after a ring wait. Under
    /// RunAsync, "/fail" sends its headers and fails once released.
    /// </summary>
    private static int Start(ConcurrentQueue<Seen> seen, bool streamedResponse, bool streamBodies = true,
        int maxRequestBytes = 8 * 1024 * 1024) => TestServer.Start(async (reactor, conn) =>
    {
        try
        {
            var connection = new Nghttp2Connection(conn,
                new Nghttp2Options { StreamRequestBodies = streamBodies, MaxRequestBytes = maxRequestBytes });
            var timer = new RingTimer(reactor);
            var gate = new TaskCompletionSource();

            if (streamedResponse)
            {
                await connection.RunAsync(async (request, writer) =>
                {
                    if (request.Path.Span.SequenceEqual("/fail"u8))
                    {
                        writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                        await writer.FlushAsync();
                        await gate.Task;
                        throw new InvalidOperationException("the handler failed mid-upload");
                    }
                    writer.WriteHeaders(new Nghttp2Response { Status = await Serve(request, timer, gate, seen) });
                });
            }
            else
            {
                await connection.RunBufferedAsync(async request =>
                    new Nghttp2Response { Status = await Serve(request, timer, gate, seen) });
            }
        }
        finally
        {
            conn.DecRef();
        }
    });

    private static async ValueTask<int> Serve(Nghttp2Request request, RingTimer timer, TaskCompletionSource gate,
        ConcurrentQueue<Seen> seen)
    {
        string path = Encoding.ASCII.GetString(request.Path.Span);
        switch (path)
        {
            case "/go":
                gate.TrySetResult();
                return 200;

            case "/unread-after-a-wait":
                await timer.DelayAsync(50);
                seen.Enqueue(new Seen(request.StreamId, path, 0, 0, -1, Streamed: true));
                return 401;

            case "/unread":
                seen.Enqueue(new Seen(request.StreamId, path, 0, 0, -1, Streamed: true));
                return 401;

            case "/hold":
                await gate.Task;
                break;
        }

        if (request.BodyReader is not { } reader)
        {
            seen.Enqueue(new Seen(request.StreamId, path, request.Body.Length, 0, FirstBreak(request.Body.Span, 0), Streamed: false));
            return 200;
        }

        long bytes = 0, broken = -1;
        int chunks = 0;
        ReadOnlyMemory<byte> chunk;
        while (!(chunk = await reader.ReadAsync()).IsEmpty)
        {
            if (broken < 0)
            {
                broken = FirstBreak(chunk.Span, bytes);
            }
            bytes += chunk.Length;
            chunks++;
        }

        seen.Enqueue(new Seen(request.StreamId, path, bytes, chunks, broken, Streamed: true));
        return 200;
    }

    private static long FirstBreak(ReadOnlySpan<byte> data, long offset)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] != H2cClient.PatternAt(offset + i))
            {
                return offset + i;
            }
        }
        return -1;
    }

    // Whether the pool hands this very array out again. Everything rented on the way goes back, but
    // not the array itself: its owner still returns that one.
    private static bool InPool(byte[] array)
    {
        var rented = new List<byte[]>();
        bool found = false;
        for (int i = 0; i < 64 && !found; i++)
        {
            byte[] next = ArrayPool<byte>.Shared.Rent(array.Length);
            found = ReferenceEquals(next, array);
            if (!found)
            {
                rented.Add(next);
            }
        }

        foreach (byte[] next in rented)
        {
            ArrayPool<byte>.Shared.Return(next);
        }
        return found;
    }

    // For server-side state no wire event can signal; a generous bound, never a measure of speed.
    private static bool WaitFor(Func<bool> condition, int timeoutMs = 10_000)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (!condition())
        {
            if (Environment.TickCount64 > deadline)
            {
                return false;
            }
            Thread.Sleep(10);
        }
        return true;
    }

    private static Seen Single(ConcurrentQueue<Seen> seen, int stream)
    {
        Seen[] matches = [.. seen.Where(s => s.Stream == stream)];
        Assert.True(matches.Length == 1, $"no single handler finished stream {stream}; the handlers saw {Describe(seen)}");
        return matches[0];
    }

    private static string Describe(ConcurrentQueue<Seen> seen) => seen.IsEmpty
        ? "nothing"
        : string.Join(", ", seen.Select(s => $"{s.Path} on stream {s.Stream}: {s.Bytes} bytes in {s.Chunks} chunks"
                                           + (s.Broken >= 0 ? $", off the pattern at {s.Broken}" : "")));
}
