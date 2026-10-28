using System.Buffers;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// Streamed HTTP/2 response BODIES, asserted by content rather than by frame shape.
///
/// The shape these cover is the one a static file server produces: headers written inside the
/// dispatch pass, then a park on the file read, then the body pushed as chunks with a flush after
/// each - because the producer is copying into a bounded buffer and has to drain it before it can
/// stage the next slice. A response that loses those bytes still emits well-formed HEADERS and a
/// well-formed END_STREAM, so every assertion here reassembles the DATA payloads and compares them
/// to what the handler wrote. Frame-shape assertions alone cannot see the failure.
/// </summary>
internal static class Http2StreamedBodyTests
{
    // What GenHTTP's IoxideFiles module uses: sized to leave room for status + headers in a 16 KiB
    // write slab. The exact number does not matter here, only that the body needs several of them.
    private const int FileChunk = 12 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("h2 body: a small response completed in one go arrives whole", () =>
        {
            byte[] file = Pattern(202);

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write(file);
                await writer.CompleteAsync();
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);

            List<Frame> frames = client.Drain();
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: a small response flushed before completion arrives whole", () =>
        {
            byte[] file = Pattern(202);

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write(file);
                await writer.FlushAsync();               // the producer drains its buffer...
                await writer.CompleteAsync();            // ...and only then ends the stream
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);

            List<Frame> frames = client.Drain();
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: a file resumed outside the pass and flushed per chunk arrives whole", () =>
        {
            // The static-file shape end to end: 8 KiB is one chunk, but the park before it is what
            // moves every flush outside the dispatch pass and onto the real-write path.
            byte[] file = Pattern(8 * 1024);
            var read = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await read.Task;                         // the file read, off the ring
                await WriteChunked(writer, file);
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);
            List<Frame> frames = client.Drain();         // the pass flush: ack + HEADERS

            read.SetResult();

            frames.AddRange(client.Drain());
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: a multi-chunk file flushed per chunk arrives whole and in order", () =>
        {
            // Several chunks AND several DATA frames per chunk: 12 KiB does not fit the peer's
            // 16 KiB maximum frame size cleanly once headers are accounted for, so ordering across
            // the split is part of what is asserted.
            byte[] file = Pattern((3 * FileChunk) + 517);
            var read = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await read.Task;
                await WriteChunked(writer, file);
            });

            client.ReleaseFlush();
            client.SendRequests(1);
            List<Frame> frames = client.Drain();

            read.SetResult();

            // Past the initial 65535-byte windows the writer parks on credit, exactly as it would
            // against a real client; crediting both windows lets the rest through.
            frames.AddRange(DrainWithCredit(client, streamId: 1));
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: a file larger than the peer's window arrives whole", () =>
        {
            // 256 KiB against a 65535-byte connection window: the response cannot complete without
            // WINDOW_UPDATE, so this covers the park-and-resume path a large download always takes.
            byte[] file = Pattern(256 * 1024);
            var read = new TaskCompletionSource();

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await read.Task;
                await WriteChunked(writer, file);
            });

            client.ReleaseFlush();
            client.SendRequests(1);
            List<Frame> frames = client.Drain();

            read.SetResult();

            frames.AddRange(DrainWithCredit(client, streamId: 1));
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: chunks staged inside the pass coalesce into one transport write", () =>
        {
            // Nothing here parks, so every chunk stays inside the dispatch pass and rides its
            // flush. Coalescing is the point of that design; this pins it so a fix for the
            // resumed-outside-the-pass case cannot quietly buy correctness by flushing per chunk.
            byte[] file = Pattern(4 * 1024);

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                for (int at = 0; at < file.Length; at += 512)
                {
                    writer.Write(file.AsSpan(at, 512));
                    await writer.FlushAsync();
                }
                await writer.CompleteAsync();
            });

            client.ReleaseFlush();                       // server SETTINGS
            client.SendRequests(1);

            Assert.Equal(1, client.PendingFlushes);      // eight chunks, one write
            List<Frame> frames = client.Drain();
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: a producer past the coalesce limit writes for real inside the pass", () =>
        {
            // A producer that never awaits anything of its own has no yield but the write. Past
            // CoalesceLimit the writer must flush for real, or the reactor spins and the response
            // never moves.
            byte[] file = Pattern(64 * 1024);

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                for (int at = 0; at < file.Length; at += 4 * 1024)
                {
                    writer.Write(file.AsSpan(at, 4 * 1024));
                    await writer.FlushAsync();
                }
                await writer.CompleteAsync();
            });

            client.ReleaseFlush();
            client.SendRequests(1);

            List<Frame> frames = DrainWithCredit(client, streamId: 1);
            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });

        runner.Test("h2 body: credit arriving while the pre-park flush is in flight is not lost", () =>
        {
            // Before parking on credit the writer flushes what it has staged, because the peer only
            // sends WINDOW_UPDATE once it has consumed DATA. That flush is an await, so the credit
            // can arrive while the writer is inside it - before it has registered as a waiter. The
            // wake-up then has nowhere to be recorded, and the writer parks on a message that has
            // already been and gone.
            //
            // DrainWithCredit cannot see this: it only credits once the flush has been released and
            // the writer is already registered. So this drains the other way round - credit first,
            // release second - which puts every WINDOW_UPDATE inside the window that loses it.
            byte[] file = Pattern(200_000);   // past the 65535-byte initial window, so it must park

            using var client = new StrictClient();
            Task run = client.Connection.RunAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });
                await WriteChunked(writer, file);
            });

            client.ReleaseFlush();
            client.SendRequests(1);

            var frames = new List<Frame>();

            for (int turn = 0; turn < 4096; turn++)
            {
                if (client.PendingFlushes == 0)
                {
                    // Nothing left in flight. Either the stream finished, or the writer is parked on
                    // a wake-up that was dropped - the assertions below say which.
                    break;
                }

                // Deliberately small. A window big enough to carry the rest of the file would let
                // the writer finish without ever parking, which is the case this is not about.
                client.SendWindowUpdate(1, 8 * 1024);
                client.SendWindowUpdate(0, 8 * 1024);

                frames.AddRange(Frame.Walk(client.ReleaseFlush()));

                if (frames.Any(f => f is { Type: Frame.Data, EndStream: true } && f.StreamId == 1))
                {
                    break;
                }
            }

            AssertBody(file, frames, streamId: 1);

            client.Close(run);
        });
    }

    // The IoxideFiles copy loop: stage at most Chunk bytes, drain, repeat - then end the stream.
    private static async ValueTask WriteChunked(Http2ResponseWriter writer, byte[] file)
    {
        for (int at = 0; at < file.Length; at += FileChunk)
        {
            writer.Write(file.AsSpan(at, Math.Min(FileChunk, file.Length - at)));
            await writer.FlushAsync();
        }
        await writer.CompleteAsync();
    }

    // Release flushes, crediting both windows whenever the writer runs dry, until the stream ends.
    private static List<Frame> DrainWithCredit(StrictClient client, int streamId)
    {
        var frames = new List<Frame>();

        for (int turn = 0; turn < 4096; turn++)
        {
            if (client.PendingFlushes == 0)
            {
                if (frames.Any(f => f is { Type: Frame.Data, EndStream: true } && f.StreamId == streamId))
                {
                    break;
                }

                // Parked on flow control: credit the stream and the connection alike, since either
                // can be the one holding the writer.
                client.SendWindowUpdate(streamId, 1 << 20);
                client.SendWindowUpdate(0, 1 << 20);

                if (client.PendingFlushes == 0)
                {
                    break;   // not a credit stall; let the assertions report what is missing
                }
            }

            frames.AddRange(Frame.Walk(client.ReleaseFlush()));
        }

        return frames;
    }

    private static void AssertBody(byte[] expected, List<Frame> frames, int streamId)
    {
        Assert.True(frames.Any(f => f.Type == Frame.Headers && f.StreamId == streamId),
            $"HEADERS for stream {streamId}");
        Assert.True(frames.Any(f => f is { Type: Frame.Data, EndStream: true } && f.StreamId == streamId),
            $"DATA with END_STREAM for stream {streamId}");

        byte[] body = Frame.Body(frames, streamId);

        Assert.True(body.Length == expected.Length,
            $"body length: expected {expected.Length}, received {body.Length}");
        Assert.True(body.AsSpan().SequenceEqual(expected),
            $"body content differs at offset {FirstDifference(expected, body)}");
    }

    private static int FirstDifference(byte[] expected, byte[] actual)
    {
        for (int i = 0; i < Math.Min(expected.Length, actual.Length); i++)
        {
            if (expected[i] != actual[i])
            {
                return i;
            }
        }
        return Math.Min(expected.Length, actual.Length);
    }

    // Position-dependent, so a body reassembled out of order fails on content and not only length.
    private static byte[] Pattern(int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)((i * 31) ^ (i >> 8));
        }
        return bytes;
    }
}
