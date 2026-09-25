using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// Streamed request bodies: the handler runs while the body is still arriving, and flow-control
/// credit goes back to the peer only as it READS.
///
/// That last part is the entire feature, and it is the part an end-to-end test cannot see - an
/// upload succeeds either way. What differs is what bounds memory: crediting on arrival lets a peer
/// send as fast as it likes, and the bytes pile up behind a slow handler. So these tests watch the
/// WINDOW_UPDATE frames rather than the body.
/// </summary>
internal static class Http2StreamedRequestTests
{
    public static void Register(Runner runner)
    {
        runner.Test("h2 streamed request: credit is returned on read, not on arrival", () =>
        {
            var gate = new TaskCompletionSource();
            var chunks = new List<int>();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(async request =>
            {
                await gate.Task;                       // hold the body unread, like a slow consumer

                while (true)
                {
                    ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
                    if (chunk.IsEmpty)
                    {
                        break;
                    }
                    chunks.Add(chunk.Length);
                }

                return Http2Response.Text("done");
            });

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.SendData(streamId: 1, bytes: 600, endStream: true);

            // The handler is parked before its first read. The bytes are in - and the peer has been
            // told nothing, so it may not send more.
            Assert.Equal(0, peer.CreditFor(streamId: 1));
            Assert.Equal(0, peer.CreditFor(streamId: 0));

            gate.SetResult();
            peer.Pump();

            // Read, and only now does the window open - on the stream AND on the connection, which
            // is the part HTTP/3 does not have to do.
            Assert.Equal(1000, peer.CreditFor(streamId: 1));
            Assert.Equal(1000, peer.CreditFor(streamId: 0));
            Assert.Equal(2, chunks.Count);
            Assert.Equal(400, chunks[0]);
            Assert.Equal(600, chunks[1]);

            peer.Close(run);
        });

        runner.Test("h2 streamed request: a read outside the pass still sends its credit", () =>
        {
            var gate = new TaskCompletionSource();
            int read = 0;

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(async request =>
            {
                await gate.Task;

                while (true)
                {
                    ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
                    if (chunk.IsEmpty)
                    {
                        break;
                    }
                    read += chunk.Length;
                }

                return Http2Response.Text("done");
            });

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.SendData(streamId: 1, bytes: 600, endStream: false);   // more to come

            // The handler resumes on its own - a disk write, a database, a timer - with no inbound
            // frame to start a pass. The peer is out of window by now and sends nothing until it is
            // credited, so a WINDOW_UPDATE that waits for the next pass flush waits forever. This is
            // the upload that stalled after its first connection window.
            gate.SetResult();

            Assert.Equal(1000, read);
            Assert.Equal(1000, peer.CreditFor(streamId: 1));
            Assert.Equal(1000, peer.CreditFor(streamId: 0));

            peer.SendData(streamId: 1, bytes: 1, endStream: true);
            peer.Close(run);
        });

        runner.Test("h2 streamed request: a body the handler never reads is credited to the connection", () =>
        {
            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            var gate = new TaskCompletionSource();

            // Answers without touching the body - an auth failure, a 404, a validation error.
            Task run = peer.Connection.RunBufferedAsync(async _ =>
            {
                await gate.Task;
                return Http2Response.Text("no");
            });

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.SendData(streamId: 1, bytes: 600, endStream: true);

            gate.SetResult();

            // Those bytes still count against the window every other stream shares. Without this a
            // long-lived browser connection loses a little per such request until no body on it
            // can move - every POST from then on hangs.
            Assert.Equal(1000, peer.CreditFor(streamId: 0));

            peer.Close(run);
        });

        runner.Test("h2 streamed request: a body larger than the connection window arrives whole", () =>
        {
            const int Total = 1_200_000;
            int read = 0;
            var resume = new TaskCompletionSource();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(async request =>
            {
                while (true)
                {
                    ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
                    if (chunk.IsEmpty)
                    {
                        break;
                    }
                    read += chunk.Length;

                    // An upload handler writes each chunk somewhere, and comes back when that is
                    // done - outside whatever pass delivered the chunk.
                    resume = new TaskCompletionSource();
                    await resume.Task;
                }

                return Http2Response.Text("done");
            });

            peer.OpenRequest(streamId: 1, endStream: false);

            // A well-behaved client: never more than the windows allow, and when both are spent it
            // waits for credit. The connection window starts at 65535 whatever SETTINGS say.
            int sent = 0;
            int connectionWindow = 65535;
            int streamWindow = new Http2Options().InitialWindowSize;
            int creditSeen = 0;
            DateTime deadline = DateTime.UtcNow.AddSeconds(5);

            while (sent < Total && DateTime.UtcNow < deadline)
            {
                int credit = peer.CreditFor(streamId: 0);
                connectionWindow += credit - creditSeen;
                creditSeen = credit;
                streamWindow = new Http2Options().InitialWindowSize + peer.CreditFor(streamId: 1) - sent;

                int chunk = Math.Min(16384, Math.Min(Total - sent, Math.Min(connectionWindow, streamWindow)));
                if (chunk <= 0)
                {
                    resume.TrySetResult();   // the "disk write" finishes; still single-threaded
                    Thread.Sleep(1);
                    continue;
                }

                peer.SendData(streamId: 1, bytes: chunk, endStream: sent + chunk == Total);
                sent += chunk;
                connectionWindow -= chunk;
            }

            Assert.Equal(Total, sent);

            while (read < Total && DateTime.UtcNow < deadline)
            {
                resume.TrySetResult();
                Thread.Sleep(1);
            }
            Assert.Equal(Total, read);

            peer.Close(run);
        });

        runner.Test("h2 streamed request: a request with no body reads empty at once", () =>
        {
            bool sawEmpty = false;

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(async request =>
            {
                sawEmpty = (await request.BodyReader!.ReadAsync()).IsEmpty;
                return Http2Response.Text("done");
            });

            // END_STREAM on the HEADERS: there is no body coming, so the reader has to end rather
            // than park forever waiting for a DATA frame that cannot arrive.
            peer.OpenRequest(streamId: 1, endStream: true);
            peer.Pump();

            Assert.True(sawEmpty, "a bodyless request should read empty immediately");
            peer.Close(run);
        });

        runner.Test("h2 streamed request: buffered dispatch still assembles the body", () =>
        {
            int seen = -1;

            using var peer = new Peer(new Http2Options());   // streaming OFF - the default
            Task run = peer.Connection.RunBufferedAsync(request =>
            {
                seen = request.Body.Length;
                Assert.True(request.BodyReader is null, "buffered dispatch hands over no reader");
                return Http2Response.Text("done");
            });

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.SendData(streamId: 1, bytes: 600, endStream: true);
            peer.Pump();

            // The other half of the trade: the whole body is in hand before the handler runs, and
            // the window was credited as it arrived rather than as it was read.
            Assert.Equal(1000, seen);
            Assert.Equal(1000, peer.CreditFor(streamId: 1));

            peer.Close(run);
        });
    }

    /// <summary>
    /// A peer driven by hand: frames in through an inline pipe, everything the server wrote back
    /// captured for inspection.
    /// </summary>
    private sealed class Peer : IDuplexPipe, IDisposable
    {
        private readonly Pipe _input = new(new PipeOptions(
            readerScheduler: PipeScheduler.Inline,
            writerScheduler: PipeScheduler.Inline,
            useSynchronizationContext: false));

        private readonly CaptureWriter _output = new();

        public Peer(Http2Options options) => Connection = new Http2Connection(this, options);

        public Http2Connection Connection { get; }

        public PipeReader Input => _input.Reader;
        public PipeWriter Output => _output;

        /// <summary>Total WINDOW_UPDATE credit the server has handed back for a stream (0 = connection).</summary>
        public int CreditFor(int streamId)
        {
            int total = 0;
            ReadOnlySpan<byte> wire = _output.Written;
            int at = 0;

            while (at + 9 <= wire.Length)
            {
                int length = (wire[at] << 16) | (wire[at + 1] << 8) | wire[at + 2];
                byte type = wire[at + 3];
                int stream = (int)(BinaryPrimitives.ReadUInt32BigEndian(wire[(at + 5)..]) & 0x7FFFFFFF);

                if (type == 0x8 && stream == streamId)   // WINDOW_UPDATE
                {
                    total += (int)(BinaryPrimitives.ReadUInt32BigEndian(wire[(at + 9)..]) & 0x7FFFFFFF);
                }
                at += 9 + length;
            }

            return total;
        }

        /// <summary>Preface, an empty SETTINGS, then one indexed-HPACK POST that opens a stream.</summary>
        public void OpenRequest(int streamId, bool endStream)
        {
            var bytes = new List<byte>("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray());
            bytes.AddRange(Header(0, 0x4, 0, 0));

            // 0x83 :method POST, 0x86 :scheme http, 0x84 :path / - static table only, so this
            // needs no HPACK encoder of its own.
            byte flags = (byte)(0x4 | (endStream ? 0x1 : 0));
            bytes.AddRange(Header(3, 0x1, flags, streamId));
            bytes.AddRange([0x83, 0x86, 0x84]);
            Feed(bytes.ToArray());
        }

        public void SendData(int streamId, int bytes, bool endStream)
        {
            var frame = new List<byte>(Header(bytes, 0x0, (byte)(endStream ? 0x1 : 0), streamId));
            frame.AddRange(Enumerable.Repeat((byte)'z', bytes));
            Feed(frame.ToArray());
        }

        /// <summary>Let the connection loop run whatever the last feed made possible.</summary>
        public void Pump() => Feed([]);

        public void Close(Task run)
        {
            _input.Writer.Complete();
            Assert.True(run.Wait(5_000), "connection wound down");
        }

        public void Dispose() => Connection.Dispose();

        private void Feed(byte[] bytes)
        {
            if (bytes.Length > 0)
            {
                _input.Writer.WriteAsync(bytes).GetAwaiter().GetResult();
            }
            else
            {
                _input.Writer.FlushAsync().GetAwaiter().GetResult();
            }
        }

        private static byte[] Header(int length, byte type, byte flags, int streamId) =>
        [
            (byte)(length >> 16), (byte)(length >> 8), (byte)length,
            type, flags,
            (byte)(streamId >> 24), (byte)(streamId >> 16), (byte)(streamId >> 8), (byte)streamId,
        ];
    }

    /// <summary>Keeps every byte the server wrote, so the test can walk the frames afterwards.</summary>
    private sealed class CaptureWriter : PipeWriter
    {
        private readonly List<byte> _written = [];
        private byte[] _scratch = new byte[4096];
        private int _pending;

        public ReadOnlySpan<byte> Written => System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_written);

        public override Memory<byte> GetMemory(int sizeHint = 0)
        {
            Grow(sizeHint);
            return _scratch.AsMemory(_pending);
        }

        public override Span<byte> GetSpan(int sizeHint = 0)
        {
            Grow(sizeHint);
            return _scratch.AsSpan(_pending);
        }

        public override void Advance(int bytes) => _pending += bytes;

        public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
        {
            _written.AddRange(_scratch.AsSpan(0, _pending));
            _pending = 0;
            return new ValueTask<FlushResult>(new FlushResult(isCanceled: false, isCompleted: false));
        }

        public override void Complete(Exception? exception = null)
        {
        }

        public override void CancelPendingFlush()
        {
        }

        private void Grow(int sizeHint)
        {
            if (_scratch.Length - _pending < Math.Max(sizeHint, 1))
            {
                Array.Resize(ref _scratch, Math.Max(_scratch.Length * 2, _pending + Math.Max(sizeHint, 4096)));
            }
        }
    }
}
