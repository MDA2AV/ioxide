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
    private const uint Cancel = 0x8;

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

        runner.Test("h2 streamed request: the request and the chunk a handler holds stay its own when the peer resets the stream under it", () =>
        {
            var holder = new Holder();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(holder.Handle);

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.SendRst(streamId: 1, Cancel);                     // an aborted upload
            holder.Release();

            Assert.True(holder.Ended, "the reset never reached the handler's body");
            Assert.True(holder.Verdict == Holder.Kept,
                $"the peer reset the stream under a running handler, and {holder.Verdict}");
            peer.Close(run);
        });

        runner.Test("h2 streamed request: the request and the chunk a handler holds stay its own when the server resets the stream under it", () =>
        {
            var holder = new Holder();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(holder.Handle);

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.SendWindowUpdate(streamId: 1, int.MaxValue);      // past 2^31-1: the stream is reset (RFC 9113 6.9.1)
            holder.Release();

            Assert.True(holder.Ended, "the reset never reached the handler's body");
            Assert.True(holder.Verdict == Holder.Kept,
                $"the server reset the stream under a running handler, and {holder.Verdict}");
            peer.Close(run);
        });

        runner.Test("h2 streamed request: the request and the chunk a handler holds stay its own when the connection goes away under it", () =>
        {
            var holder = new Holder();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(holder.Handle);

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            peer.Close(run);                                       // the client drops mid-upload
            holder.Release();

            Assert.True(holder.Ended, "the teardown never reached the handler's body");
            Assert.True(holder.Verdict == Holder.Kept,
                $"the connection went away under a running handler, and {holder.Verdict}");
        });

        runner.Test("h2 streamed request: a handler parked on its body when the peer resets the stream reads the end of it", () =>
        {
            var drainer = new Drainer();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(drainer.Handle);

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            Assert.Equal(400L, drainer.Read);                      // all of it: parked on the next read
            peer.SendRst(streamId: 1, Cancel);

            Assert.True(drainer.Ended, "the handler stayed parked on a body the peer had reset");
            peer.Close(run);
        });

        runner.Test("h2 streamed request: a handler parked on its body when the connection goes away reads the end of it", () =>
        {
            var drainer = new Drainer();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(drainer.Handle);

            peer.OpenRequest(streamId: 1, endStream: false);
            peer.SendData(streamId: 1, bytes: 400, endStream: false);
            Assert.Equal(400L, drainer.Read);                      // all of it: parked on the next read
            peer.Close(run);

            Assert.True(drainer.Ended, "the handler stayed parked on a body that stopped arriving");
        });

        runner.Test("h2 streamed request: a stream the peer resets in the same read as its headers reads an ended body, and the connection serves on", () =>
        {
            var drainer = new Drainer();

            using var peer = new Peer(new Http2Options { StreamRequestBodies = true });
            Task run = peer.Connection.RunBufferedAsync(drainer.Handle);

            // Reset before its dispatch: the request is still waiting for its handler when the reset lands.
            peer.OpenRequest(streamId: 1, endStream: false, resetWith: Cancel);

            Assert.True(!run.IsCompleted, "the connection went down over one stream the peer reset");
            Assert.True(drainer.Ended, "the handler never read the end of a body the peer had reset");
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

        /// <summary>
        /// Preface, an empty SETTINGS, then one indexed-HPACK POST that opens a stream - and with
        /// <paramref name="resetWith"/>, the peer's RST_STREAM for it in the same read.
        /// </summary>
        public void OpenRequest(int streamId, bool endStream, uint? resetWith = null)
        {
            var bytes = new List<byte>("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray());
            bytes.AddRange(Header(0, 0x4, 0, 0));

            // 0x83 :method POST, 0x86 :scheme http, 0x84 :path / - static table only, so this
            // needs no HPACK encoder of its own.
            byte flags = (byte)(0x4 | (endStream ? 0x1 : 0));
            bytes.AddRange(Header(3, 0x1, flags, streamId));
            bytes.AddRange([0x83, 0x86, 0x84]);
            if (resetWith is uint code)
            {
                bytes.AddRange(Word(0x3, streamId, code));
            }
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

        public void SendRst(int streamId, uint code) => Feed(Word(0x3, streamId, code));

        public void SendWindowUpdate(int streamId, int increment) => Feed(Word(0x8, streamId, (uint)increment));

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

        // A frame whose payload is one 32-bit word: RST_STREAM's error code, WINDOW_UPDATE's increment.
        private static byte[] Word(byte type, int streamId, uint word) =>
            [.. Header(4, type, 0, streamId), (byte)(word >> 24), (byte)(word >> 16), (byte)(word >> 8), (byte)word];
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

    /// <summary>
    /// A handler that takes its path and a chunk and holds both until the test releases it, then looks
    /// for their buffers in the pool. The request is its own until it returns and the chunk until its
    /// next read, whatever happened to the stream or the connection meanwhile.
    /// </summary>
    private sealed class Holder
    {
        public const string Kept = "its request was still its own and its chunk still its own";

        private readonly TaskCompletionSource _release = new();

        public string? Verdict { get; private set; }

        public bool Ended { get; private set; }

        public async ValueTask<Http2Response> Handle(Http2Request request)
        {
            ReadOnlyMemory<byte> path = request.Path;
            ReadOnlyMemory<byte> chunk = await request.BodyReader!.ReadAsync();
            await _release.Task;

            Verdict = $"its request was {Fate(path)} and its chunk {Fate(chunk)}";
            Ended = (await request.BodyReader.ReadAsync()).IsEmpty;
            return Http2Response.Text("done");
        }

        public void Release() => _release.SetResult();

        private static string Fate(ReadOnlyMemory<byte> memory)
        {
            if (!System.Runtime.InteropServices.MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment)
                || segment.Count == 0)
            {
                return "empty";   // nothing to look for, so no verdict either way
            }
            return InPool(segment.Array!) ? "back in the pool" : "still its own";
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
    }

    /// <summary>A handler that reads its body to the end, counting what it read.</summary>
    private sealed class Drainer
    {
        public long Read { get; private set; }

        public bool Ended { get; private set; }

        public async ValueTask<Http2Response> Handle(Http2Request request)
        {
            ReadOnlyMemory<byte> chunk;
            while (!(chunk = await request.BodyReader!.ReadAsync()).IsEmpty)
            {
                Read += chunk.Length;
            }

            Ended = true;
            return Http2Response.Text("done");
        }
    }
}
