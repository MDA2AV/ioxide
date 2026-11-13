using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// A request's trailer section - a HEADERS with END_STREAM after its DATA - which a client may send
/// at any point, including after the server has answered (RFC 9113 8.1).
///
/// A streamed request is dispatched at its first HEADERS, so its trailers arrive while the handler
/// runs or after it has retired. Either way they have to be DECODED - the HPACK table is connection
/// state - and then dropped: never served as a request of their own, and never written into the
/// arena the running handler's request points into.
/// </summary>
internal static class Http2TrailerTests
{
    private const byte RstStream = 0x3, GoAway = 0x7;

    public static void Register(Runner runner)
    {
        runner.Test("h2 streamed request: trailers after the handler has answered never reach a handler as a request", () =>
        {
            var served = new List<string>();

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync((request, _) =>
            {
                served.Add($"{request.StreamId} '{Ascii(request.Path)}'");
                return ValueTask.FromResult(Http2Response.Text("done"));   // without reading, so stream 1 retires before its body ends
            });

            peer.Open();
            peer.Headers(1, Request("/unread"), endStream: false);
            peer.Data(1, 400, endStream: false);
            peer.Headers(1, Field("x-checksum", "abc"), endStream: true);
            peer.Headers(3, Request("/next"), endStream: true);

            // RFC 9113 5.1.1: stream 1 was opened once, and a HEADERS on it later opens nothing.
            Assert.True(served.SequenceEqual(["1 '/unread'", "3 '/next'"]),
                $"expected stream 1 once, then stream 3; the handler was handed: {string.Join(", ", served)}");
            // Answered unread, so stream 1 is reset with NO_ERROR to stop its upload (#571); the
            // trailers are legal here, and nothing refuses or resets them.
            Assert.Equal("1 NO_ERROR", Resets(peer));

            peer.Close(run);
        });

        runner.Test("h2 streamed request: trailers that arrive while the handler runs leave its request where it is", () =>
        {
            var trailersIn = new TaskCompletionSource();
            string path = "";
            string verdict = "never checked: the handler did not resume";
            long body = -1;

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(async (request, reader) =>
            {
                ReadOnlyMemory<byte> held = request.Path;   // valid for the whole handler call
                path = Ascii(held);
                await trailersIn.Task;

                verdict = !MemoryMarshal.TryGetArray(held, out ArraySegment<byte> segment) ? "not an array"
                    : InPool(segment.Array!) ? "back in the pool" : "still the request's";
                body = await ReadToEnd(reader);
                return Http2Response.Text("done");
            });

            peer.Open();
            peer.Headers(1, Request("/held"), endStream: false);
            peer.Data(1, 400, endStream: false);

            // More than the request's 4096-byte arena has room for: written into the request, it
            // grows the arena and returns the old one - the one request.Path points into - to the pool.
            peer.Headers(1, Field("x-digest", new string('d', 5000)), endStream: true);
            trailersIn.SetResult();

            Assert.Equal("/held", path);
            Assert.True(verdict == "still the request's",
                $"trailers arrived while the handler ran, and the array behind its request.Path was {verdict}");
            Assert.Equal(400L, body);         // the trailers' END_STREAM still ends the body
            Assert.Equal("", Resets(peer));

            peer.Close(run);
        });

        runner.Test("h2 streamed request: control: dropped trailers are still decoded, so the HPACK table stays in step", () =>
        {
            var gate = new TaskCompletionSource();
            string? seen = null;

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(async (request, _) =>
            {
                string target = Ascii(request.Path);
                if (target == "/held")
                {
                    await gate.Task;
                }
                else if (target == "/after")
                {
                    seen = Fields(request);
                }
                return Http2Response.Text("done");
            });

            peer.Open();
            peer.Headers(1, Request("/answered"), endStream: false);   // answered at once, so retired
            peer.Headers(3, Request("/held"), endStream: false);       // still running

            // One trailer section down each path that drops them, each INSERTING into the dynamic
            // table (RFC 7541 6.2.1): a block that was skipped instead would never have inserted.
            peer.Headers(3, Field("x-held", "3", index: true), endStream: true);
            peer.Headers(1, Field("x-answered", "1", index: true), endStream: true);

            // Newest first: 62 is x-answered, 63 is x-held. With either block skipped one of them
            // does not exist, and the connection ends with COMPRESSION_ERROR instead.
            peer.Headers(5, [.. Request("/after"), 0x80 | 62, 0x80 | 63], endStream: true);
            gate.SetResult();

            Assert.Equal("x-answered: 1, x-held: 3", seen);
            peer.Close(run);
        });

        runner.Test("h2 request: control: a buffered request's trailers still merge into it, and it is served once with its body", () =>
        {
            var served = new List<string>();

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(request =>     // no body reader: the body comes whole
            {
                request.TryGetHeader("x-checksum"u8, out ReadOnlyMemory<byte> checksum);
                served.Add($"{request.StreamId} '{Ascii(request.Path)}' {request.Body.Length} x-checksum '{Ascii(checksum)}'");
                return Http2Response.Text("done");
            });

            peer.Open();
            peer.Headers(1, Request("/upload"), endStream: false);
            peer.Data(1, 400, endStream: false);
            peer.Headers(1, Field("x-checksum", "abc"), endStream: true);
            peer.Headers(3, Request("/next"), endStream: true);

            Assert.True(served.SequenceEqual(["1 '/upload' 400 x-checksum 'abc'", "3 '/next' 0 x-checksum ''"]),
                $"the handler was handed: {string.Join(", ", served)}");
            Assert.Equal("", Resets(peer));

            peer.Close(run);
        });

        runner.Test("h2 request: a buffered request's trailers split over HEADERS and CONTINUATION merge into it, and the connection serves on", () =>
        {
            var served = new List<string>();

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(request =>
            {
                request.TryGetHeader("x-checksum"u8, out ReadOnlyMemory<byte> checksum);
                request.TryGetHeader("x-digest"u8, out ReadOnlyMemory<byte> digest);
                served.Add($"{request.StreamId} '{Ascii(request.Path)}' {request.Body.Length} x-checksum '{Ascii(checksum)}' x-digest '{Ascii(digest)}'");
                return Http2Response.Text("done");
            });

            peer.Open();
            peer.Headers(1, Request("/upload"), endStream: false);
            peer.Data(1, 400, endStream: false);
            peer.HeadersOpen(1, Field("x-checksum", "abc"), endStream: true);   // END_STREAM, with the block still open
            peer.Continuation(1, Field("x-digest", "def"));                    // END_HEADERS
            peer.Headers(3, Request("/next"), endStream: true);

            Assert.True(served.SequenceEqual(["1 '/upload' 400 x-checksum 'abc' x-digest 'def'", "3 '/next' 0 x-checksum '' x-digest ''"]),
                $"the handler was handed: {string.Join(", ", served)}");
            Assert.Equal("", GoAways(peer));

            peer.Close(run);
        });

        runner.Test("h2 request: a stream refused past MaxConcurrentStreams still gets REFUSED_STREAM, and its id opens nothing later", () =>
        {
            var served = new List<string>();

            using var peer = new Peer(new Http2Options { MaxConcurrentStreams = 1 });
            Task run = peer.Connection.RunAsync(request =>
            {
                served.Add($"{request.StreamId} '{Ascii(request.Path)}'");
                return Http2Response.Text("done");
            });

            peer.Open();
            peer.Headers(1, Request("/open"), endStream: false);     // holds the one slot until its body ends
            peer.Headers(3, Request("/refused"), endStream: true);   // past the limit
            peer.Data(1, 0, endStream: true);                         // stream 1 is served and frees the slot
            peer.Headers(3, Request("/again"), endStream: true);     // a refused request is retried on a NEW id
            peer.Headers(5, Request("/new"), endStream: true);

            Assert.Equal("3 REFUSED_STREAM", Resets(peer));
            Assert.True(served.SequenceEqual(["1 '/open'", "5 '/new'"]),
                $"expected streams 1 and 5; the handler was handed: {string.Join(", ", served)}");

            peer.Close(run);
        });

        runner.Test("h2 streamed request: a CONTINUATION that continues no header block is a PROTOCOL_ERROR, on a stream being served too", () =>
        {
            var gate = new TaskCompletionSource();

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(async (_, _) =>
            {
                await gate.Task;
                return Http2Response.Text("done");
            });

            peer.Open();
            peer.Headers(1, Request("/held"), endStream: false);

            // Its block ended with that HEADERS (RFC 9113 6.10). Taken as a continuation, this one is
            // decoded into the request its handler is reading.
            peer.Continuation(1, Field("x-digest", new string('d', 5000)));

            Assert.Equal("PROTOCOL_ERROR", GoAways(peer));
            gate.SetResult();
            peer.Close(run);
        });

        // RFC 9113 8.1. Its fields landed in the arena the body was being appended to, and the body's range ran across them.
        runner.Test("h2 buffered request: HEADERS without END_STREAM after the opening block resets the stream, and its body never reaches a handler", () =>
        {
            var served = new List<string>();

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(request =>
            {
                served.Add($"{Ascii(request.Path)} {Fields(request)}");
                return Http2Response.Text("ok");
            });

            peer.Open();
            peer.Headers(1, Request("/up"), endStream: false);
            peer.Data(1, 400, endStream: false);
            peer.Headers(1, Field("x-a", "abc", index: true), endStream: false);
            peer.Data(1, 400, endStream: true);
            peer.Headers(3, [.. Request("/next"), 0xBE], endStream: true);   // the block was decoded, so x-a is at index 62
            peer.Close(run);

            Assert.Equal("1 PROTOCOL_ERROR", Resets(peer));
            Assert.Equal("", GoAways(peer));
            Assert.True(served.SequenceEqual(["/next x-a: abc"]), $"the handler was handed: {string.Join(", ", served)}");
        });

        // The block's CONTINUATION is still owed after the reset, and has to reach the decoder, not end the connection.
        runner.Test("h2 buffered request: HEADERS without END_STREAM split over CONTINUATION still keeps HPACK in step", () =>
        {
            var served = new List<string>();

            using var peer = new Peer(new Http2Options());
            Task run = peer.Connection.RunAsync(request =>
            {
                served.Add($"{Ascii(request.Path)} {Fields(request)}");
                return Http2Response.Text("ok");
            });

            peer.Open();
            peer.Headers(1, Request("/up"), endStream: false);
            byte[] block = Field("x-a", "abc", index: true);
            peer.HeadersOpen(1, block[..3], endStream: false);
            peer.Continuation(1, block[3..]);
            peer.Headers(3, [.. Request("/next"), 0xBE], endStream: true);
            peer.Close(run);

            Assert.Equal("1 PROTOCOL_ERROR", Resets(peer));
            Assert.Equal("", GoAways(peer));
            Assert.True(served.SequenceEqual(["/next x-a: abc"]), $"the handler was handed: {string.Join(", ", served)}");
        });
    }

    // :method POST and :scheme http from the static table, and :path as a literal on its static
    // name (index 4, without indexing) so each request can be told apart.
    private static byte[] Request(string path)
    {
        var block = new List<byte> { 0x83, 0x86 };
        Integer(block, 4, 4, 0x00);
        Literal(block, path);
        return [.. block];
    }

    // A literal with a new name: without indexing, or with incremental indexing, which inserts it
    // into the dynamic table at index 62.
    internal static byte[] Field(string name, string value, bool index = false)
    {
        var block = new List<byte> { (byte)(index ? 0x40 : 0x00) };
        Literal(block, name);
        Literal(block, value);
        return [.. block];
    }

    private static void Literal(List<byte> block, string text)
    {
        Integer(block, text.Length, 7, 0x00);   // H = 0: raw, not Huffman
        block.AddRange(Encoding.ASCII.GetBytes(text));
    }

    // RFC 7541 5.1.
    private static void Integer(List<byte> block, int value, int prefixBits, byte flags)
    {
        int max = (1 << prefixBits) - 1;
        if (value < max)
        {
            block.Add((byte)(flags | value));
            return;
        }

        block.Add((byte)(flags | max));
        value -= max;
        while (value >= 128)
        {
            block.Add((byte)((value % 128) + 128));
            value /= 128;
        }
        block.Add((byte)value);
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);

    private static string Fields(Http2Request request)
    {
        var fields = new List<string>();
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
        {
            fields.Add($"{Ascii(field.Key)}: {Ascii(field.Value)}");
        }
        return string.Join(", ", fields);
    }

    private static async ValueTask<long> ReadToEnd(Http2BodyReader reader)
    {
        long total = 0;
        while (true)
        {
            ReadOnlyMemory<byte> chunk = await reader.ReadAsync();
            if (chunk.IsEmpty)
            {
                return total;
            }
            total += chunk.Length;
        }
    }

    /// <summary>Every RST_STREAM the server wrote, as "stream CODE".</summary>
    private static string Resets(Peer peer) => string.Join(", ", peer.Written()
        .Where(frame => frame.Type == RstStream)
        .Select(frame => $"{frame.StreamId} {ErrorName(frame.Payload.AsSpan(0, 4))}"));

    /// <summary>Every GOAWAY the server wrote, by error code.</summary>
    private static string GoAways(Peer peer) => string.Join(", ", peer.Written()
        .Where(frame => frame.Type == GoAway)
        .Select(frame => ErrorName(frame.Payload.AsSpan(4, 4))));

    private static string ErrorName(ReadOnlySpan<byte> code) => BinaryPrimitives.ReadUInt32BigEndian(code) switch
    {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x7 => "REFUSED_STREAM",
        0x9 => "COMPRESSION_ERROR",
        uint other => $"0x{other:x}",
    };

    // Whether this very array is back in the pool. Everything rented on the way goes back; the array
    // itself, should it turn up, stays out - whoever returned it may still be using it.
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

    /// <summary>
    /// A client driven by hand: frames in through an inline pipe, so the whole connection loop runs
    /// on the test thread, and everything the server wrote kept for inspection.
    /// </summary>
    private sealed class Peer : IDuplexPipe, IDisposable
    {
        private static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

        private readonly Pipe _input = new(new PipeOptions(
            readerScheduler: PipeScheduler.Inline,
            writerScheduler: PipeScheduler.Inline,
            useSynchronizationContext: false));

        private readonly CaptureWriter _output = new();

        public Peer(Http2Options options) => Connection = new Http2Connection(this, options);

        public Http2Connection Connection { get; }

        public PipeReader Input => _input.Reader;
        public PipeWriter Output => _output;

        public List<Frame> Written() => Frame.Walk(_output.Written);

        /// <summary>The preface and an empty SETTINGS.</summary>
        public void Open() => Feed([.. Preface, .. FrameBytes(0x4, 0, 0, [])]);

        /// <summary>A whole header block in one HEADERS frame (END_HEADERS).</summary>
        public void Headers(int streamId, byte[] block, bool endStream)
            => Feed(FrameBytes(0x1, (byte)(0x4 | (endStream ? 0x1 : 0)), streamId, block));

        public void Continuation(int streamId, byte[] block) => Feed(FrameBytes(0x9, 0x4, streamId, block));

        /// <summary>A HEADERS frame without END_HEADERS: a CONTINUATION ends its block.</summary>
        public void HeadersOpen(int streamId, byte[] block, bool endStream)
            => Feed(FrameBytes(0x1, (byte)(endStream ? 0x1 : 0), streamId, block));

        public void Data(int streamId, int bytes, bool endStream)
            => Feed(FrameBytes(0x0, (byte)(endStream ? 0x1 : 0), streamId, Enumerable.Repeat((byte)'z', bytes).ToArray()));

        public void Close(Task run)
        {
            _input.Writer.Complete();
            Assert.True(run.Wait(5_000), "connection wound down");
        }

        public void Dispose() => Connection.Dispose();

        private void Feed(byte[] bytes) => _input.Writer.WriteAsync(bytes).GetAwaiter().GetResult();

        private static byte[] FrameBytes(byte type, byte flags, int streamId, byte[] payload) =>
        [
            (byte)(payload.Length >> 16), (byte)(payload.Length >> 8), (byte)payload.Length,
            type, flags,
            (byte)(streamId >> 24), (byte)(streamId >> 16), (byte)(streamId >> 8), (byte)streamId,
            .. payload,
        ];
    }

    /// <summary>Keeps every byte the server wrote; each flush completes at once.</summary>
    private sealed class CaptureWriter : PipeWriter
    {
        private readonly List<byte> _written = [];
        private byte[] _scratch = new byte[4096];
        private int _pending;

        public ReadOnlySpan<byte> Written => CollectionsMarshal.AsSpan(_written);

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
