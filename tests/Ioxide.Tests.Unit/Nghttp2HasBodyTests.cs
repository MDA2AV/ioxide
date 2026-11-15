using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// Whether a request says a body follows its HEADERS, told from the frames: none of these requests carries a
/// content-length, which HTTP/2 does not require. HEADERS that end the stream and HEADERS followed by one empty
/// DATA frame that does make the same calls into the connection, but for the END_STREAM the shim hands up with
/// the end of the headers.
/// </summary>
internal static class Nghttp2HasBodyTests
{
    private const byte Data = 0x0, Headers = 0x1, Continuation = 0x9;
    private const byte EndStream = 0x1, EndHeaders = 0x4;

    // :method POST or GET, :scheme http, :path /, and an :authority, which nghttp2 requires.
    private static readonly byte[] Post = [0x83, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];
    private static readonly byte[] Get = [0x82, 0x86, 0x84, 0x01, 9, .. "a.example"u8.ToArray()];

    private static readonly Nghttp2Response Ok = Nghttp2Response.Text("ok");

    public static void Register(Runner runner)
    {
        // A handler that takes a body reader runs at the HEADERS, so this is all it knows before it reads.
        runner.Test("nghttp2 streamed request: a request whose HEADERS ended the stream says it has no body", () =>
        {
            FirstLook look = LookAtDispatch(client => client.Feed(Open(1, endStream: true)));

            Assert.True(look.HasBody == false && look.Read == 0, $"END_STREAM rode the HEADERS, and {look}");
        });

        runner.Test("nghttp2 streamed request: an upload without content-length says it has a body before any of it arrives", () =>
        {
            FirstLook look = LookAtDispatch(client =>
            {
                client.Feed(Open(1, endStream: false));   // dispatched here, with no DATA yet
                client.Drain();
                client.Feed(Body(1, 400, endStream: true));
            });

            Assert.True(look.Parked, $"the DATA came after the handler started, so a read had to wait, and {look}");
            Assert.True(look.HasBody == true && look.Read == 400 && !look.ContentLength,
                $"an upload of unknown length was on its way, and {look}");
        });

        runner.Test("nghttp2 streamed request: a request whose body ended in the same read as its HEADERS still says it has one", () =>
        {
            // The body has ended before its handler runs, which a flag read off the reader's end would take for none.
            FirstLook look = LookAtDispatch(client => client.Feed([.. Open(1, endStream: false), .. Body(1, 400, endStream: true)]));

            Assert.True(!look.Parked, $"the DATA came in the same read as the HEADERS, so no read had to wait, and {look}");
            Assert.True(look.HasBody == true && look.Read == 400 && !look.ContentLength,
                $"a body arrived with its HEADERS, and {look}");
        });

        runner.Test("nghttp2 streamed request: a request whose body is one empty DATA frame still says it has one, and reads empty", () =>
        {
            // nghttp2 hands up no bytes for an empty DATA frame, so only END_STREAM's place tells this from HEADERS that ended the stream.
            FirstLook look = LookAtDispatch(client => client.Feed([.. Open(1, endStream: false), .. Body(1, 0, endStream: true)]));

            Assert.True(!look.Parked, $"the empty DATA came in the same read as the HEADERS, so no read had to wait, and {look}");
            Assert.True(look.HasBody == true && look.Read == 0, $"the HEADERS left the stream open for a body, and {look}");
        });

        runner.Test("nghttp2 request: an assembled upload without content-length says it has a body", () =>
        {
            List<string> seen = Serve(streamed: false,
                Open(1, endStream: false), Body(1, 400, endStream: false), Body(1, 600, endStream: true));

            Assert.True(seen.SequenceEqual(["1 a body, 1000 B"]), $"the handler was handed: {string.Join(", ", seen)}");
        });

        runner.Test("nghttp2 request: an assembled request whose HEADERS ended the stream says it has none, and one whose body is an empty DATA frame says it has one", () =>
        {
            List<string> seen = Serve(streamed: false,
                Open(1, endStream: true), [.. Open(3, endStream: false), .. Body(3, 0, endStream: true)]);

            Assert.True(seen.SequenceEqual(["1 no body, 0 B", "3 a body, 0 B"]), $"the handler was handed: {string.Join(", ", seen)}");
        });

        foreach (bool streamed in new[] { false, true })
        {
            bool s = streamed;
            string mode = s ? "streamed request" : "request";

            // One read each, so a streamed request is handed over after its trailers have been decoded too.
            runner.Test($"nghttp2 {mode}: a request with trailers after its body says it has one", () =>
            {
                List<string> seen = Serve(s, [.. Open(1, endStream: false), .. Body(1, 400, endStream: false), .. Trailers(1)]);

                Assert.True(seen.SequenceEqual(["1 a body, 400 B"]), $"the trailers' END_STREAM is no answer, and the handler was handed: {string.Join(", ", seen)}");
            });

            runner.Test($"nghttp2 {mode}: a request with trailers and no DATA says it has a body", () =>
            {
                List<string> seen = Serve(s, [.. Open(1, endStream: false), .. Trailers(1)]);

                Assert.True(seen.SequenceEqual(["1 a body, 0 B"]), $"the trailers' END_STREAM is no answer, and the handler was handed: {string.Join(", ", seen)}");
            });

            runner.Test($"nghttp2 {mode}: HEADERS that end the stream with their block finished by a CONTINUATION say there is no body", () =>
            {
                List<string> seen = Serve(s, OpenThroughContinuation(1));

                Assert.True(seen.SequenceEqual(["1 no body, 0 B"]), $"END_STREAM rode the HEADERS, and the handler was handed: {string.Join(", ", seen)}");
            });
        }

        runner.Test("nghttp2 request: a GET that reuses an upload's request says it has no body", () =>
        {
            using var client = new StrictClient();
            var connection = new Nghttp2Connection(client);

            var seen = new List<(Nghttp2Request Request, string Said)>();
            Task run = connection.RunAsync(request =>
            {
                seen.Add((request, Said(request.StreamId, request.HasBody, request.Body.Length)));
                return Ok;
            });

            client.SendRequests();                   // preface and SETTINGS
            client.Drain();
            client.Feed([.. Open(1, endStream: false), .. Body(1, 5, endStream: true)]);
            client.Drain();
            client.Feed(Frame(Headers, EndHeaders | EndStream, 3, Get));
            client.Drain();
            client.Close(run);
            connection.Dispose();

            Assert.True(seen.Count == 2 && ReferenceEquals(seen[0].Request, seen[1].Request), "control: the GET reuses the upload's request");
            Assert.True(seen.Select(entry => entry.Said).SequenceEqual(["1 a body, 5 B", "3 no body, 0 B"]),
                $"the handler was handed: {string.Join(", ", seen.Select(entry => entry.Said))}");
        });
    }

    /// <summary>
    /// What a handler that takes a body reader is told about its body when it starts, before its first read,
    /// then what reading it to the end found.
    /// </summary>
    private sealed class FirstLook
    {
        public bool? HasBody;         // null: the handler never ran
        public bool ContentLength;
        public bool Parked;           // a read had to wait: the handler ran before its body was in
        public long Read;

        public override string ToString()
            => HasBody is null
                ? "the handler never ran"
                : $"the request said HasBody {HasBody}{(ContentLength ? " with a content-length" : "")}, "
                  + $"then read {Read} bytes{(Parked ? ", waiting for some" : " without waiting")}";
    }

    private static FirstLook LookAtDispatch(Action<StrictClient> send)
    {
        var look = new FirstLook();

        using var client = new StrictClient();
        var connection = new Nghttp2Connection(client);
        Task run = connection.RunAsync(async (request, body) =>
        {
            look.HasBody = request.HasBody;
            look.ContentLength = request.TryGetHeader("content-length"u8, out _);

            ReadOnlyMemory<byte> chunk;
            do
            {
                ValueTask<ReadOnlyMemory<byte>> read = body.ReadAsync();
                look.Parked |= !read.IsCompleted;
                chunk = await read;
                look.Read += chunk.Length;
            }
            while (!chunk.IsEmpty);

            return Ok;
        });

        client.SendRequests();                       // preface and SETTINGS
        client.Drain();
        send(client);
        client.Drain();
        client.Close(run);
        connection.Dispose();
        return look;
    }

    /// <summary>Feeds each read in turn and returns what every request said of its body, in the order they were served.</summary>
    private static List<string> Serve(bool streamed, params byte[][] reads)
    {
        var seen = new List<string>();

        using var client = new StrictClient();
        var connection = new Nghttp2Connection(client);
        Task run = streamed
            ? connection.RunAsync(async (request, body) =>
            {
                bool hasBody = request.HasBody;      // before the first read
                long read = 0;
                ReadOnlyMemory<byte> chunk;
                while (!(chunk = await body.ReadAsync()).IsEmpty)
                {
                    read += chunk.Length;
                }
                seen.Add(Said(request.StreamId, hasBody, read));
                return Ok;
            })
            : connection.RunAsync(request =>
            {
                seen.Add(Said(request.StreamId, request.HasBody, request.Body.Length));
                return Ok;
            });

        client.SendRequests();                       // preface and SETTINGS
        client.Drain();
        foreach (byte[] read in reads)
        {
            client.Feed(read);
            client.Drain();
        }
        client.Close(run);
        connection.Dispose();
        return seen;
    }

    private static string Said(int streamId, bool hasBody, long bytes) => $"{streamId} {(hasBody ? "a body" : "no body")}, {bytes} B";

    private static byte[] Open(int streamId, bool endStream)
        => Frame(Headers, endStream ? (byte)(EndHeaders | EndStream) : EndHeaders, streamId, Post);

    private static byte[] Body(int streamId, int bytes, bool endStream)
        => Frame(Data, endStream ? EndStream : (byte)0, streamId, Enumerable.Repeat((byte)'z', bytes).ToArray());

    private static byte[] Trailers(int streamId)
        => Frame(Headers, EndHeaders | EndStream, streamId, Http2TrailerTests.Field("x-checksum", "abc"));

    // END_STREAM on the HEADERS, END_HEADERS on the CONTINUATION that finishes its block, which carries no other flag (RFC 9113 6.10).
    private static byte[] OpenThroughContinuation(int streamId)
        => [.. Frame(Headers, EndStream, streamId, Post[..3]), .. Frame(Continuation, EndHeaders, streamId, Post[3..])];

    private static byte[] Frame(byte type, byte flags, int streamId, byte[] payload)
        => Http2FlowControlTests.FrameBytes(type, flags, streamId, payload);
}
