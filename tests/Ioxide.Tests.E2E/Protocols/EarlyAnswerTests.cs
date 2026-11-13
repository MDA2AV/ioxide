using System.Buffers;
using System.Net;
using ioxide.http2;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// An answer that ends before its request does (#571) - a 413 to an upload, say - with a real client:
/// .NET's HttpClient over h2c and over h3, posting a body the handler never reads. The client has to
/// get the whole answer, and its upload has to stop. It used to go on to the end, every byte of it
/// credited and dropped: HTTP/2 now resets the stream with NO_ERROR after the answer's END_STREAM
/// (RFC 9113 8.1), and HTTP/3 stops reading the request stream with H3_NO_ERROR (RFC 9114 4.1).
/// The wire order of the HTTP/2 reset is pinned in Ioxide.Tests.Unit's Http2EarlyAnswerTests.
/// </summary>
internal static class EarlyAnswerTests
{
    // Far more than any window lets through before the client hears it should stop.
    private const long Upload = 64L << 20;

    // A control's upload, read whole by its handler.
    private const long ReadUpload = 8L << 20;

    public static void Register(Runner runner)
    {
        // Several DATA frames, inside the client's 64 KiB stream window: this client finishes its upload
        // before it reads an answer, and the reset can only follow the answer's END_STREAM, so an answer
        // it would have to read first could never end.
        byte[] h2Answer = Pattern(32 * 1024);

        // Many packets, which the STOP_SENDING rides out with.
        byte[] h3Answer = Pattern(256 * 1024);

        byte[] bufferedAnswer = Pattern(8 * 1024);

        runner.Test("h2 early answer: a streamed 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH2(connection => connection.RunAsync((_, _, writer) => AnswerAsync(writer, h2Answer)));
            using HttpClient client = H2Client();
            AssertAnsweredAndStopped(client, $"http://127.0.0.1:{port}/", h2Answer);
        });

        runner.Test("h2 early answer: a buffered 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH2(connection => connection.RunAsync((_, _) =>
                new ValueTask<Http2Response>(new Http2Response { Status = 413, Body = bufferedAnswer })));
            using HttpClient client = H2Client();
            AssertAnsweredAndStopped(client, $"http://127.0.0.1:{port}/", bufferedAnswer);
        });

        runner.Test("control: h2 an upload its handler reads to the end is sent whole and answered", () =>
        {
            int port = StartH2(connection => connection.RunAsync(async (_, body, writer) =>
            {
                long read = await ReadAllAsync(body.ReadAsync);
                writer.WriteHeaders(new Http2Response { Status = 200 });
                writer.Write(System.Text.Encoding.ASCII.GetBytes($"read {read}"));
                await writer.CompleteAsync();
            }));
            using HttpClient client = H2Client();
            AssertReadWhole(client, $"http://127.0.0.1:{port}/");
        });

        bool h3 = Http3ClientSupported();

        runner.Test("h3 early answer (nghttp3): a streamed 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH3(connection => connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Nghttp3Response { Status = 413 });
                writer.Write(h3Answer);
                await writer.CompleteAsync();
            }));
            using HttpClient client = H3Client();
            AssertAnsweredAndStopped(client, $"https://127.0.0.1:{port}/", h3Answer);
        }, skip: !h3);

        runner.Test("h3 early answer (nghttp3): a buffered 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH3(connection => connection.RunAsync((_, _) =>
                new ValueTask<Nghttp3Response>(new Nghttp3Response { Status = 413, Body = bufferedAnswer })));
            using HttpClient client = H3Client();
            AssertAnsweredAndStopped(client, $"https://127.0.0.1:{port}/", bufferedAnswer);
        }, skip: !h3);

        runner.Test("control: h3 (nghttp3) an upload its handler reads to the end is sent whole and answered", () =>
        {
            int port = StartH3(connection => connection.RunAsync(async (_, body, writer) =>
            {
                long read = await ReadAllAsync(body.ReadAsync);
                writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                writer.Write(System.Text.Encoding.ASCII.GetBytes($"read {read}"));
                await writer.CompleteAsync();
            }));
            using HttpClient client = H3Client();
            AssertReadWhole(client, $"https://127.0.0.1:{port}/");
        }, skip: !h3);
    }

    private static void AssertAnsweredAndStopped(HttpClient client, string url, byte[] answer)
    {
        var upload = new CountedUpload(Upload);
        Task<(HttpStatusCode Status, byte[] Body)> answered = PostAsync(client, url, upload);

        Assert.True(answered.Wait(100_000), "the answer never arrived");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, answered.Result.Status);
        AssertBody(answer, answered.Result.Body);

        long sent = upload.Ended.Result;
        Assert.True(sent < Upload / 2,
            $"the client uploaded {sent} of {Upload} bytes to a handler that read none of them: nothing asked it to stop");
    }

    private static void AssertReadWhole(HttpClient client, string url)
    {
        var upload = new CountedUpload(ReadUpload);
        Task<(HttpStatusCode Status, byte[] Body)> answered = PostAsync(client, url, upload);

        Assert.True(answered.Wait(100_000), "the answer never arrived");
        Assert.Equal(HttpStatusCode.OK, answered.Result.Status);
        Assert.Equal($"read {ReadUpload}", System.Text.Encoding.ASCII.GetString(answered.Result.Body));
        Assert.Equal(ReadUpload, upload.Ended.Result);
    }

    // The answer, once the upload has ended as well: at its last byte, or where the client gave up on the rest.
    private static async Task<(HttpStatusCode Status, byte[] Body)> PostAsync(HttpClient client, string url, CountedUpload upload)
    {
        try
        {
            using HttpResponseMessage response = await client.PostAsync(url, upload);
            byte[] body = await response.Content.ReadAsByteArrayAsync();

            // Held open until then: disposing a response whose request is still uploading has the
            // client cancel the upload itself, which is not the server asking it to stop.
            if (await Task.WhenAny(upload.Ended, Task.Delay(30_000)) != upload.Ended)
            {
                throw new Exception($"the upload neither finished nor stopped, at {upload.Sent} bytes");
            }
            return (response.StatusCode, body);
        }
        catch (HttpRequestException exception)
        {
            // The default message names neither the protocol error nor the side that raised it.
            Exception cause = exception.GetBaseException();
            throw new Exception($"{cause.GetType().Name}: {cause.Message}", exception);
        }
    }

    private static ValueTask AnswerAsync(Http2ResponseWriter writer, byte[] answer)
    {
        writer.WriteHeaders(new Http2Response { Status = 413 });
        writer.Write(answer);
        return writer.CompleteAsync();
    }

    private static async ValueTask<long> ReadAllAsync(Func<ValueTask<ReadOnlyMemory<byte>>> read)
    {
        long total = 0;
        while (true)
        {
            ReadOnlyMemory<byte> chunk = await read();
            if (chunk.IsEmpty)
            {
                return total;
            }
            total += chunk.Length;
        }
    }

    private static int StartH2(Func<Http2Connection, Task> serve)
        => TestServer.Start(async (_, conn) =>
        {
            try
            {
                await serve(new Http2Connection(conn));
            }
            finally
            {
                conn.DecRef();
            }
        });

    private static int StartH3(Func<Nghttp3Connection, Task> serve)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
        (_, int udpPort) = TestServer.StartDatagram(onDatagram: null, quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => serve(new Nghttp3Connection(conn)));
        return udpPort;
    }

    // Cleartext HTTP/2 with prior knowledge, as Http2BodyTests uses.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(60),
    };

    // HTTP/3 straight away, against the self-signed test certificate.
    private static HttpClient H3Client() => new(new SocketsHttpHandler
    {
        SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true },
    })
    {
        DefaultRequestVersion = HttpVersion.Version30,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(60),
    };

    // .NET speaks HTTP/3 through msquic, which a machine may not have.
    private static bool Http3ClientSupported() => OperatingSystem.IsLinux() && System.Net.Quic.QuicConnection.IsSupported;

    private static void AssertBody(byte[] expected, byte[] actual)
    {
        Assert.True(actual.Length == expected.Length, $"the answer arrived {actual.Length} bytes long, of {expected.Length}");
        Assert.True(actual.AsSpan().SequenceEqual(expected), "the answer arrived with different content");
    }

    // Position-dependent, so an answer reassembled out of order fails on content and not only length.
    private static byte[] Pattern(int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)((i * 31) ^ (i >> 8));
        }
        return bytes;
    }

    /// <summary>
    /// An upload read from a source as the client sends it, as a file is, which says how much the
    /// client took and when it stopped taking: at the end, or where it gave up on the rest. A
    /// StreamContent, so not duplex - over HTTP/3 the client then finishes the upload before it hands
    /// over the answer, so an upload stopped in a way the client takes for a failure costs the answer.
    /// </summary>
    private sealed class CountedUpload : StreamContent
    {
        private readonly Source _source;
        private readonly TaskCompletionSource<long> _ended = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CountedUpload(long length) : this(new Source(length))
        {
        }

        private CountedUpload(Source source) : base(source, 64 * 1024)
        {
            _source = source;
            Headers.ContentLength = source.Size;
        }

        public long Sent => _source.Taken;

        public Task<long> Ended => _ended.Task;

        // The overload a client sends through; StreamContent routes a subclass on to the one without a token.
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            try
            {
                await base.SerializeToStreamAsync(stream, context, cancellationToken);
            }
            finally
            {
                _ended.TrySetResult(Sent);
            }
        }
    }

    // Zeros, as many as the upload is long, counted as they are taken.
    private sealed class Source(long size) : Stream
    {
        private long _taken;

        public long Size => size;

        public long Taken => Interlocked.Read(ref _taken);

        public override int Read(Span<byte> buffer)
        {
            int count = (int)Math.Min(buffer.Length, size - Taken);
            buffer[..count].Clear();
            Interlocked.Add(ref _taken, count);
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => new(Read(buffer.Span));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.FromResult(Read(buffer.AsSpan(offset, count)));

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
