using System.Buffers;
using System.Net;
using ioxide;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>An ioxide.nghttp2 answer that ends before its request does, with .NET's HttpClient: the answer arrives whole, and the upload stops (RFC 9113 8.1).</summary>
internal static class Nghttp2EarlyAnswerTests
{
    // Far more than any window lets through before the client hears it should stop.
    private const long Upload = 64L << 20;

    // A control's upload, read whole by its handler.
    private const long ReadUpload = 8L << 20;

    // Measured at 64 KiB, the connection window; a reset stream takes no more credit, so its window bounds what follows.
    private const long Stopped = 4L << 20;

    public static void Register(Runner runner)
    {
        // Inside the client's 64 KiB stream window: this client credits an answer only once its upload ends, and the reset follows the END_STREAM.
        byte[] answer = Pattern(32 * 1024);

        runner.Test("h2 early answer (nghttp2): a streamed 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = Start(connection => connection.RunAsync((_, _, writer) =>
            {
                writer.WriteHeaders(new Nghttp2Response { Status = 413 });
                writer.Write(answer);
                return ValueTask.CompletedTask;
            }));
            AssertAnsweredAndStopped(port, answer);
        });

        runner.Test("h2 early answer (nghttp2): a buffered 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = Start(connection => connection.RunAsync((_, _) =>
                new ValueTask<Nghttp2Response>(new Nghttp2Response { Status = 413, Body = answer })));
            AssertAnsweredAndStopped(port, answer);
        });

        runner.Test("h2 early answer (nghttp2): a bodyless 413 to an upload arrives, and the client stops uploading", () =>
        {
            int port = Start(connection => connection.RunAsync((_, _) =>
                new ValueTask<Nghttp2Response>(new Nghttp2Response { Status = 413 })));
            AssertAnsweredAndStopped(port, []);
        });

        runner.Test("h2 early answer (nghttp2): control: an upload its handler reads to the end is sent whole and answered", () =>
        {
            int port = Start(connection => connection.RunAsync(async (_, body, writer) =>
            {
                long read = 0;
                ReadOnlyMemory<byte> chunk;
                while (!(chunk = await body.ReadAsync()).IsEmpty)
                {
                    read += chunk.Length;
                }
                writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                writer.Write(System.Text.Encoding.ASCII.GetBytes($"read {read}"));
            }));

            using HttpClient client = H2Client();
            var upload = new CountedUpload(ReadUpload);
            Task<(HttpStatusCode Status, byte[] Body)> answered = PostAsync(client, $"http://127.0.0.1:{port}/", upload);

            Assert.True(answered.Wait(100_000), "the answer never arrived");
            Assert.Equal(HttpStatusCode.OK, answered.Result.Status);
            Assert.Equal($"read {ReadUpload}", System.Text.Encoding.ASCII.GetString(answered.Result.Body));
            Assert.Equal(ReadUpload, upload.Ended.Result);
        });
    }

    private static void AssertAnsweredAndStopped(int port, byte[] answer)
    {
        using HttpClient client = H2Client();
        var upload = new CountedUpload(Upload);
        Task<(HttpStatusCode Status, byte[] Body)> answered = PostAsync(client, $"http://127.0.0.1:{port}/", upload);

        Assert.True(answered.Wait(100_000), "the answer never arrived");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, answered.Result.Status);
        Assert.True(answered.Result.Body.AsSpan().SequenceEqual(answer),
            $"the answer arrived {answered.Result.Body.Length} bytes long, of {answer.Length}, or with different content");

        long sent = upload.Ended.Result;
        Assert.True(sent < Stopped,
            $"the client uploaded {sent} of {Upload} bytes to a handler that read none of them: nothing asked it to stop");
    }

    // The answer, once the upload has ended as well: at its last byte, or where the client gave up on the rest.
    private static async Task<(HttpStatusCode Status, byte[] Body)> PostAsync(HttpClient client, string url, CountedUpload upload)
    {
        try
        {
            using HttpResponseMessage response = await client.PostAsync(url, upload);
            byte[] body = await response.Content.ReadAsByteArrayAsync();

            // Held open until then: disposing it would have the client cancel the upload itself.
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

    private static int Start(Func<Nghttp2Connection, Task> serve)
        => TestServer.Start(async (_, conn) =>
        {
            try
            {
                await serve(new Nghttp2Connection(conn));
            }
            finally
            {
                conn.DecRef();
            }
        });

    // Cleartext HTTP/2 with prior knowledge.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(60),
    };

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

    // A StreamContent, so not duplex: the client reads its answer once the upload has ended or been stopped.
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
