using System.Buffers;
using System.Net;
using ioxide;
using ioxide.http2;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>An answer that ends before its request does, with real clients: the answer arrives whole, and the upload stops (RFC 9113 8.1, RFC 9114 4.1).</summary>
internal static class EarlyAnswerTests
{
    // Far more than any window lets through before the client hears it should stop.
    private const long Upload = 64L << 20;

    // A control's upload, read whole by its handler.
    private const long ReadUpload = 8L << 20;

    // Measured stops are 64 KiB on h2, the connection window, and 192 KiB on h3; these leave room for a slow box.
    private const long H2Stopped = 512L << 10;
    private const long H3Stopped = 1L << 20;

    // What the raw client offers to upload after the request's headers: past it, nothing stopped the upload.
    private const long RawBudget = 4L << 20;

    private const ulong H3RequestCancelled = 0x10c;

    public static void Register(Runner runner)
    {
        RegisterHttpClient(runner);
        RegisterRawClient(runner);
    }

    private static void RegisterHttpClient(Runner runner)
    {
        // Inside the client's 64 KiB stream window: this client credits an answer only once its upload ends, and the reset follows the END_STREAM.
        byte[] h2Answer = Pattern(32 * 1024);

        // Many packets, which the STOP_SENDING rides out with.
        byte[] h3Answer = Pattern(256 * 1024);

        byte[] bufferedAnswer = Pattern(8 * 1024);

        runner.Test("h2 early answer: a streamed 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH2(connection => connection.RunAsync((_, _, writer) => AnswerAsync(writer, h2Answer)));
            using HttpClient client = H2Client();
            AssertAnsweredAndStopped(client, $"http://127.0.0.1:{port}/", h2Answer, H2Stopped);
        });

        runner.Test("h2 early answer: a buffered 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH2(connection => connection.RunAsync((_, _) =>
                new ValueTask<Http2Response>(new Http2Response { Status = 413, Body = bufferedAnswer })));
            using HttpClient client = H2Client();
            AssertAnsweredAndStopped(client, $"http://127.0.0.1:{port}/", bufferedAnswer, H2Stopped);
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
            AssertAnsweredAndStopped(client, $"https://127.0.0.1:{port}/", h3Answer, H3Stopped);
        }, skip: !h3);

        runner.Test("h3 early answer (nghttp3): a buffered 413 to an upload arrives whole, and the client stops uploading", () =>
        {
            int port = StartH3(connection => connection.RunAsync((_, _) =>
                new ValueTask<Nghttp3Response>(new Nghttp3Response { Status = 413, Body = bufferedAnswer })));
            using HttpClient client = H3Client();
            AssertAnsweredAndStopped(client, $"https://127.0.0.1:{port}/", bufferedAnswer, H3Stopped);
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

    // The shim's own client, so these run where msquic is missing.
    private static void RegisterRawClient(Runner runner)
    {
        byte[] answer = Pattern(8 * 1024);

        foreach (bool streamed in new[] { false, true })
        {
            bool stream = streamed;
            runner.Test($"h3 early answer (nghttp3, raw client): a {(stream ? "streamed" : "buffered")} 413 to an upload still arriving arrives whole, and the upload stops", () =>
            {
                int port = StartH3(connection => stream
                    ? connection.RunAsync(async (_, _, writer) =>
                    {
                        writer.WriteHeaders(new Nghttp3Response { Status = 413 });
                        writer.Write(answer);
                        await writer.CompleteAsync();
                    })
                    : connection.RunAsync((_, _) => new ValueTask<Nghttp3Response>(new Nghttp3Response { Status = 413, Body = answer })));

                using RawH3Client client = ConnectRaw(port);
                client.OpenRequestStream();
                Assert.True(client.TryWrite([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(Upload)], fin: false),
                    "the request's headers were refused");

                long sent = UploadUntilStopped(client);
                Assert.True(sent < H3Stopped, $"the client uploaded {sent} bytes to a handler that read none of them: nothing asked it to stop");
                Assert.True(client.WaitForFin(timeoutMs: 5000), "the answer never ended");
                AssertBody(answer, DataPayload(client.Received));
            });
        }

        runner.Test("h3 early answer (nghttp3, raw client): a client that refused the answer is still asked to stop uploading once its handler returns", () =>
        {
            // More answer than the client's window holds, so the transport is still sending it when the refusal lands.
            var refused = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var returned = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = StartH3(connection => connection.RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Nghttp3Response { Status = 413 });
                for (int i = 0; i < 128; i++)
                {
                    answer.CopyTo(writer.GetSpan(answer.Length));
                    writer.Advance(answer.Length);
                    await writer.FlushAsync();
                }
                await refused.Task;
                returned.TrySetResult((await writer.FlushAsync()).IsCompleted);
            }));

            using RawH3Client client = ConnectRaw(port);
            client.OpenRequestStream();
            Assert.True(client.TryWrite([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(Upload), .. new byte[16 * 1024]], fin: false),
                "the request's headers were refused");
            client.StopSending(H3RequestCancelled);
            Assert.True(client.WaitForReset(timeoutMs: 5000) == H3RequestCancelled, "the server never answered the refusal with RESET_STREAM");

            refused.SetResult();
            Assert.True(client.WaitFor(returned.Task, timeoutMs: 10_000), "the handler never returned");
            Assert.True(returned.Task.Result, "the handler was never told the client refused its answer");

            long sent = UploadUntilStopped(client);
            Assert.True(sent < H3Stopped, $"the client uploaded {sent} more bytes after the handler returned: nothing asked it to stop");
        });

        runner.Test("h3 early answer (nghttp3): a transport that ends the connection inside StopReading leaves nghttp3 nothing to call", () =>
        {
            // Off the run loop, the close resumes it inline and its teardown frees nghttp3: a native call after it is a NULL dereference.
            var quic = new ClosingStopQuic();
            Assert.True(quic.EnqueueStreamData(0, [.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(1000), .. new byte[100]], fin: false),
                "the recv ring refused the request");
            quic.SignalDataArrived();

            var answered = new TaskCompletionSource();
            Task run = new Nghttp3Connection(quic).RunAsync(async (_, _) =>
            {
                await answered.Task;
                return new Nghttp3Response { Status = 413 };
            });
            Assert.True(!run.IsCompleted, "the run loop is not parked on its next read");

            answered.SetResult();
            Assert.True(run.Wait(5000), "the run loop never ended");
            Assert.Equal(1, quic.StopReadingCalls);
        });
    }

    private static void AssertAnsweredAndStopped(HttpClient client, string url, byte[] answer, long stopped)
    {
        var upload = new CountedUpload(Upload);
        Task<(HttpStatusCode Status, byte[] Body)> answered = PostAsync(client, url, upload);

        Assert.True(answered.Wait(100_000), "the answer never arrived");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, answered.Result.Status);
        AssertBody(answer, answered.Result.Body);

        long sent = upload.Ended.Result;
        Assert.True(sent < stopped,
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

    // How much the raw client uploads before the server's STOP_SENDING shuts its sending side, up to the budget.
    private static long UploadUntilStopped(RawH3Client client)
    {
        byte[] chunk = new byte[16 * 1024];
        long sent = 0;
        long deadline = Environment.TickCount64 + 30_000;
        while (sent < RawBudget && Environment.TickCount64 < deadline && client.TryWrite(chunk, fin: false))
        {
            sent += chunk.Length;
        }
        return sent;
    }

    // The DATA payload of the h3 frames on a request stream.
    private static byte[] DataPayload(ReadOnlySpan<byte> frames)
    {
        var body = new List<byte>();
        while (!frames.IsEmpty)
        {
            long type = ReadVarint(ref frames);
            int length = (int)ReadVarint(ref frames);
            if (type == 0x0)
            {
                body.AddRange(frames[..length]);
            }
            frames = frames[length..];
        }
        return body.ToArray();
    }

    // RFC 9000 16: the top two bits give the length, 1, 2, 4 or 8 bytes.
    private static long ReadVarint(ref ReadOnlySpan<byte> bytes)
    {
        int length = 1 << (bytes[0] >> 6);
        long value = bytes[0] & 0x3F;
        for (int i = 1; i < length; i++)
        {
            value = (value << 8) | bytes[i];
        }
        bytes = bytes[length..];
        return value;
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

    private static RawH3Client ConnectRaw(int udpPort)
    {
        var client = new RawH3Client("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;
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

    // A StreamContent, so not duplex: over HTTP/3 the client finishes its upload before it hands over the answer.
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

    // A transport whose StopReading ends the connection, as the engine's does when the flush it makes off a cycle fails.
    private sealed class ClosingStopQuic : QuicConnection
    {
        private long _nextUni = 3;

        public int StopReadingCalls;

        public ClosingStopQuic()
        {
            NegotiatedProtocol = "h3";
        }

        public override void OnDatagram(ReadOnlySpan<byte> payload, byte tos) { }
        public override long GetNextTimeout(long nowMs) => long.MaxValue;
        public override void OnTimer(long nowMs) { }
        public override void OnEvicted(QuicEvictReason reason) { }
        public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin) { }

        public override long OpenUniStream()
        {
            long id = _nextUni;
            _nextUni += 4;
            return id;
        }

        public override void Close(ulong applicationErrorCode) => MarkClosed();

        public override void StopReading(long streamId, ulong applicationErrorCode)
        {
            StopReadingCalls++;
            Close(0x102);
        }
    }
}
