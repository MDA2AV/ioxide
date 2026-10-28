using System.Buffers;
using System.Text;

using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Streamed HTTP/3 response bodies over the nghttp3 writer, against a real QUIC server and the
/// nghttp3-based test client.
///
/// This is the HTTP/3 counterpart of Http2BodyTests, and it exists for the same reason: a body
/// that never leaves still produces a well-formed 200 with a correct content-length, so only
/// comparing the RECEIVED bytes catches it. The shapes are a static file server's - a body pushed
/// as bounded chunks with a flush after each, and the same body staged whole and left for
/// CompleteAsync to send. Those two took different paths through the writer and only one of them
/// was covered anywhere.
/// </summary>
internal static class Http3BodyTests
{
    // What a file-serving module stages per flush.
    private const int FileChunk = 12 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("h3 body: a small response completed without a flush arrives whole", () =>
        {
            AssertServed(Pattern(202), chunk: 0);
        });

        runner.Test("h3 body: a small response flushed before completion arrives whole", () =>
        {
            AssertServed(Pattern(202), chunk: FileChunk);
        });

        runner.Test("h3 body: an 8 KiB file flushed per chunk arrives whole", () =>
        {
            AssertServed(Pattern(8 * 1024), chunk: FileChunk);
        });

        runner.Test("h3 body: an 8 KiB file staged whole and completed arrives whole", () =>
        {
            // No flush of the handler's own: the body is staged and CompleteAsync has to send it.
            // A module that does not pace itself produces exactly this, and it is the shape that
            // delivered a 200 with an empty body.
            AssertServed(Pattern(8 * 1024), chunk: 0);
        });

        runner.Test("h3 body: a multi-chunk file flushed per chunk arrives whole", () =>
        {
            AssertServed(Pattern((3 * FileChunk) + 517), chunk: FileChunk);
        });

        runner.Test("h3 body: a large file staged whole and completed arrives whole", () =>
        {
            AssertServed(Pattern(64 * 1024), chunk: 0);
        });

        runner.Test("h3 body: a file flushed in small chunks arrives whole", () =>
        {
            AssertServed(Pattern(32 * 1024), chunk: 512);
        });

        runner.Test("h3 body: a body copied in through GetMemory arrives whole", () =>
        {
            // The OTHER half of IBufferWriter. Everything above pushes with Write/GetSpan, but a
            // caller copying a stream in reaches for GetMemory - a Stream can read straight into a
            // Memory<byte> and cannot read into a Span - so that is the shape a framework's
            // "write this file to the response" helper actually produces:
            //
            //     while (true) { var m = target.GetMemory(64 * 1024);
            //                    var n = await stream.ReadAsync(m);
            //                    if (n == 0) break; target.Advance(n); }
            //
            // A writer that throws from GetMemory is not an IBufferWriter, and the caller sees it
            // as a 200 with an empty body, because the headers are already gone by then.
            AssertServed(Pattern(8 * 1024), chunk: -1);
        });

        runner.Test("h3 body: a large body copied in through GetMemory arrives whole", () =>
        {
            AssertServed(Pattern(256 * 1024), chunk: -1);
        });

        runner.Test("h3 body: a buffer held across an await survives the flush that follows", () =>
        {
            // The reason GetMemory cannot simply point at the native staging block. A caller holds
            // the buffer across the await it asked for one to do, and in that window the writer's
            // own machinery moves that block: a flush swaps staging with the in-flight chunk, and
            // connection teardown frees it outright without waiting for parked handlers. Whatever
            // GetMemory returns has to stay writable regardless.
            byte[] file = Pattern(64 * 1024);

            AssertServedBy(file, async (writer, body) =>
            {
                for (int at = 0; at < body.Length; at += 4096)
                {
                    int take = Math.Min(4096, body.Length - at);

                    Memory<byte> buffer = writer.GetMemory(take);

                    // Hand the reactor back while holding it - a real read would park here.
                    await Task.Yield();

                    body.AsSpan(at, take).CopyTo(buffer.Span);
                    writer.Advance(take);

                    await writer.FlushAsync();
                }

                await writer.CompleteAsync();
            });
        });
    }

    /// <param name="chunk">
    /// Bytes staged per flush; 0 stages the whole body and never flushes; -1 copies the body in
    /// through GetMemory, the way a stream-to-response helper does.
    /// </param>
    private static void AssertServedBy(byte[] file, Func<Nghttp3ResponseWriter, byte[], ValueTask> produce)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => new Nghttp3Connection(conn, new Nghttp3Options { StreamRequestBodies = true }).RunStreamedResponseAsync(
                async (_, writer) =>
                {
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                    await produce(writer, file);
                }));

        AssertBodyFrom(udpPort, file);
    }

    private static void AssertServed(byte[] file, int chunk)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => new Nghttp3Connection(conn, new Nghttp3Options { StreamRequestBodies = true }).RunStreamedResponseAsync(
                async (_, writer) =>
                {
                    writer.WriteHeaders(new Nghttp3Response { Status = 200 });

                    if (chunk < 0)
                    {
                        // Exactly GenHTTP's StreamExtensions.WriteAsync(Stream, IBufferWriter).
                        using var source = new MemoryStream(file, writable: false);

                        while (true)
                        {
                            Memory<byte> memory = writer.GetMemory(64 * 1024);
                            int read = await source.ReadAsync(memory);

                            if (read == 0)
                            {
                                break;
                            }

                            writer.Advance(read);
                        }
                    }
                    else if (chunk == 0)
                    {
                        writer.Write(file);
                    }
                    else
                    {
                        for (int at = 0; at < file.Length; at += chunk)
                        {
                            writer.Write(file.AsSpan(at, Math.Min(chunk, file.Length - at)));
                            await writer.FlushAsync();
                        }
                    }

                    await writer.CompleteAsync();
                }));

        AssertBodyFrom(udpPort, file);
    }

    private static void AssertBodyFrom(int udpPort, byte[] file)
    {
        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

        (int status, string body) = client.Get("/", timeoutMs: 15_000);

        Assert.Equal(200, status);

        byte[] received = Encoding.ASCII.GetBytes(body);
        Assert.True(received.Length == file.Length,
            $"body length: expected {file.Length}, received {received.Length}");
        Assert.True(received.AsSpan().SequenceEqual(file),
            $"body content differs at offset {FirstDifference(file, received)}");
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

    // Printable ASCII, because the test client hands the body back as a string - a position
    // dependent pattern still catches a body reassembled out of order, without the round trip
    // through Encoding losing bytes.
    private static byte[] Pattern(int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)('a' + (i % 26));
        }
        return bytes;
    }
}
