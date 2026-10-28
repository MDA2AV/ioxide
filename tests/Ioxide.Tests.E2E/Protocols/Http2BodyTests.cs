using System.Buffers;
using System.Net;

using ioxide;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// Streamed HTTP/2 response bodies over a REAL server: a real reactor, a real TcpConnection and its
/// write slab, and a real HTTP/2 client reading the body back.
///
/// The shape under test is a static file server's: headers inside the dispatch pass, a park on the
/// file read, then the body pushed as bounded chunks with a flush after each - because the producer
/// copies into a fixed buffer and must drain it before staging the next slice.
///
/// Everything is asserted on the RECEIVED BYTES. A response that loses its body still emits
/// well-formed HEADERS and END_STREAM, so it arrives as a clean 200 of length zero; only comparing
/// content catches it. The in-process queue tests (Ioxide.Tests.Unit) drive the same shapes through
/// a fake pipe and pass, so anything that fails here and not there is the transport, not the
/// framing.
/// </summary>
internal static class Http2BodyTests
{
    // What a file-serving module stages per flush: bounded well under the 16 KiB write slab so the
    // status and headers already in it still fit.
    private const int FileChunk = 12 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("h2 body: a small response arrives whole", () =>
        {
            byte[] file = Pattern(202);
            AssertServed(file, StartFileServer(file, park: false, chunk: FileChunk));
        });

        runner.Test("h2 body: a small response parked before the body arrives whole", () =>
        {
            byte[] file = Pattern(202);
            AssertServed(file, StartFileServer(file, park: true, chunk: FileChunk));
        });

        runner.Test("h2 body: an 8 KiB file flushed in one chunk arrives whole", () =>
        {
            byte[] file = Pattern(8 * 1024);
            AssertServed(file, StartFileServer(file, park: true, chunk: FileChunk));
        });

        runner.Test("h2 body: a file flushed per 12 KiB chunk arrives whole", () =>
        {
            byte[] file = Pattern((3 * FileChunk) + 517);
            AssertServed(file, StartFileServer(file, park: true, chunk: FileChunk));
        });

        runner.Test("h2 body: a file past the initial flow-control window arrives whole", () =>
        {
            // 256 KiB against a 65535-byte connection window: it cannot complete without
            // WINDOW_UPDATE, so this covers the park-on-credit path every large download takes.
            byte[] file = Pattern(256 * 1024);
            AssertServed(file, StartFileServer(file, park: true, chunk: FileChunk));
        });

        runner.Test("h2 body: a file flushed in small chunks arrives whole", () =>
        {
            // Many more flushes than frames: the coalescing path has to preserve every byte, not
            // merely most of them.
            byte[] file = Pattern(64 * 1024);
            AssertServed(file, StartFileServer(file, park: true, chunk: 512));
        });

        runner.Test("h2 body: a file written without flushing arrives whole", () =>
        {
            // The counterpart shape - stage the whole body, let completion send it - which is what
            // a module that does not flush per chunk produces.
            byte[] file = Pattern(64 * 1024);
            AssertServed(file, StartFileServer(file, park: true, chunk: 0));
        });

        // StreamRequestBodies hands the handler a request whose body is still arriving, so the
        // stream stays open for reading while the response is written. It is what a framework
        // serving arbitrary request bodies turns on, and it changes the connection's stream
        // bookkeeping - so every body shape above has to hold under it too.
        runner.Test("h2 body: a file arrives whole with streamed request bodies", () =>
        {
            byte[] file = Pattern(8 * 1024);
            AssertServed(file, StartFileServer(file, park: true, chunk: FileChunk,
                options: new Http2Options { StreamRequestBodies = true }));
        });

        runner.Test("h2 body: a large file arrives whole with streamed request bodies", () =>
        {
            byte[] file = Pattern(256 * 1024);
            AssertServed(file, StartFileServer(file, park: true, chunk: FileChunk,
                options: new Http2Options { StreamRequestBodies = true }));
        });

        runner.Test("h2 body: a body copied in through GetMemory arrives whole", () =>
        {
            // The other half of IBufferWriter: a Stream reads into Memory<byte> and cannot read
            // into Span<byte>, so every "copy this stream to the response" helper goes through
            // GetMemory. The HTTP/3 writer threw here and served empty bodies; this pins the
            // contract on the HTTP/2 one, where the two must not diverge.
            byte[] file = Pattern(64 * 1024);
            int port = TestServer.Start(async (_, conn) =>
            {
                try
                {
                    await new Http2Connection(conn).RunStreamedResponseAsync(async (_, writer) =>
                    {
                        writer.WriteHeaders(new Http2Response { Status = 200 });
                        await Task.Yield();

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
                            await writer.FlushAsync();
                        }

                        await writer.CompleteAsync();
                    });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            AssertServed(file, port);
        });

        runner.Test("h2 body: a response with capitalised headers still delivers its body", () =>
        {
            // RFC 9113 8.2.1: an uppercase letter in a field name is malformed, and a peer may
            // treat the whole message as a stream error. Callers hold headers in whatever case
            // their own API uses, so the encoder has to lowercase them - and when it did not, the
            // response arrived as a clean 200 with the body silently discarded, which reads like a
            // body bug rather than a header one.
            byte[] file = Pattern(8 * 1024);
            int port = TestServer.Start(async (_, conn) =>
            {
                try
                {
                    await new Http2Connection(conn).RunStreamedResponseAsync(async (_, writer) =>
                    {
                        var head = new Http2Response { Status = 200 };
                        head.Headers.Add("Content-Type"u8.ToArray(), "text/css"u8.ToArray());
                        head.Headers.Add("Vary"u8.ToArray(), "Accept-Encoding"u8.ToArray());
                        head.Headers.Add("X-Custom-Header"u8.ToArray(), "AbC"u8.ToArray());
                        writer.WriteHeaders(head);

                        await Task.Yield();
                        writer.Write(file);
                        await writer.CompleteAsync();
                    });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using HttpClient client = H2Client();
            Task<(string[] Names, byte[] Body)> received = GetWithHeadersAsync(client, port);
            Assert.True(received.Wait(30_000), "the response completed");

            // Asserted on the CUSTOM name as delivered. A lenient client is no witness - .NET
            // accepts a capitalised name happily - and it canonicalises the ones it knows, so
            // "vary" is reported back as "Vary" whatever crossed the wire. An unknown name is the
            // only one whose received case still reflects what was sent. HpackEncodeTests asserts
            // on the encoded bytes, where every name is visible.
            string? custom = received.Result.Names
                                     .FirstOrDefault(n => n.Equals("x-custom-header", StringComparison.OrdinalIgnoreCase));

            Assert.True(custom is not null, "the custom header was delivered");
            Assert.Equal("x-custom-header", custom!);

            AssertBody(file, received.Result.Body, "body");
        });

        runner.Test("h2 body: concurrent requests each get their own body whole", () =>
        {
            // Multiplexed streams share one connection window and one write slab; a body that
            // leaks into another stream's, or is cut short by it, shows up here and nowhere else.
            byte[] file = Pattern(32 * 1024);
            int port = StartFileServer(file, park: true, chunk: FileChunk);

            using var client = H2Client();
            var responses = new Task<byte[]>[8];
            for (int i = 0; i < responses.Length; i++)
            {
                responses[i] = GetAsync(client, port);
            }

            Assert.True(Task.WhenAll(responses).Wait(30_000), "all concurrent responses completed");
            for (int i = 0; i < responses.Length; i++)
            {
                AssertBody(file, responses[i].Result, $"stream {i}");
            }
        });
    }

    /// <summary>
    /// A server that answers every request with <paramref name="file"/>, through the streamed writer.
    /// </summary>
    /// <param name="park">
    /// Yield before the body, so the flushes land OUTSIDE the dispatch pass - which is where a file
    /// read off the ring puts them. Without it the whole response is produced inside the pass and
    /// rides its flush, which is a different write path entirely.
    /// </param>
    /// <param name="chunk">Bytes to stage per flush; 0 stages the whole body and never flushes.</param>
    private static int StartFileServer(byte[] file, bool park, int chunk, Http2Options? options = null)
        => TestServer.Start(async (_, conn) =>
    {
        try
        {
            await new Http2Connection(conn, options).RunStreamedResponseAsync(async (_, writer) =>
            {
                writer.WriteHeaders(new Http2Response { Status = 200 });

                if (park)
                {
                    // Resumes on the reactor, after the pass that dispatched this request has gone.
                    await Task.Yield();
                }

                if (chunk <= 0)
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
            });
        }
        finally
        {
            conn.DecRef();
        }
    });

    private static void AssertServed(byte[] file, int port)
    {
        using var client = H2Client();
        Task<byte[]> response = GetAsync(client, port);
        Assert.True(response.Wait(30_000), "the response completed");
        AssertBody(file, response.Result, "body");
    }

    // Cleartext HTTP/2 with prior knowledge: no upgrade dance, exactly what an h2c peer sends.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(30),
    };

    private static async Task<byte[]> GetAsync(HttpClient client, int port)
    {
        try
        {
            using HttpResponseMessage response = await client.GetAsync($"http://127.0.0.1:{port}/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await response.Content.ReadAsByteArrayAsync();
        }
        catch (HttpRequestException exception)
        {
            // The default message ("Error while copying content to a stream") names neither the
            // protocol error nor the side that raised it, and a body that dies mid-transfer is
            // exactly what these tests are here to diagnose.
            Exception cause = exception.GetBaseException();
            throw new Exception($"{cause.GetType().Name}: {cause.Message}", exception);
        }
    }

    private static async Task<(string[] Names, byte[] Body)> GetWithHeadersAsync(HttpClient client, int port)
    {
        using HttpResponseMessage response = await client.GetAsync($"http://127.0.0.1:{port}/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string[] names = [.. response.Headers.Select(h => h.Key), .. response.Content.Headers.Select(h => h.Key)];
        return (names, await response.Content.ReadAsByteArrayAsync());
    }

    private static void AssertBody(byte[] expected, byte[] actual, string what)
    {
        Assert.True(actual.Length == expected.Length,
            $"{what} length: expected {expected.Length}, received {actual.Length}");
        Assert.True(actual.AsSpan().SequenceEqual(expected),
            $"{what} content differs at offset {FirstDifference(expected, actual)}");
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
