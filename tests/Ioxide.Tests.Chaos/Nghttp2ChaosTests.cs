using ioxide;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// The same h2c assaults as <see cref="H2ChaosTests"/>, pointed at the nghttp2 binding instead of
/// the managed server. It is a supported option again, so it is tested like one - and because the
/// wire is identical, the client harness is shared and the two can be compared directly.
///
/// Two of these are the vectors the managed server had to be taught to defend against. Running
/// them here answers what "battle-tested" is actually worth: the reference implementation should
/// turn both away without being told to.
/// </summary>
internal static class Nghttp2ChaosTests
{
    private static int StartH2c() => TestServer.Start(static async (_, conn) =>
    {
        try
        {
            await new Nghttp2Connection(conn).RunBufferedAsync(
                static _ => new Nghttp2Response { Status = 200, Body = "ok"u8.ToArray() });
        }
        finally
        {
            conn.DecRef();
        }
    });

    /// <summary>A server whose <c>/slow</c> handler parks for a second before answering.</summary>
    private static int StartSlowH2c() => TestServer.Start(static async (_, conn) =>
    {
        try
        {
            await new Nghttp2Connection(conn).RunBufferedAsync(static async request =>
            {
                if (request.Path.Span.SequenceEqual("/slow"u8))
                {
                    await Task.Delay(1000);
                }
                return new Nghttp2Response { Status = 200, Body = "ok"u8.ToArray() };
            });
        }
        finally
        {
            conn.DecRef();
        }
    });

    private static void AssertServes(int port)
    {
        using var client = new H2cClient(port);
        client.Open();
        client.Request(streamId: 1);
        Assert.True(client.AwaitResponse(streamId: 1), "server did not answer a well-formed h2c request");
    }

    public static void Register(Runner runner)
    {
        runner.Test("nghttp2: a well-formed request is answered", () => AssertServes(StartH2c()));

        runner.Test("nghttp2: a bad connection preface is rejected, server survives", () =>
        {
            int port = StartH2c();

            using (var bad = new H2cClient(port))
            {
                bad.WriteRaw("NOT-AN-HTTP2-PREFACE\r\n\r\n"u8);
                bad.WriteRaw(new byte[64]);
            }

            AssertServes(port);
        });

        runner.Test("nghttp2: a frame larger than the max is rejected, server survives", () =>
        {
            int port = StartH2c();

            using (var bad = new H2cClient(port))
            {
                bad.Open();
                // Declare 1 MiB of DATA and send none: past SETTINGS_MAX_FRAME_SIZE, and a lie.
                bad.WriteFrameHeader(0x0, 0, 1, 1024 * 1024, ReadOnlySpan<byte>.Empty);
            }

            AssertServes(port);
        });

        runner.Test("nghttp2: unknown frame types are ignored, the request still answers", () =>
        {
            int port = StartH2c();

            using var client = new H2cClient(port);
            client.Open();
            client.WriteFrame(0x2A, flags: 0, streamId: 0, "ignore me"u8);   // no such frame type
            client.Request(streamId: 1);

            Assert.True(client.AwaitResponse(streamId: 1), "an unknown frame type broke the connection");
        });

        runner.Test("nghttp2: a frame truncated mid-payload is handled, server survives", () =>
        {
            int port = StartH2c();

            using (var bad = new H2cClient(port))
            {
                bad.Open();
                bad.WriteFrameHeader(0x0, 0, 1, declaredLen: 256, actual: new byte[32]);
            }

            AssertServes(port);
        });

        runner.Test("nghttp2: a frame inside an open header block, or a CONTINUATION outside one, is a PROTOCOL_ERROR", () =>
        {
            int port = StartH2c();

            Assert.Equal("HEADERS 1", H2cClient.Verdict(port, c =>
            {
                c.RequestHeadersOnly(streamId: 1, endHeaders: false);
                c.WriteFrame(H2cClient.Continuation, flags: 0x4, streamId: 1, []);
            }));

            string verdicts = string.Join(", ",
                H2cClient.Verdict(port, c =>
                {
                    c.RequestHeadersOnly(streamId: 1, endHeaders: false);
                    c.Request(streamId: 3);
                }),
                H2cClient.Verdict(port, c =>
                {
                    c.RequestHeadersOnly(streamId: 1, endHeaders: false);
                    c.WriteFrame(0x6, flags: 0, streamId: 0, new byte[8]);
                    c.WriteFrame(H2cClient.Continuation, flags: 0x4, streamId: 1, []);
                }),
                H2cClient.Verdict(port, c =>
                {
                    c.RequestHeadersOnly(streamId: 1, endHeaders: true, endStream: false);
                    c.WriteFrame(H2cClient.Continuation, flags: 0x4, streamId: 1, []);
                    c.WriteFrame(0x0, flags: 0x1, streamId: 1, []);
                }),
                H2cClient.Verdict(port, c => c.WriteFrame(H2cClient.Continuation, flags: 0x4, streamId: 0, [])));

            Assert.Equal(string.Join(", ", Enumerable.Repeat("GOAWAY PROTOCOL_ERROR", 4)), verdicts);
            AssertServes(port);
        });

        runner.Test("nghttp2: a CONTINUATION flood is refused, server survives", () =>
        {
            // The managed server needed MaxHeaderListSize taught to it. nghttp2 has defended
            // against this since the flood was disclosed, so this should pass with no configuring -
            // which is precisely the argument for keeping the binding around.
            int port = StartH2c();

            using (var client = new H2cClient(port))
            {
                client.Open();
                client.RequestHeadersOnly(streamId: 1, endHeaders: false, endStream: false);

                byte[] filler = new byte[4096];
                byte seen = 0;
                for (int i = 0; i < 128 && seen == 0; i++)
                {
                    try
                    {
                        client.WriteFrame(H2cClient.Continuation, flags: 0, streamId: 1, filler);
                    }
                    catch (IOException)
                    {
                        seen = 0xFF;   // closed on us, which is a refusal
                        break;
                    }
                    seen = client.AwaitAnyOf([0x7], timeoutMs: 50);   // GOAWAY
                }

                Assert.True(seen != 0, "nghttp2 accepted an unbounded CONTINUATION block");
            }

            AssertServes(port);
        });

        runner.Test("nghttp2: a slow handler does not block another stream", () =>
        {
            // The binding kept the blocking dispatch loop long after the managed stack lost it:
            // DispatchReadyAsync awaited each handler in turn, so /fast could not answer until
            // /slow had. Asserting on ORDER rather than elapsed time keeps this deterministic -
            // with a blocking loop the first response is always the stream dispatched first.
            int port = StartSlowH2c();

            using var client = new H2cClient(port);
            client.Open();
            client.Request(streamId: 1, path: "/slow");
            client.Request(streamId: 3, path: "/fast");

            Assert.Equal(3, client.AwaitFirstResponse());
        });

        runner.Test("nghttp2: a streamed body arrives as separate DATA frames", () =>
        {
            // nghttp2 PULLS body bytes, so the shim buffers each chunk and resumes the stream while
            // its read callback defers on an empty window. Two things can go wrong invisibly: the
            // body arriving as ONE coalesced frame (the writer flushing nothing per chunk), or the
            // stream ending at the first dry moment (read_body returning EOF where it should defer).
            // Counting frames catches both - a single 4096-byte DATA would pass a length check.
            const int Chunks = 4, ChunkBytes = 1024;

            int port = TestServer.Start(static async (_, conn) =>
            {
                try
                {
                    await new Nghttp2Connection(conn).RunAsync(static async (_, writer) =>
                    {
                        writer.WriteHeaders(new Nghttp2Response { Status = 200 });
                        for (int i = 0; i < Chunks; i++)
                        {
                            byte[] chunk = new byte[ChunkBytes];
                            chunk.AsSpan().Fill((byte)'x');
                            chunk.CopyTo(writer.GetSpan(ChunkBytes));
                            writer.Advance(ChunkBytes);
                            await writer.FlushAsync();
                        }
                    });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            using var client = new H2cClient(port);
            client.Open();
            client.Request(streamId: 1);

            (int frames, int bytes, bool ended) = client.DrainBody(streamId: 1);

            Assert.Equal(Chunks * ChunkBytes, bytes);
            Assert.True(ended, "the stream never ended - read_body deferred forever instead of flagging EOF");
            Assert.True(frames >= Chunks,
                $"expected at least {Chunks} DATA frames, got {frames} - the body was coalesced, not streamed");
        });
    }
}
