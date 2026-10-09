using ioxide;
using ioxide.http2;

namespace Ioxide.Tests;

/// <summary>
/// HTTP/2 (h2c) chaos against the managed <see cref="Http2Connection"/> server: a bad connection
/// preface, a frame larger than the negotiated maximum, unknown frame types that the spec says to
/// ignore, and a frame truncated mid-payload. The server must reject the malformed input on its own
/// terms (GOAWAY, or a dropped connection) and keep answering fresh connections.
/// </summary>
internal static class H2ChaosTests
{
    private static int StartH2c(Http2Options? options = null) => TestServer.Start(async (_, conn) =>
    {
        try
        {
            await new Http2Connection(conn, options).RunBufferedAsync(static _ => Http2Response.Text("ok"));
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
        runner.Test("h2c: a well-formed request is answered", () =>
        {
            int port = StartH2c();
            AssertServes(port);
        });

        runner.Test("h2c: a bad connection preface is rejected, server survives", () =>
        {
            int port = StartH2c();

            using (var bad = new H2cClient(port))
            {
                bad.WriteRaw("NOT-A-VALID-HTTP2-PREFACE\r\n\r\n"u8);   // not "PRI * HTTP/2.0..."
                Thread.Sleep(150);
            }

            AssertServes(port);
        });

        runner.Test("h2c: a frame larger than the max is rejected, server survives", () =>
        {
            int port = StartH2c();

            using (var attacker = new H2cClient(port))
            {
                attacker.Open();
                // Declare a 1 MiB HEADERS frame - far past the 16384 max - then send none of it. The
                // server must fault on the frame header (FRAME_SIZE_ERROR), not try to buffer a
                // megabyte.
                attacker.WriteFrameHeader(type: 0x1, flags: 0x4, streamId: 1, declaredLen: 1 << 20,
                    actual: ReadOnlySpan<byte>.Empty);
                Thread.Sleep(150);
            }

            AssertServes(port);
        });

        runner.Test("h2c: unknown frame types are ignored, the request still answers", () =>
        {
            int port = StartH2c();

            using var client = new H2cClient(port);
            client.Open();
            // RFC 9113 4.1: an endpoint MUST ignore a frame of unknown type. Slip one in before the
            // request and the request must still be served.
            client.WriteFrame(type: 0xFA, flags: 0, streamId: 0, payload: [1, 2, 3, 4]);
            client.Request(streamId: 1);
            Assert.True(client.AwaitResponse(streamId: 1), "server choked on an unknown frame type");
        });

        runner.Test("h2c: DATA on stream 0 is a PROTOCOL_ERROR", () =>
        {
            // RFC 9113 6.1. It was credited to the connection and dropped.
            int port = StartH2c();

            Assert.Equal("HEADERS 1", H2cClient.Verdict(port, c =>
            {
                c.RequestHeadersOnly(streamId: 1, endHeaders: true, endStream: false);
                c.WriteFrame(0x0, flags: 0x1, streamId: 1, "x"u8);
            }));
            Assert.Equal("GOAWAY PROTOCOL_ERROR", H2cClient.Verdict(port, c =>
            {
                c.WriteFrame(0x0, flags: 0, streamId: 0, "x"u8);
                c.Request(streamId: 1);
            }));

            AssertServes(port);
        });

        runner.Pending("h2c: DATA on an idle stream is a PROTOCOL_ERROR", () =>
        {
            int port = StartH2c();
            Assert.Equal("GOAWAY PROTOCOL_ERROR", H2cClient.Verdict(port, c =>
            {
                c.WriteFrame(0x0, flags: 0, streamId: 5, "x"u8);
                c.Request(streamId: 1);
            }));
        }, "RFC 9113 5.1 - an idle stream differs from a closed one only by the highest stream id opened, which Http2Connection does not keep");

        runner.Test("h2c: a frame truncated mid-payload is handled, server survives", () =>
        {
            int port = StartH2c();

            using (var attacker = new H2cClient(port))
            {
                attacker.Open();
                // Declare 100 bytes of HEADERS, send 10, then drop the connection.
                attacker.WriteFrameHeader(type: 0x1, flags: 0x4, streamId: 1, declaredLen: 100,
                    actual: new byte[10]);
                Thread.Sleep(150);
            }

            AssertServes(port);
        });

        runner.Test("h2c: a WINDOW_UPDATE that takes the connection window past 2^31-1 is a FLOW_CONTROL_ERROR", () =>
        {
            // RFC 9113 6.9.1. The sum wrapped negative, and a response then had no credit to leave on.
            int port = StartH2c();
            const int ToMax = int.MaxValue - 65535;   // the peer's window starts at 65535

            using (var client = new H2cClient(port))
            {
                client.Open();
                client.WriteWindowUpdate(streamId: 0, ToMax);
                client.Request(streamId: 1);
                Assert.Equal((1, 2, true), client.DrainBody(streamId: 1));
            }

            Assert.Equal("GOAWAY FLOW_CONTROL_ERROR", H2cClient.Verdict(port, c =>
            {
                c.WriteWindowUpdate(streamId: 0, ToMax + 1);
                c.Request(streamId: 1);
            }));

            AssertServes(port);
        });

        runner.Test("h2c: a WINDOW_UPDATE that takes a stream window past 2^31-1 resets the stream with FLOW_CONTROL_ERROR", () =>
        {
            // RFC 9113 6.9.1. A request still arriving keeps its window on its stream.
            int port = StartH2c();
            const int ToMax = int.MaxValue - 65535;

            Assert.Equal("HEADERS 1", H2cClient.Verdict(port, c =>
            {
                c.RequestHeadersOnly(streamId: 1, endHeaders: true, endStream: false);
                c.WriteWindowUpdate(streamId: 1, ToMax);
                c.WriteFrame(0x0, flags: 0x1, streamId: 1, []);
            }));
            Assert.Equal("RST_STREAM 1 FLOW_CONTROL_ERROR", H2cClient.Verdict(port, c =>
            {
                c.RequestHeadersOnly(streamId: 1, endHeaders: true, endStream: false);
                c.WriteWindowUpdate(streamId: 1, ToMax + 1);
                c.WriteFrame(0x0, flags: 0x1, streamId: 1, []);
            }));

            AssertServes(port);
        });

        runner.Test("h2c: a WINDOW_UPDATE past 2^31-1 resets a streamed response instead of stalling it", () =>
        {
            // A response in flight keeps its own window, and the wrapped sum left it without credit for good.
            const int ToMax = int.MaxValue - 65535;
            int port = TestServer.Start(static async (_, conn) =>
            {
                try
                {
                    await new Http2Connection(conn, new Http2Options { StreamRequestBodies = true }).RunAsync(
                        static async (request, writer) =>
                        {
                            writer.WriteHeaders(new Http2Response { Status = 200 });
                            await writer.FlushAsync();
                            while (!(await request.BodyReader!.ReadAsync()).IsEmpty)
                            {
                            }
                            "ok"u8.CopyTo(writer.GetSpan(2));
                            writer.Advance(2);
                        });
                }
                finally
                {
                    conn.DecRef();
                }
            });

            // The response's headers come first, so its window exists before the WINDOW_UPDATE lands.
            H2cClient InFlight(int increment)
            {
                var client = new H2cClient(port);
                client.Open();
                client.RequestHeadersOnly(streamId: 1, endHeaders: true, endStream: false);
                Assert.Equal("HEADERS 1", client.AwaitVerdict());
                client.WriteWindowUpdate(streamId: 1, increment);
                client.WriteFrame(0x0, flags: 0x1, streamId: 1, []);
                return client;
            }

            using (H2cClient client = InFlight(ToMax))
            {
                Assert.Equal((1, 2, true), client.DrainBody(streamId: 1));
            }
            using (H2cClient client = InFlight(ToMax + 1))
            {
                Assert.Equal("RST_STREAM 1 FLOW_CONTROL_ERROR", client.AwaitVerdict());
            }

            AssertServes(port);
        });

        runner.Test("h2c: a burst of streams on one connection are all framed", () =>
        {
            int port = StartH2c();

            using var client = new H2cClient(port);
            client.Open();

            const int streams = 16;
            for (int i = 0; i < streams; i++)
            {
                client.Request(streamId: 1 + (i * 2));   // odd stream ids, client-initiated
            }

            // At least the first stream must come back; the point is the multiplexer survives a
            // burst without losing the connection.
            Assert.True(client.AwaitResponse(streamId: 1), "server dropped a multiplexed request burst");
        });

        runner.Test("h2c: a CONTINUATION flood is cut off instead of growing without bound", () =>
        {
            // MaxFrameSize bounds one frame; nothing bounds how MANY continuations follow a HEADERS
            // that never sets END_HEADERS. Unbounded, the accumulated block grows until the process
            // dies - the flood disclosed in April 2024. The block is capped now, and exceeding it is
            // a CONNECTION error because a block that stops being decoded desynchronises HPACK.
            int port = StartH2c(new Http2Options { MaxHeaderListSize = 16 * 1024 });

            using (var client = new H2cClient(port))
            {
                client.Open();
                client.RequestHeadersOnly(streamId: 1, endHeaders: false, endStream: false);

                byte[] filler = new byte[4096];
                byte seen = 0;
                for (int i = 0; i < 64 && seen == 0; i++)   // 256 KiB, far past the 16 KiB cap
                {
                    try
                    {
                        client.WriteFrame(H2cClient.Continuation, flags: 0, streamId: 1, filler);
                    }
                    catch (IOException)
                    {
                        seen = 0xFF;   // server closed on us, which is also a refusal
                        break;
                    }
                    seen = client.AwaitAnyOf([0x7], timeoutMs: 50);   // GOAWAY
                }

                Assert.True(seen != 0, "server accepted an unbounded CONTINUATION block");
            }

            AssertServes(port);   // and the process is still there to serve the next connection
        });

        runner.Test("h2c: streams past MaxConcurrentStreams are refused, not allocated", () =>
        {
            // The limit was advertised in SETTINGS and never enforced, so "open a stream, reset it,
            // repeat" cost the server an arena per cycle and the peer nothing (CVE-2023-44487).
            // Streams past the limit now get REFUSED_STREAM, which RFC 9113 8.7 makes safe to retry.
            int port = StartH2c(new Http2Options { MaxConcurrentStreams = 4 });

            using var client = new H2cClient(port);
            client.Open();

            // END_HEADERS but NOT END_STREAM: each stream stays open, so the limit is reached.
            for (int i = 0; i < 4; i++)
            {
                client.RequestHeadersOnly(1 + (i * 2), endHeaders: true, endStream: false);
            }

            client.RequestHeadersOnly(streamId: 101, endHeaders: true, endStream: false);
            Assert.Equal(H2cClient.RstStream, client.AwaitAnyOf([H2cClient.RstStream], streamId: 101));

            // Refusing must not have desynchronised HPACK - the block was still decoded - so a
            // stream opened afterwards on the same connection still parses.
            AssertServes(port);
        });
    }
}
