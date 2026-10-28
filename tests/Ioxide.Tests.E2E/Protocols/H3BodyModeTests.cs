using System.Buffers;
using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Which body a handler is handed, on both HTTP/3 stacks. <c>StreamRequestBodies</c> decides it for
/// every handler that can await one - a buffered response and a streamed one alike - and a
/// synchronous handler, which cannot, always gets the whole body. Each handler answers with what it
/// was given, so a body that went to the wrong place fails naming where it went.
/// </summary>
internal static class H3BodyModeTests
{
    // Past the 256 KiB stream window, so a streamed body only arrives if it is credited mid-flight.
    private static readonly byte[] Upload = Encoding.ASCII.GetBytes(new string('u', 300_000));

    private static readonly string Whole = $"whole {Upload.Length}";
    private static readonly string Streamed = $"streamed {Upload.Length}";

    public static void Register(Runner runner)
    {
        RegisterNghttp3(runner);
        RegisterManaged(runner);
    }

    private static void RegisterNghttp3(Runner runner)
    {
        runner.Test("h3: a streamed response gets the whole body without StreamRequestBodies", () =>
            Assert.Equal(Whole, Answer(conn => new Nghttp3Connection(conn).RunStreamedResponseAsync(
                async (req, writer) => Write(writer, await Received(req))))));

        runner.Test("h3: a streamed response pulls the body through BodyReader with StreamRequestBodies", () =>
            Assert.Equal(Streamed, Answer(conn => new Nghttp3Connection(conn, new Nghttp3Options { StreamRequestBodies = true })
                .RunStreamedResponseAsync(async (req, writer) => Write(writer, await Received(req))))));

        runner.Test("h3: an asynchronous buffered handler gets the whole body without StreamRequestBodies", () =>
            Assert.Equal(Whole, Answer(conn => new Nghttp3Connection(conn).RunBufferedAsync(
                async req => Nghttp3Response.Text(await Received(req))))));

        runner.Test("h3: an asynchronous buffered handler pulls the body through BodyReader with StreamRequestBodies", () =>
            Assert.Equal(Streamed, Answer(conn => new Nghttp3Connection(conn, new Nghttp3Options { StreamRequestBodies = true })
                .RunBufferedAsync(async req => Nghttp3Response.Text(await Received(req))))));

        runner.Test("h3: a synchronous handler gets the whole body even with StreamRequestBodies", () =>
            Assert.Equal(Whole, Answer(conn => new Nghttp3Connection(conn, new Nghttp3Options { StreamRequestBodies = true })
                .RunBufferedAsync(req => Nghttp3Response.Text(ReceivedSynchronously(req.Body, req.BodyReader is not null))))));
    }

    private static void RegisterManaged(Runner runner)
    {
        runner.Test("http3: a streamed response gets the whole body without StreamRequestBodies", () =>
            Assert.Equal(Whole, Answer(conn => new Http3Connection(conn).RunStreamedResponseAsync(
                async (req, writer) => Write(writer, await Received(req))))));

        runner.Test("http3: a streamed response pulls the body through BodyReader with StreamRequestBodies", () =>
            Assert.Equal(Streamed, Answer(conn => new Http3Connection(conn, new Http3Options { StreamRequestBodies = true })
                .RunStreamedResponseAsync(async (req, writer) => Write(writer, await Received(req))))));

        runner.Test("http3: an asynchronous buffered handler gets the whole body without StreamRequestBodies", () =>
            Assert.Equal(Whole, Answer(conn => new Http3Connection(conn).RunBufferedAsync(
                async req => Http3Response.Text(await Received(req))))));

        runner.Test("http3: an asynchronous buffered handler pulls the body through BodyReader with StreamRequestBodies", () =>
            Assert.Equal(Streamed, Answer(conn => new Http3Connection(conn, new Http3Options { StreamRequestBodies = true })
                .RunBufferedAsync(async req => Http3Response.Text(await Received(req))))));

        runner.Test("http3: a synchronous handler gets the whole body even with StreamRequestBodies", () =>
            Assert.Equal(Whole, Answer(conn => new Http3Connection(conn, new Http3Options { StreamRequestBodies = true })
                .RunBufferedAsync(req => Http3Response.Text(ReceivedSynchronously(req.Body, req.BodyReader is not null))))));

        runner.Test("http3: a streamed response echoes the body it pulls through BodyReader", () =>
        {
            // Both directions at once, read a chunk and write a chunk: the shape the pure-C#
            // ManagedStreamedBoth sample promises, and one this stack could not serve before
            // StreamRequestBodies reached its streamed response - BodyReader was always null there.
            var upload = new byte[600_000];
            for (int i = 0; i < upload.Length; i++)
            {
                upload[i] = (byte)('a' + i % 26);
            }

            string echoed = Answer(conn => new Http3Connection(conn, new Http3Options { StreamRequestBodies = true })
                .RunStreamedResponseAsync(async (req, writer) =>
                {
                    writer.WriteHeaders(new Http3Response { Status = 200 });
                    ReadOnlyMemory<byte> chunk;
                    while (!(chunk = await req.BodyReader!.ReadAsync()).IsEmpty)
                    {
                        writer.Write(chunk.Span);
                        if ((await writer.FlushAsync()).IsCompleted)
                        {
                            return;
                        }
                    }
                }), upload);

            Assert.Equal(upload.Length, echoed.Length);
            Assert.True(echoed == Encoding.ASCII.GetString(upload), "the echo came back with the right length and the wrong bytes");
        });
    }

    /// <summary>POST the body to a server whose connections run <paramref name="serve"/>, and return its 200 answer.</summary>
    private static string Answer(Func<QuicConnection, Task> serve, byte[]? body = null)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (_, conn) => serve(conn));

        using var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");

        (int status, string text) = client.Request("POST", "/upload", body ?? Upload, timeoutMs: 15_000);
        Assert.True(status == 200, $"the upload was answered {status} '{text}'");
        return text;
    }

    private static ValueTask<string> Received(Nghttp3Request req)
        => Received(req.Body, req.BodyReader is { } reader ? reader.ReadAsync : null);

    private static ValueTask<string> Received(Http3Request req)
        => Received(req.Body, req.BodyReader is { } reader ? reader.ReadAsync : null);

    /// <summary>What an asynchronous handler was given: the whole body, or a reader it pulled to the end.</summary>
    private static async ValueTask<string> Received(ReadOnlyMemory<byte> body, Func<ValueTask<ReadOnlyMemory<byte>>>? read)
    {
        if (read is null)
        {
            return $"whole {body.Length}";
        }

        long total = 0;
        ReadOnlyMemory<byte> chunk;
        while (!(chunk = await read()).IsEmpty)
        {
            total += chunk.Length;
        }
        return body.IsEmpty ? $"streamed {total}" : $"streamed {total}, and a whole body of {body.Length}";
    }

    /// <summary>What a synchronous handler was given - it cannot await a reader, only see that one was set.</summary>
    private static string ReceivedSynchronously(ReadOnlyMemory<byte> body, bool reader)
        => reader ? $"a reader it cannot await, and a whole body of {body.Length}" : $"whole {body.Length}";

    private static void Write(Nghttp3ResponseWriter writer, string text)
    {
        writer.WriteHeaders(new Nghttp3Response { Status = 200 });
        writer.Write(Encoding.ASCII.GetBytes(text));
    }

    private static void Write(Http3ResponseWriter writer, string text)
    {
        writer.WriteHeaders(new Http3Response { Status = 200 });
        writer.Write(Encoding.ASCII.GetBytes(text));
    }
}
