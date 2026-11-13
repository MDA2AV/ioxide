using System.Buffers;
using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Which body a handler is handed, on both HTTP/3 stacks. A handler that takes a body reader pulls the
/// body through it - with a buffered response and a streamed one alike - and one that does not,
/// synchronous or not, gets it whole. Each handler answers with what it was given, so a body that
/// went to the wrong place fails naming where it went. Either way it is told up front whether there
/// is a body at all, which no content-length has to announce.
/// </summary>
internal static class H3BodyModeTests
{
    // Past the 256 KiB stream window, so a streamed body only arrives if it is credited mid-flight.
    private static readonly byte[] Upload = Encoding.ASCII.GetBytes(new string('u', 300_000));

    // Small enough to share a packet with its HEADERS and the fin, so it has ended by the time its
    // handler runs - which a flag read off the reader's end would take for no body.
    private static readonly byte[] Small = Encoding.ASCII.GetBytes(new string('s', 64));

    private static readonly string Whole = $"whole {Upload.Length}";
    private static readonly string Streamed = $"streamed {Upload.Length}";

    public static void Register(Runner runner)
    {
        RegisterNghttp3(runner);
        RegisterManaged(runner);
    }

    private static void RegisterNghttp3(Runner runner)
    {
        runner.Test("h3: a streamed response without a body reader gets the whole body", () =>
            Assert.Equal(Whole, Answer(conn => new Nghttp3Connection(conn).RunAsync(
                async (req, writer) => Write(writer, await Received(req.Body))))));

        runner.Test("h3: a streamed response with a body reader pulls the body through it", () =>
            Assert.Equal(Streamed, Answer(conn => new Nghttp3Connection(conn).RunAsync(
                async (req, body, writer) => Write(writer, await Received(req.Body, body.ReadAsync))))));

        runner.Test("h3: an asynchronous buffered handler without a body reader gets the whole body", () =>
            Assert.Equal(Whole, Answer(conn => new Nghttp3Connection(conn).RunAsync(
                async req => Nghttp3Response.Text(await Received(req.Body))))));

        runner.Test("h3: a buffered handler with a body reader pulls the body through it", () =>
            Assert.Equal(Streamed, Answer(conn => new Nghttp3Connection(conn).RunAsync(
                async (req, body) => Nghttp3Response.Text(await Received(req.Body, body.ReadAsync))))));

        runner.Test("h3: a synchronous handler gets the whole body", () =>
            Assert.Equal(Whole, Answer(conn => new Nghttp3Connection(conn).RunAsync(
                req => Nghttp3Response.Text($"whole {req.Body.Length}")))));

        runner.Test("h3: a handler with a body reader is told whether there is a body before it reads any", () =>
            AssertTold("streamed", conn => new Nghttp3Connection(conn).RunAsync(async (req, body, writer) =>
            {
                bool hasBody = req.HasBody;   // looked at first, as a host deciding up front does
                Write(writer, Told(hasBody, await Received(req.Body, body.ReadAsync)));
            })));

        runner.Test("h3: a handler given the whole body is told whether there was one", () =>
            AssertTold("whole", conn => new Nghttp3Connection(conn).RunAsync(
                req => Nghttp3Response.Text(Told(req.HasBody, $"whole {req.Body.Length}")))));
    }

    private static void RegisterManaged(Runner runner)
    {
        runner.Test("http3: a streamed response without a body reader gets the whole body", () =>
            Assert.Equal(Whole, Answer(conn => new Http3Connection(conn).RunAsync(
                async (req, writer) => Write(writer, await Received(req.Body))))));

        runner.Test("http3: a streamed response with a body reader pulls the body through it", () =>
            Assert.Equal(Streamed, Answer(conn => new Http3Connection(conn).RunAsync(
                async (req, body, writer) => Write(writer, await Received(req.Body, body.ReadAsync))))));

        runner.Test("http3: an asynchronous buffered handler without a body reader gets the whole body", () =>
            Assert.Equal(Whole, Answer(conn => new Http3Connection(conn).RunAsync(
                async req => Http3Response.Text(await Received(req.Body))))));

        runner.Test("http3: a buffered handler with a body reader pulls the body through it", () =>
            Assert.Equal(Streamed, Answer(conn => new Http3Connection(conn).RunAsync(
                async (req, body) => Http3Response.Text(await Received(req.Body, body.ReadAsync))))));

        runner.Test("http3: a synchronous handler gets the whole body", () =>
            Assert.Equal(Whole, Answer(conn => new Http3Connection(conn).RunAsync(
                req => Http3Response.Text($"whole {req.Body.Length}")))));

        runner.Test("http3: a streamed response echoes the body it pulls through its body reader", () =>
        {
            // Both directions at once, read a chunk and write a chunk: the shape the pure-C#
            // ManagedStreamedBoth sample promises, and one this stack could not serve before: its
            // streamed response always found a null reader on the request.
            var upload = new byte[600_000];
            for (int i = 0; i < upload.Length; i++)
            {
                upload[i] = (byte)('a' + i % 26);
            }

            string echoed = Answer(conn => new Http3Connection(conn)
                .RunAsync(async (_, body, writer) =>
                {
                    writer.WriteHeaders(new Http3Response { Status = 200 });
                    ReadOnlyMemory<byte> chunk;
                    while (!(chunk = await body.ReadAsync()).IsEmpty)
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

        runner.Test("http3: a handler with a body reader is told whether there is a body before it reads any", () =>
            AssertTold("streamed", conn => new Http3Connection(conn).RunAsync(async (req, body, writer) =>
            {
                bool hasBody = req.HasBody;   // looked at first, as a host deciding up front does
                Write(writer, Told(hasBody, await Received(req.Body, body.ReadAsync)));
            })));

        runner.Test("http3: a handler given the whole body is told whether there was one", () =>
            AssertTold("whole", conn => new Http3Connection(conn).RunAsync(
                req => Http3Response.Text(Told(req.HasBody, $"whole {req.Body.Length}")))));
    }

    /// <summary>POST the body to a server whose connections run <paramref name="serve"/>, and return its 200 answer.</summary>
    private static string Answer(Func<QuicConnection, Task> serve, byte[]? body = null)
        => Answers(serve, ("POST", body ?? Upload))[0];

    /// <summary>Send each request in turn, on one connection, to a server whose connections run <paramref name="serve"/>, and return its 200 answers.</summary>
    private static string[] Answers(Func<QuicConnection, Task> serve, params (string Method, byte[]? Body)[] requests)
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

        var answers = new string[requests.Length];
        for (int i = 0; i < requests.Length; i++)
        {
            (int status, string text) = client.Request(requests[i].Method, "/upload", requests[i].Body, timeoutMs: 15_000);
            Assert.True(status == 200, $"the {(requests[i].Body is null ? "GET" : "upload")} was answered {status} '{text}'");
            answers[i] = text;
        }
        return answers;
    }

    /// <summary>
    /// What a handler was told about its body before reading any, for each request a host has to
    /// tell apart: a GET whose fin came with its HEADERS, a small upload that ended in the same packet,
    /// and a large one still arriving when its handler runs. None of them carries a content-length,
    /// which is what a host had to go on before - and what would call both uploads bodyless.
    /// </summary>
    private static void AssertTold(string given, Func<QuicConnection, Task> serve)
    {
        string[] answers = Answers(serve, ("GET", null), ("POST", Small), ("POST", Upload));

        Assert.True(answers[0] == $"no body, {given} 0", $"a GET whose fin came with its HEADERS was told '{answers[0]}'");
        Assert.True(answers[1] == $"a body, {given} {Small.Length}", $"an upload that ended with its HEADERS was told '{answers[1]}'");
        Assert.True(answers[2] == $"a body, {given} {Upload.Length}", $"an upload still arriving at dispatch was told '{answers[2]}'");
    }

    private static string Told(bool hasBody, string received) => $"{(hasBody ? "a body" : "no body")}, {received}";

    /// <summary>What an asynchronous handler was given: the whole body, or a reader it pulled to the end.</summary>
    private static async ValueTask<string> Received(ReadOnlyMemory<byte> body, Func<ValueTask<ReadOnlyMemory<byte>>>? read = null)
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
