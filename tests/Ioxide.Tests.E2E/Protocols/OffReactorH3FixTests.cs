using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;
using static Ioxide.Tests.H3ErrorCodeTests;

namespace Ioxide.Tests;

/// <summary>
/// Three review findings on the HTTP/3 stacks' off-reactor paths (#441), each on every stack it
/// applies to. Headers written off the reactor are copied before WriteHeaders returns, since the
/// caller may reuse their memories at once. nghttp3 sends what is submitted outside its dispatch
/// pass. A connection no reactor owns, as a test driver runs one, counts as on its reactor.
/// </summary>
internal static class OffReactorH3FixTests
{
    // GET and POST / with "abc", framed by hand: static :method, :scheme https and :path /, and a
    // literal :authority, since nghttp3 refuses an empty one.
    private static readonly byte[] Get = [0x01, 0x10, 0x00, 0x00, 0xD1, 0xD7, 0xC1, 0x50, 0x09, .. "localhost"u8];
    private static readonly byte[] PostAbc = [0x01, 0x10, 0x00, 0x00, 0xD4, 0xD7, 0xC1, 0x50, 0x09, .. "localhost"u8, 0x00, 0x03, .. "abc"u8];

    // The :status line after the field section's prefix: static index 25 (200) and 71 (500).
    private static readonly byte[] Status200 = [0xD9];
    private static readonly byte[] Status500 = [0xFF, 0x08];

    public static void Register(Runner runner)
    {
        // The handler overwrites the header's buffers as soon as WriteHeaders returns, as a pool
        // handing them to the next renter would.
        runner.Test("h3 off-reactor (http3): headers written from the thread pool go out as written, though the caller reuses their memory", () =>
            AssertWrittenHeader((conn, calls) => new Http3Connection(conn).RunAsync((Http3Request request, Http3ResponseWriter writer) =>
                WriteThenReuse(calls, request.Path.Span.SequenceEqual("/flush"u8), (name, value) =>
                {
                    var response = new Http3Response { Status = 200 };
                    response.Headers.Add((name, value));
                    writer.WriteHeaders(response);
                }, writer, writer.FlushAsync))));

        runner.Test("h3 off-reactor (nghttp3): headers written from the thread pool go out as written, though the caller reuses their memory", () =>
            AssertWrittenHeader((conn, calls) => new Nghttp3Connection(conn).RunAsync((Nghttp3Request request, Nghttp3ResponseWriter writer) =>
                WriteThenReuse(calls, request.Path.Span.SequenceEqual("/flush"u8), (name, value) =>
                {
                    var response = new Nghttp3Response { Status = 200 };
                    response.Headers.Add(name, value);
                    writer.WriteHeaders(response);
                }, writer, writer.FlushAsync))));

        // nghttp3 holds what is submitted until something pumps it, and outside the dispatch pass
        // only the submitter is there to.
        runner.Test("h3 off-reactor (nghttp3): a handler that throws from the thread pool before its headers is answered 500", () =>
        {
            var calls = new Calls();
            using H3TestClient client = H3Connect(conn => new Nghttp3Connection(conn).RunAsync(async (Nghttp3Request _, Nghttp3ResponseWriter _) =>
            {
                await LeaveReactor();
                calls.Note();
                throw new InvalidOperationException("a handler failed off the reactor before its headers");
            }));

            (int status, _) = client.Request("GET", "/", null, timeoutMs: 5_000);
            Assert.True(status == 500, $"the request was answered 500 within 5 s, got {status}");
            calls.AssertAllOff();
        });

        runner.Test("h3 off-reactor (nghttp3): an empty flush from the thread pool sends the headers written before it", () =>
        {
            var calls = new Calls();
            long sentByFlush = -1;
            using H3TestClient client = H3Connect(conn => new Nghttp3Connection(conn).RunAsync(async (Nghttp3Request _, Nghttp3ResponseWriter writer) =>
            {
                await LeaveReactor();
                calls.Note();
                writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                await writer.FlushAsync();
                Volatile.Write(ref sentByFlush, ((TallyQuic)conn).SentOn(writer.StreamId));
                writer.Write("body"u8);
            }));

            (int status, string body) = client.Request("GET", "/", null, timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.Equal("body", body);
            Assert.True(Volatile.Read(ref sentByFlush) > 0,
                $"the empty flush handed the headers to QUIC before it returned ({sentByFlush} bytes on the stream)");
            calls.AssertAllOff();
        });

        runner.Test("h3 later pass (nghttp3): an empty flush on the reactor sends the headers written before it", () =>
        {
            long sentByFlush = -1;
            using H3TestClient client = H3Connect(conn => new Nghttp3Connection(conn).RunAsync(async (Nghttp3Request _, Nghttp3ResponseWriter writer) =>
            {
                await TestServer.LaterPass();   // on the reactor, outside the pass that dispatched it
                writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                await writer.FlushAsync();
                Volatile.Write(ref sentByFlush, ((TallyQuic)conn).SentOn(writer.StreamId));
                writer.Write("body"u8);
            }));

            (int status, string body) = client.Request("GET", "/", null, timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.Equal("body", body);
            Assert.True(Volatile.Read(ref sentByFlush) > 0,
                $"the empty flush handed the headers to QUIC before it returned ({sentByFlush} bytes on the stream)");
        });

        // The transport is a recording fake its test drives inline, with no reactor behind it.
        runner.Test("h3 no reactor (http3): a streamed handler reads its body and writes its headers", () =>
            AssertServedInline(PostAbc, Status200, "abc", quic => new Http3Connection(quic).RunAsync(
                (Http3Request _, Http3BodyReader body, Http3ResponseWriter writer) =>
                    ReadThenEcho(body.ReadAsync, () => writer.WriteHeaders(new Http3Response { Status = 200 }), writer))));

        runner.Test("h3 no reactor (nghttp3): a streamed handler reads its body and writes its headers", () =>
            AssertServedInline(PostAbc, Status200, "abc", quic => new Nghttp3Connection(quic).RunAsync(
                (Nghttp3Request _, Nghttp3BodyReader body, Nghttp3ResponseWriter writer) =>
                    ReadThenEcho(body.ReadAsync, () => writer.WriteHeaders(new Nghttp3Response { Status = 200 }), writer))));

        runner.Test("h3 no reactor (http3): a streamed handler that writes nothing is answered 500", () =>
            AssertServedInline(Get, Status500, "", quic => new Http3Connection(quic).RunAsync(
                (Http3Request _, Http3ResponseWriter _) => ValueTask.CompletedTask)));

        runner.Test("h3 no reactor (nghttp3): a streamed handler that writes nothing is answered 500", () =>
            AssertServedInline(Get, Status500, "", quic => new Nghttp3Connection(quic).RunAsync(
                (Nghttp3Request _, Nghttp3ResponseWriter _) => ValueTask.CompletedTask)));
    }

    // Headers from buffers overwritten as soon as WriteHeaders returns, with every call made from the
    // pool. A flush sends them with the body, or the completion does.
    private static async ValueTask WriteThenReuse(Calls calls, bool flush, Action<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> writeHeaders,
        IBufferWriter<byte> writer, Func<ValueTask<FlushResult>> flushAsync)
    {
        await LeaveReactor();
        calls.Note();
        byte[] name = "x-probe"u8.ToArray();
        byte[] value = "first"u8.ToArray();
        writeHeaders(name, value);
        "x-wrong"u8.CopyTo(name);
        "SECND"u8.CopyTo(value);

        writer.Write("body"u8);
        if (flush)
        {
            await flushAsync();
        }
    }

    private static void AssertWrittenHeader(Func<QuicConnection, Calls, Task> serve)
    {
        var calls = new Calls();
        using H3TestClient client = H3Connect(conn => serve(conn, calls));

        foreach (string path in new[] { "/flush", "/complete" })
        {
            (int status, string body) = client.Request("GET", path, null, timeoutMs: 30_000);
            Assert.Equal(200, status);
            Assert.Equal("body", body);

            string got = string.Join(", ", client.ResponseHeaders.Select(h => $"{h.Name}: {h.Value}"));
            Assert.True(client.ResponseHeaders.Contains(("x-probe", "first")),
                $"{path}: the header went out as written (x-probe: first), got [{got}]");
        }
        calls.AssertAllOff();
    }

    private static async ValueTask ReadThenEcho(Func<ValueTask<ReadOnlyMemory<byte>>> read, Action writeHeaders, IBufferWriter<byte> writer)
    {
        var received = new ArrayBufferWriter<byte>();
        while (true)
        {
            ReadOnlyMemory<byte> chunk = await read();
            if (chunk.IsEmpty)
            {
                break;
            }
            received.Write(chunk.Span);
        }

        writeHeaders();
        writer.Write(received.WrittenSpan);
    }

    /// <summary>
    /// Serve one request through the recording fake, whose awaits all complete inline, then close it
    /// and read the response off what the stack sent on the request stream.
    /// </summary>
    private static void AssertServedInline(byte[] request, byte[] status, string body, Func<RecordingQuic, Task> serve)
    {
        var quic = new RecordingQuic();
        Assert.True(quic.EnqueueStreamData(0, request, true), "the recv ring rejected the request");
        Task run = serve(quic);
        quic.MarkClosed();
        Assert.True(run.IsCompleted, "the run loop ended once the transport closed");

        Assert.True(quic.Resets.Count == 0,
            $"the stream was answered, not reset (0x{quic.Resets.FirstOrDefault().Code:x})");
        List<(long StreamId, byte[] Bytes, bool Fin)> sent = [.. quic.Sent.Where(s => s.StreamId == 0)];
        Assert.True(sent.Count > 0 && sent[^1].Fin, $"the response was sent and ended ({sent.Count} sends on the stream)");

        byte[] stream = [.. sent.SelectMany(s => s.Bytes)];
        byte[]? fields = null;
        var data = new List<byte>();
        for (int at = 0; at < stream.Length;)
        {
            long type = ReadVarint(stream, ref at);
            int length = (int)ReadVarint(stream, ref at);
            if (type == 0x01)
            {
                fields ??= stream[at..(at + length)];
            }
            else if (type == 0x00)
            {
                data.AddRange(stream[at..(at + length)]);
            }
            at += length;
        }

        Assert.True(fields is not null && fields.AsSpan(2).StartsWith(status),
            $"the HEADERS carried :status as [{Convert.ToHexString(status)}], got [{(fields is null ? "no HEADERS" : Convert.ToHexString(fields))}]");
        Assert.Equal(body, Encoding.ASCII.GetString(data.ToArray()));
    }

    private static long ReadVarint(byte[] bytes, ref int at)
    {
        int length = 1 << (bytes[at] >> 6);
        long value = bytes[at] & 0x3F;
        for (int i = 1; i < length; i++)
        {
            value = (value << 8) | bytes[at + i];
        }
        at += length;
        return value;
    }

    private static ConfiguredTaskAwaitable LeaveReactor() => Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);

    /// <summary>Whether the handler's calls were made off the reactor, so a run that never left cannot pass.</summary>
    private sealed class Calls
    {
        private int _on;
        private int _off;

        public void Note() => Interlocked.Increment(ref (Reactor.Current == null ? ref _off : ref _on));

        public void AssertAllOff() =>
            Assert.True(Volatile.Read(ref _off) > 0 && Volatile.Read(ref _on) == 0,
                $"every handler call was made off the reactor ({_off} off, {_on} on)");
    }

    private static H3TestClient H3Connect(Func<QuicConnection, Task> serve)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(_ => new TallyQuic(engine)),
            quicHandle: (_, conn) => serve(conn));

        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;
    }

    /// <summary>Counts the stream bytes handed to QUIC, per stream.</summary>
    private sealed class TallyQuic(QuicEngine engine) : QuicEngineConnection(engine)
    {
        private readonly Dictionary<long, long> _sent = [];

        public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin)
        {
            lock (_sent)
            {
                _sent[streamId] = _sent.GetValueOrDefault(streamId) + data.Length;
            }
            base.SendStream(streamId, data, fin);
        }

        public long SentOn(long streamId)
        {
            lock (_sent)
            {
                return _sent.GetValueOrDefault(streamId);
            }
        }
    }
}
