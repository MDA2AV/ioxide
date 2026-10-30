using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using ioxide;
using ioxide.http2;
using ioxide.http3;
using ioxide.nghttp2;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A handler that has left its reactor still reads its request body and writes its response, on all
/// four HTTP/2 and HTTP/3 stacks (#441), and the stack still finishes the request on the reactor
/// however the handler ended. Leaving takes nothing exotic: an await on anything another thread
/// completes - Task.Run, a BCL client - resumes on that thread.
///
/// Each handler moves to the pool before every call and counts where each call was made, so a run
/// that never left the reactor cannot pass. On HTTP/2 the transport is wrapped
/// to count writes that reach it from off the reactor; on HTTP/3 one aborts the process inside
/// ngtcp2 (<c>conn->log.last_ts &lt;= ts</c>).
/// </summary>
internal static class OffReactorStreamTests
{
    // Past the initial windows on every stack, so the body arrives only if reads credit it mid-flight.
    private static readonly byte[] Upload = Pattern(1024 * 1024);

    public static void Register(Runner runner)
    {
        runner.Test("h2 off-reactor (http2): an upload read and echoed from the thread pool arrives whole", () =>
            AssertH2Echo((pipe, calls) => new Http2Connection(pipe).RunAsync((_, body, writer) =>
                Echo(calls, body.ReadAsync, () => writer.WriteHeaders(new Http2Response { Status = 200 }), writer, writer.FlushAsync))));

        runner.Test("h2 off-reactor (nghttp2): an upload read and echoed from the thread pool arrives whole", () =>
            AssertH2Echo((pipe, calls) => new Nghttp2Connection(pipe).RunAsync((_, body, writer) =>
                Echo(calls, body.ReadAsync, () => writer.WriteHeaders(new Nghttp2Response { Status = 200 }), writer, writer.FlushAsync))));

        runner.Test("h3 off-reactor (nghttp3): an upload read and echoed from the thread pool arrives whole", () =>
            AssertH3Echo((conn, calls) => new Nghttp3Connection(conn).RunAsync((_, body, writer) =>
                Echo(calls, body.ReadAsync, () => writer.WriteHeaders(new Nghttp3Response { Status = 200 }), writer, writer.FlushAsync))));

        runner.Test("h3 off-reactor (http3): an upload read and echoed from the thread pool arrives whole", () =>
            AssertH3Echo((conn, calls) => new Http3Connection(conn).RunAsync((_, body, writer) =>
                Echo(calls, body.ReadAsync, () => writer.WriteHeaders(new Http3Response { Status = 200 }), writer, writer.FlushAsync))));

        // Headers written off the reactor wait for a flush that runs on it; a handler that returns
        // without one leaves them to the completion, which must still send them.
        runner.Test("h2 off-reactor (http2): headers written from the thread pool with no body and no flush arrive", () =>
            AssertH2Accepted((pipe, calls) => new Http2Connection(pipe).RunAsync(async (_, writer) =>
            {
                await LeaveReactor();
                calls.Note();
                writer.WriteHeaders(new Http2Response { Status = 202 });
            })));

        runner.Test("h2 off-reactor (nghttp2): headers written from the thread pool with no body and no flush arrive", () =>
            AssertH2Accepted((pipe, calls) => new Nghttp2Connection(pipe).RunAsync(async (_, writer) =>
            {
                await LeaveReactor();
                calls.Note();
                writer.WriteHeaders(new Nghttp2Response { Status = 202 });
            })));

        runner.Test("h3 off-reactor (nghttp3): headers written from the thread pool with no body and no flush arrive", () =>
            AssertH3Accepted((conn, calls) => new Nghttp3Connection(conn).RunAsync(async (_, writer) =>
            {
                await LeaveReactor();
                calls.Note();
                writer.WriteHeaders(new Nghttp3Response { Status = 202 });
            })));

        runner.Test("h3 off-reactor (http3): headers written from the thread pool with no body and no flush arrive", () =>
            AssertH3Accepted((conn, calls) => new Http3Connection(conn).RunAsync(async (_, writer) =>
            {
                await LeaveReactor();
                calls.Note();
                writer.WriteHeaders(new Http3Response { Status = 202 });
            })));

        // A whole response, returned from the pool: the stack sends it, which is connection work.
        runner.Test("h2 off-reactor (http2): a whole response returned from the thread pool is sent from the reactor", () =>
            AssertH2Accepted((pipe, calls) => new Http2Connection(pipe).RunAsync(_ =>
                AcceptFromPool(calls, new Http2Response { Status = 202 }))));

        runner.Test("h2 off-reactor (nghttp2): a whole response returned from the thread pool is sent from the reactor", () =>
            AssertH2Accepted((pipe, calls) => new Nghttp2Connection(pipe).RunAsync(_ =>
                AcceptFromPool(calls, new Nghttp2Response { Status = 202 }))));

        runner.Test("h3 off-reactor (nghttp3): a whole response returned from the thread pool is sent from the reactor", () =>
            AssertH3Accepted((conn, calls) => new Nghttp3Connection(conn).RunAsync(_ =>
                AcceptFromPool(calls, new Nghttp3Response { Status = 202 }))));

        runner.Test("h3 off-reactor (http3): a whole response returned from the thread pool is sent from the reactor", () =>
            AssertH3Accepted((conn, calls) => new Http3Connection(conn).RunAsync(_ =>
                AcceptFromPool(calls, new Http3Response { Status = 202 }))));

        runner.Test("h2 off-reactor (http2): a body read and a whole response returned from the thread pool", () =>
            AssertH2Accepted((pipe, calls) => new Http2Connection(pipe).RunAsync((Http2Request _, Http2BodyReader body) =>
                DrainThenAccept(calls, body.ReadAsync, new Http2Response { Status = 202 })), Upload));

        runner.Test("h2 off-reactor (nghttp2): a body read and a whole response returned from the thread pool", () =>
            AssertH2Accepted((pipe, calls) => new Nghttp2Connection(pipe).RunAsync((Nghttp2Request _, Nghttp2BodyReader body) =>
                DrainThenAccept(calls, body.ReadAsync, new Nghttp2Response { Status = 202 })), Upload));

        runner.Test("h3 off-reactor (nghttp3): a body read and a whole response returned from the thread pool", () =>
            AssertH3Accepted((conn, calls) => new Nghttp3Connection(conn).RunAsync((Nghttp3Request _, Nghttp3BodyReader body) =>
                DrainThenAccept(calls, body.ReadAsync, new Nghttp3Response { Status = 202 })), Upload));

        runner.Test("h3 off-reactor (http3): a body read and a whole response returned from the thread pool", () =>
            AssertH3Accepted((conn, calls) => new Http3Connection(conn).RunAsync((Http3Request _, Http3BodyReader body) =>
                DrainThenAccept(calls, body.ReadAsync, new Http3Response { Status = 202 })), Upload));

        // The stack catches what the handler throws and resets the stream: that is connection work,
        // and the handler threw from the pool.
        runner.Test("h2 off-reactor (http2): a handler that throws from the thread pool is reset from the reactor, and the connection serves on", () =>
            AssertH2Throws((pipe, calls) => new Http2Connection(pipe).RunAsync((_, writer) =>
                ThrowFirst(calls, status => writer.WriteHeaders(new Http2Response { Status = status })))));

        runner.Test("h2 off-reactor (nghttp2): a handler that throws from the thread pool is reset from the reactor, and the connection serves on", () =>
            AssertH2Throws((pipe, calls) => new Nghttp2Connection(pipe).RunAsync((_, writer) =>
                ThrowFirst(calls, status => writer.WriteHeaders(new Nghttp2Response { Status = status })))));

        runner.Test("h3 off-reactor (nghttp3): a handler that throws from the thread pool is reset from the reactor, and the connection serves on", () =>
            AssertH3Throws((conn, calls) => new Nghttp3Connection(conn).RunAsync((_, writer) =>
                ThrowFirst(calls, status => writer.WriteHeaders(new Nghttp3Response { Status = status })))));

        runner.Test("h3 off-reactor (http3): a handler that throws from the thread pool is reset from the reactor, and the connection serves on", () =>
            AssertH3Throws((conn, calls) => new Http3Connection(conn).RunAsync((_, writer) =>
                ThrowFirst(calls, status => writer.WriteHeaders(new Http3Response { Status = status })))));
    }

    /// <summary>
    /// Echo the body chunk by chunk, every call made from the pool: each call completes on the
    /// reactor and resumes the loop there, so the loop leaves again before the next.
    /// </summary>
    private static async ValueTask Echo(Calls calls, Func<ValueTask<ReadOnlyMemory<byte>>> read, Action writeHeaders,
        IBufferWriter<byte> writer, Func<ValueTask<FlushResult>> flush)
    {
        await LeaveReactor();
        calls.Note();
        writeHeaders();

        while (true)
        {
            await LeaveReactor();
            calls.Note();
            ReadOnlyMemory<byte> chunk = await read();
            if (chunk.IsEmpty)
            {
                return;
            }

            await LeaveReactor();
            calls.Note();
            writer.Write(chunk.Span);
            if ((await flush()).IsCompleted)
            {
                return;
            }
        }
    }

    private static async ValueTask<T> AcceptFromPool<T>(Calls calls, T accepted)
    {
        await LeaveReactor();
        calls.Note();
        return accepted;
    }

    // Reads the whole body, every read made from the pool, then answers from there.
    private static async ValueTask<T> DrainThenAccept<T>(Calls calls, Func<ValueTask<ReadOnlyMemory<byte>>> read, T accepted)
    {
        while (true)
        {
            await LeaveReactor();
            calls.Note();
            if ((await read()).IsEmpty)
            {
                break;
            }
        }
        return await AcceptFromPool(calls, accepted);
    }

    // The first request throws from the pool, after its headers; the next is answered normally.
    private static async ValueTask ThrowFirst(Calls calls, Action<int> writeHeaders)
    {
        await LeaveReactor();
        calls.Note();
        if (Interlocked.Increment(ref calls.Requests) == 1)
        {
            writeHeaders(200);
            throw new InvalidOperationException("a handler failed off the reactor");
        }
        writeHeaders(202);
    }

    private static ConfiguredTaskAwaitable LeaveReactor() => Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);

    /// <summary>Where the handler's calls were made, set by the server and read by the test.</summary>
    private sealed class Calls
    {
        public Reactor? Reactor;
        public int Requests;
        public int QuicCallsOff;
        private int _on;
        private int _off;

        public void Note()
        {
            if (Reactor!.OnReactorThread)
            {
                Interlocked.Increment(ref _on);
            }
            else
            {
                Interlocked.Increment(ref _off);
            }
        }

        public void AssertAllOff()
        {
            Assert.True(Volatile.Read(ref _off) > 0, $"the handler left the reactor ({_off} calls off it)");
            Assert.True(Volatile.Read(ref _on) == 0, $"every handler call was made off the reactor ({_on} on it)");
        }
    }

    // ---- HTTP/2 -------------------------------------------------------------------------------

    private static void AssertH2Echo(Func<IDuplexPipe, Calls, Task> serve)
    {
        (int port, Calls calls, OffReactorWrites writes) = StartH2(serve);

        using HttpClient client = H2Client();
        Task<byte[]> echoed = SendAsync(client, port, Upload, HttpStatusCode.OK);
        Assert.True(echoed.Wait(60_000), "the echo completed");

        Assert.True(echoed.Result.AsSpan().SequenceEqual(Upload),
            $"the echo came back whole: {echoed.Result.Length} of {Upload.Length} bytes, first difference at {FirstDifference(Upload, echoed.Result)}");
        calls.AssertAllOff();
        writes.AssertNone();
    }

    private static void AssertH2Accepted(Func<IDuplexPipe, Calls, Task> serve, byte[]? upload = null)
    {
        (int port, Calls calls, OffReactorWrites writes) = StartH2(serve);

        using HttpClient client = H2Client();
        Task<byte[]> response = SendAsync(client, port, upload, HttpStatusCode.Accepted);
        Assert.True(response.Wait(30_000), "the response completed");

        Assert.Equal(0, response.Result.Length);
        calls.AssertAllOff();
        writes.AssertNone();
    }

    private static void AssertH2Throws(Func<IDuplexPipe, Calls, Task> serve)
    {
        (int port, Calls calls, OffReactorWrites writes) = StartH2(serve);

        using HttpClient client = H2Client();
        Task<byte[]> failed = SendAsync(client, port, body: null, HttpStatusCode.OK);
        Assert.True(SpinWait.SpinUntil(() => failed.IsCompleted, 30_000), "the failed request ended");
        Assert.True(failed.IsFaulted, "the failed request was reset rather than answered");

        Task<byte[]> next = SendAsync(client, port, body: null, HttpStatusCode.Accepted);
        Assert.True(next.Wait(30_000), "the next request completed");
        calls.AssertAllOff();
        writes.AssertNone();
    }

    private static (int Port, Calls Calls, OffReactorWrites Writes) StartH2(Func<IDuplexPipe, Calls, Task> serve)
    {
        var calls = new Calls();
        var writes = new OffReactorWrites();

        int port = TestServer.Start(async (reactor, conn) =>
        {
            calls.Reactor = reactor;
            try
            {
                await serve(writes.Wrap(new TcpConnectionDualPipe(conn), reactor), calls);
            }
            finally
            {
                conn.DecRef();
            }
        });

        return (port, calls, writes);
    }

    /// <summary>
    /// Counts what reaches the connection's transport from off its reactor. The connection's frames,
    /// window updates and flushes are the reactor's to write, so with the reader and writer
    /// marshalling their calls there, nothing should.
    /// </summary>
    private sealed class OffReactorWrites
    {
        private int _count;

        public IDuplexPipe Wrap(IDuplexPipe inner, Reactor reactor) => new Pipe(inner, new Writer(inner.Output, reactor, this));

        public void AssertNone() =>
            Assert.True(Volatile.Read(ref _count) == 0, $"the transport was only written from its reactor ({_count} writes from elsewhere)");

        private sealed class Pipe(IDuplexPipe inner, PipeWriter output) : IDuplexPipe
        {
            public PipeReader Input => inner.Input;
            public PipeWriter Output => output;
        }

        private sealed class Writer(PipeWriter inner, Reactor reactor, OffReactorWrites owner) : PipeWriter
        {
            public override Span<byte> GetSpan(int sizeHint = 0)
            {
                Note();
                return inner.GetSpan(sizeHint);
            }

            public override Memory<byte> GetMemory(int sizeHint = 0)
            {
                Note();
                return inner.GetMemory(sizeHint);
            }

            public override void Advance(int bytes)
            {
                Note();
                inner.Advance(bytes);
            }

            public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
            {
                Note();
                return inner.FlushAsync(cancellationToken);
            }

            public override void CancelPendingFlush() => inner.CancelPendingFlush();
            public override void Complete(Exception? exception = null) => inner.Complete(exception);

            private void Note()
            {
                if (!reactor.OnReactorThread)
                {
                    Interlocked.Increment(ref owner._count);
                }
            }
        }
    }

    // Cleartext HTTP/2 with prior knowledge, as an h2c peer sends it.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(60),
    };

    private static async Task<byte[]> SendAsync(HttpClient client, int port, byte[]? body, HttpStatusCode expected)
    {
        string url = $"http://127.0.0.1:{port}/";
        using HttpResponseMessage response = body is null
            ? await client.GetAsync(url)
            : await client.PostAsync(url, new DuplexContent(body));
        Assert.Equal(expected, response.StatusCode);
        return await response.Content.ReadAsByteArrayAsync();
    }

    // ByteArrayContent is not duplex: HttpClient sends all of it before reading any of the response, so
    // an echo past the client's receive window stalls against a server that applies backpressure.
    private sealed class DuplexContent(byte[] bytes) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(bytes).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            length = bytes.Length;
            return true;
        }
    }

    // ---- HTTP/3 -------------------------------------------------------------------------------

    private static void AssertH3Echo(Func<QuicConnection, Calls, Task> serve)
    {
        (int status, string text, Calls calls) = H3Send(serve, Upload);
        Assert.Equal(200, status);
        Assert.True(text == Encoding.ASCII.GetString(Upload),
            $"the echo came back whole: {text.Length} of {Upload.Length} bytes");
        calls.AssertAllOff();
        AssertQuicOnReactor(calls);
    }

    private static void AssertH3Accepted(Func<QuicConnection, Calls, Task> serve, byte[]? upload = null)
    {
        (int status, string text, Calls calls) = H3Send(serve, upload);
        Assert.Equal(202, status);
        Assert.Equal(0, text.Length);
        calls.AssertAllOff();
        AssertQuicOnReactor(calls);
    }

    private static void AssertQuicOnReactor(Calls calls) =>
        Assert.True(Volatile.Read(ref calls.QuicCallsOff) == 0,
            $"the QUIC connection was only called from its reactor ({calls.QuicCallsOff} calls from elsewhere)");

    private static void AssertH3Throws(Func<QuicConnection, Calls, Task> serve)
    {
        (H3TestClient client, Calls calls) = H3Connect(serve);
        using (client)
        {
            (int failed, _) = client.Request("GET", "/", null, timeoutMs: 5_000);
            Assert.True(failed != 200, $"the failed request was reset rather than answered ({failed})");

            (int status, string text) = client.Request("GET", "/", null, timeoutMs: 30_000);
            Assert.Equal(202, status);
            Assert.Equal(0, text.Length);
        }
        calls.AssertAllOff();
        AssertQuicOnReactor(calls);
    }

    private static (int Status, string Text, Calls Calls) H3Send(Func<QuicConnection, Calls, Task> serve, byte[]? body)
    {
        (H3TestClient client, Calls calls) = H3Connect(serve);
        using (client)
        {
            (int status, string text) = client.Request(body is null ? "GET" : "POST", "/", body, timeoutMs: 30_000);
            return (status, text, calls);
        }
    }

    private static (H3TestClient Client, Calls Calls) H3Connect(Func<QuicConnection, Calls, Task> serve)
    {
        var calls = new Calls();
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(_ => new CountingQuic(engine, calls)),
            quicHandle: (reactor, conn) =>
            {
                calls.Reactor = reactor;
                return serve(conn, calls);
            });

        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return (client, calls);
    }

    /// <summary>
    /// Counts calls into the QUIC connection from off its reactor. ngtcp2's state is the reactor's,
    /// so with the stacks making their calls there, nothing should.
    /// </summary>
    private sealed class CountingQuic(QuicEngine engine, Calls calls) : QuicEngineConnection(engine)
    {
        public override void SendStream(long streamId, ReadOnlySpan<byte> data, bool fin)
        {
            Note();
            base.SendStream(streamId, data, fin);
        }

        public override void ResetStream(long streamId, ulong applicationErrorCode)
        {
            Note();
            base.ResetStream(streamId, applicationErrorCode);
        }

        public override void ConsumeStreamData(long streamId, long bytes)
        {
            Note();
            base.ConsumeStreamData(streamId, bytes);
        }

        public override void SetStreamPaced(long streamId, bool paced)
        {
            Note();
            base.SetStreamPaced(streamId, paced);
        }

        public override void Close(ulong applicationErrorCode)
        {
            Note();
            base.Close(applicationErrorCode);
        }

        private void Note()
        {
            if (!Reactor.OnReactorThread)
            {
                Interlocked.Increment(ref calls.QuicCallsOff);
            }
        }
    }

    // ---- shared -------------------------------------------------------------------------------

    // ASCII and position-dependent, so the HTTP/3 client's text compares and a reordered echo fails.
    private static byte[] Pattern(int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)('a' + ((i * 7) + (i >> 10)) % 26);
        }
        return bytes;
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
}
