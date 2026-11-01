using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.CompilerServices;
using ioxide;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// Three ways an HTTP/2 connection still lost its reactor after #441, each on both stacks: headers a
/// handler wrote off the reactor went out later, read from memory it had already reused; a pipe that
/// completes on the thread pool took the read loop and the write pump there; and a RunAsync begun off
/// the reactor never learned it, so nothing the handler called was marshalled.
/// </summary>
internal static class OffReactorH2FixTests
{
    // Past the initial windows on both stacks, so the body arrives only if credit flows mid-flight.
    private static readonly byte[] Upload = Pattern(1024 * 1024);

    public static void Register(Runner runner)
    {
        // A response's memories may be pooled or static: the caller reuses them once WriteHeaders returns.
        runner.Test("h2 off-reactor (http2): headers written from the thread pool go out as written, though the caller reuses their memory at once", () =>
            AssertHeadersKept((pipe, calls) => new Http2Connection(pipe).RunAsync((_, writer) =>
                WriteThenReuse(calls, (name, value) =>
                {
                    var response = new Http2Response { Status = 200 };
                    response.Headers.Add(name, value);
                    writer.WriteHeaders(response);
                }, writer, writer.FlushAsync))));

        runner.Test("h2 off-reactor (nghttp2): headers written from the thread pool go out as written, though the caller reuses their memory at once", () =>
            AssertHeadersKept((pipe, calls) => new Nghttp2Connection(pipe).RunAsync((_, writer) =>
                WriteThenReuse(calls, (name, value) =>
                {
                    var response = new Nghttp2Response { Status = 200 };
                    response.Headers.Add(name, value);
                    writer.WriteHeaders(response);
                }, writer, writer.FlushAsync))));

        // A default Pipe completes a read, and a flush it held back, on the thread pool.
        runner.Test("h2 over a pipe that completes on the thread pool (http2): an upload is echoed whole, read, answered and written on the reactor", () =>
            AssertPoolPipe((pipe, calls) => new Http2Connection(pipe).RunAsync(request =>
            {
                calls.Note();
                return new Http2Response { Status = 200, Body = request.Body.ToArray() };
            })));

        runner.Test("h2 over a pipe that completes on the thread pool (nghttp2): an upload is echoed whole, read, answered and written on the reactor", () =>
            AssertPoolPipe((pipe, calls) => new Nghttp2Connection(pipe).RunAsync(request =>
            {
                calls.Note();
                return new Nghttp2Response { Status = 200, Body = request.Body.ToArray() };
            })));

        // A connection handler that awaited something another thread completed calls RunAsync from there.
        runner.Test("h2 RunAsync begun on the thread pool (http2): an upload read and echoed from the pool arrives whole, served on the reactor", () =>
            AssertLateStart((pipe, calls) => new Http2Connection(pipe).RunAsync((_, body, writer) =>
                Echo(calls, body.ReadAsync, () => writer.WriteHeaders(new Http2Response { Status = 200 }), writer, writer.FlushAsync))));

        runner.Test("h2 RunAsync begun on the thread pool (nghttp2): an upload read and echoed from the pool arrives whole, served on the reactor", () =>
            AssertLateStart((pipe, calls) => new Nghttp2Connection(pipe).RunAsync((_, body, writer) =>
                Echo(calls, body.ReadAsync, () => writer.WriteHeaders(new Nghttp2Response { Status = 200 }), writer, writer.FlushAsync))));
    }

    // Headers from the pool, their memory overwritten the moment WriteHeaders returns, then a body.
    private static async ValueTask WriteThenReuse(Calls calls, Action<byte[], byte[]> writeHeaders, IBufferWriter<byte> writer,
        Func<ValueTask<FlushResult>> flush)
    {
        await LeaveReactor();
        calls.Note();
        byte[] name = "x-probe"u8.ToArray();
        byte[] value = "original"u8.ToArray();
        writeHeaders(name, value);
        "x-wrong"u8.CopyTo(name);
        "CLOBBER!"u8.CopyTo(value);

        writer.Write("body"u8);
        await flush();
    }

    // Echo the body chunk by chunk, every call made from the pool.
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

    private static ConfiguredTaskAwaitable LeaveReactor() => Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);

    private static void AssertHeadersKept(Func<IDuplexPipe, Calls, Task> serve)
    {
        (int port, Calls calls, Transport transport) = StartH2(serve);

        using HttpClient client = H2Client();
        Task<(HttpStatusCode Status, string Probe, string Body)> sent = GetProbeAsync(client, port);
        Assert.True(sent.Wait(30_000), "the response completed");

        Assert.Equal(HttpStatusCode.OK, sent.Result.Status);
        Assert.True(sent.Result.Probe == "original", $"the header went out as written: x-probe was {sent.Result.Probe}");
        Assert.Equal("body", sent.Result.Body);
        calls.AssertAllOff();
        transport.AssertOnReactor();
    }

    private static void AssertPoolPipe(Func<IDuplexPipe, Calls, Task> serve)
    {
        (int port, Calls calls, Transport transport) = StartH2(serve, viaPool: true);

        using HttpClient client = H2Client();
        AssertEcho(client, port);
        calls.AssertAllOn();
        transport.AssertOnReactor();
    }

    private static void AssertLateStart(Func<IDuplexPipe, Calls, Task> serve)
    {
        (int port, Calls calls, Transport transport) = StartH2(serve, startOffReactor: true);

        using HttpClient client = H2Client();
        AssertEcho(client, port);
        calls.AssertAllOff();
        transport.AssertOnReactor();
    }

    private static void AssertEcho(HttpClient client, int port)
    {
        Task<byte[]> echoed = PostAsync(client, port, Upload);
        Assert.True(echoed.Wait(60_000), "the echo completed");
        Assert.True(echoed.Result.AsSpan().SequenceEqual(Upload),
            $"the echo came back whole: {echoed.Result.Length} of {Upload.Length} bytes, first difference at {FirstDifference(Upload, echoed.Result)}");
    }

    private static (int Port, Calls Calls, Transport Transport) StartH2(Func<IDuplexPipe, Calls, Task> serve,
        bool viaPool = false, bool startOffReactor = false)
    {
        var calls = new Calls();
        var transport = new Transport(viaPool, fromReactorRead: startOffReactor);

        int port = TestServer.Start(async (reactor, conn) =>
        {
            calls.Reactor = reactor;
            try
            {
                IDuplexPipe pipe = transport.Wrap(new TcpConnectionDualPipe(conn), reactor);
                if (startOffReactor)
                {
                    await LeaveReactor();
                }
                await serve(pipe, calls);
            }
            finally
            {
                conn.DecRef();
            }
        });

        return (port, calls, transport);
    }

    /// <summary>Where the handler's calls were made.</summary>
    private sealed class Calls
    {
        public Reactor? Reactor;
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

        public void AssertAllOn()
        {
            Assert.True(Volatile.Read(ref _off) == 0, $"the handler was dispatched on the reactor ({_off} calls off it)");
            Assert.True(Volatile.Read(ref _on) > 0, $"the handler ran ({_on} calls on the reactor)");
        }
    }

    /// <summary>
    /// Counts the calls that reach the test's transports from off their reactor. With viaPool reads and
    /// flushes complete on the thread pool, as a default Pipe completes a read, and a flush it held back,
    /// there. With fromReactorRead a connection counts once a read of its completes on the reactor: begun on
    /// the pool it writes its SETTINGS from there, before it can know its reactor, and the harness's listen
    /// probe, closed by then, never learns it.
    /// </summary>
    private sealed class Transport(bool viaPool, bool fromReactorRead)
    {
        private int _off;

        public IDuplexPipe Wrap(IDuplexPipe inner, Reactor reactor) => new Duplex(inner, reactor, this, viaPool, counting: !fromReactorRead);

        public void AssertOnReactor() =>
            Assert.True(Volatile.Read(ref _off) == 0, $"the transport was only called from its reactor ({_off} calls from elsewhere)");

        // One connection's transport.
        private sealed class Duplex : IDuplexPipe
        {
            private readonly Reactor _reactor;
            private readonly Transport _owner;
            private readonly bool _viaPool;
            private int _counting;

            public Duplex(IDuplexPipe inner, Reactor reactor, Transport owner, bool viaPool, bool counting)
            {
                _reactor = reactor;
                _owner = owner;
                _viaPool = viaPool;
                _counting = counting ? 1 : 0;
                Input = new Reader(inner.Input, this);
                Output = new Writer(inner.Output, this);
            }

            public PipeReader Input { get; }
            public PipeWriter Output { get; }

            public void Note()
            {
                if (Volatile.Read(ref _counting) == 1 && !_reactor.OnReactorThread)
                {
                    Interlocked.Increment(ref _owner._off);
                }
            }

            public async ValueTask<ReadResult> Read(ValueTask<ReadResult> pending)
            {
                ReadResult read = await pending;
                if (_reactor.OnReactorThread)
                {
                    Volatile.Write(ref _counting, 1);
                }
                if (_viaPool)
                {
                    await LeaveReactor();
                }
                return read;
            }

            public async ValueTask<FlushResult> Flush(ValueTask<FlushResult> pending)
            {
                FlushResult flushed = await pending;
                if (_viaPool)
                {
                    await LeaveReactor();
                }
                return flushed;
            }
        }

        private sealed class Reader(PipeReader inner, Duplex owner) : PipeReader
        {
            public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
            {
                owner.Note();
                return owner.Read(inner.ReadAsync(cancellationToken));
            }

            public override bool TryRead(out ReadResult result)
            {
                owner.Note();
                return inner.TryRead(out result);
            }

            public override void AdvanceTo(SequencePosition consumed)
            {
                owner.Note();
                inner.AdvanceTo(consumed);
            }

            public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
            {
                owner.Note();
                inner.AdvanceTo(consumed, examined);
            }

            public override void CancelPendingRead() => inner.CancelPendingRead();
            public override void Complete(Exception? exception = null) => inner.Complete(exception);
        }

        private sealed class Writer(PipeWriter inner, Duplex owner) : PipeWriter
        {
            public override Span<byte> GetSpan(int sizeHint = 0)
            {
                owner.Note();
                return inner.GetSpan(sizeHint);
            }

            public override Memory<byte> GetMemory(int sizeHint = 0)
            {
                owner.Note();
                return inner.GetMemory(sizeHint);
            }

            public override void Advance(int bytes)
            {
                owner.Note();
                inner.Advance(bytes);
            }

            public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
            {
                owner.Note();
                return owner.Flush(inner.FlushAsync(cancellationToken));
            }

            public override void CancelPendingFlush() => inner.CancelPendingFlush();
            public override void Complete(Exception? exception = null) => inner.Complete(exception);
        }
    }

    // Cleartext HTTP/2 with prior knowledge, as an h2c peer sends it.
    private static HttpClient H2Client() => new(new SocketsHttpHandler())
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(60),
    };

    private static async Task<(HttpStatusCode Status, string Probe, string Body)> GetProbeAsync(HttpClient client, int port)
    {
        using HttpResponseMessage response = await client.GetAsync($"http://127.0.0.1:{port}/");
        string probe = response.Headers.TryGetValues("x-probe", out IEnumerable<string>? values) ? string.Join(",", values) : "missing";
        return (response.StatusCode, probe, await response.Content.ReadAsStringAsync());
    }

    private static async Task<byte[]> PostAsync(HttpClient client, int port, byte[] body)
    {
        using HttpResponseMessage response = await client.PostAsync($"http://127.0.0.1:{port}/", new DuplexContent(body));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsByteArrayAsync();
    }

    // HttpClient sends a ByteArrayContent whole before it reads the response, which stalls an echo past its receive window.
    private sealed class DuplexContent(byte[] bytes) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(bytes).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            length = bytes.Length;
            return true;
        }
    }

    // Position-dependent, so a reordered echo fails.
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
