using System.Collections;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks.Sources;
using ioxide;
using ioxide.http3;
using ioxide.ngtcp2;
using ioxide.timer;

namespace Ioxide.Tests;

/// <summary>
/// ioxide.http3 hands a finished request stream, with its request, to the next stream on the connection.
/// </summary>
internal static class Http3RequestReuseTests
{
    private enum Shape { Synchronous, Completed, Parked, Streamed }

    public static void Register(Runner runner)
    {
        foreach (Shape shape in new[] { Shape.Synchronous, Shape.Completed, Shape.Parked, Shape.Streamed })
        {
            Shape s = shape;
            runner.Test($"h3 request (ioxide.http3, {s.ToString().ToLowerInvariant()} handler): the next stream's request holds nothing of the one before", () =>
            {
                var seen = new List<(Http3Request Request, string Fields)>();
                int udpPort = Start(s, request => seen.Add((request, Describe(request))));   // on the reactor's thread

                using H3TestClient client = Connect(udpPort);
                Assert.Equal(200, client.Request("POST", "/first", "hello"u8.ToArray(),
                    [("x-one", "1"), ("x-two", "2"), ("content-length", "5")], timeoutMs: 5000).Status);
                Assert.Equal(200, client.Request("GET", "/", null, [("host", "b.example")], timeoutMs: 5000).Status);
                // A content-length the request before it already counted down must not read as a repeated one.
                Assert.Equal(200, client.Request("POST", "/again", "world"u8.ToArray(), [("content-length", "5")], timeoutMs: 5000).Status);

                Assert.Equal(3, seen.Count);
                Assert.Equal("POST localhost /first [x-one=1 x-two=2 content-length=5] hello", seen[0].Fields);
                Assert.Equal("GET - / [host=b.example] -", seen[1].Fields);
                Assert.Equal("POST localhost /again [content-length=5] world", seen[2].Fields);
                Assert.True(ReferenceEquals(seen[0].Request, seen[1].Request) && ReferenceEquals(seen[1].Request, seen[2].Request),
                    "each stream reuses the request of the one before");
            });
        }

        runner.Test("h3 request (ioxide.http3): headers past 4 KiB leave no large arena for the next stream", () =>
        {
            var arenas = new List<int>();
            ServeInTurn([Get(lines: 1, value: 5 * 1024), Get(lines: 0)], request =>
            {
                Assert.True(MemoryMarshal.TryGetArray(request.Method, out ArraySegment<byte> arena), "the method is in the arena");
                arenas.Add(arena.Array!.Length);
            });

            Assert.Equal(2, arenas.Count);
            Assert.True(arenas[0] > 5 * 1024, $"the first request's arena was {arenas[0]} B");
            Assert.True(arenas[1] < 4 * 1024, $"the next stream started on an arena of {arenas[1]} B");
        });

        foreach ((int lines, bool kept) in new[] { (64, true), (65, false) })
        {
            int count = lines;
            bool expected = kept;
            runner.Test($"h3 request (ioxide.http3): a request with {count} header lines {(expected ? "is" : "is not")} kept for the next stream", () =>
            {
                var seen = new List<Http3Request>();
                ServeInTurn([Get(count), Get(lines: 0)], seen.Add);

                Assert.Equal(2, seen.Count);
                Assert.Equal(expected, ReferenceEquals(seen[0], seen[1]));
            });
        }

        runner.Test("h3 request (ioxide.http3): a connection keeps at most 32 requests for later streams", () =>
        {
            var quic = new H3ErrorCodeTests.RecordingQuic();
            var connection = new Http3Connection(quic);
            int served = 0;
            Task run = connection.RunAsync(_ =>
            {
                served++;
                return Ok;
            });

            for (int i = 0; i < 40; i++)                 // one read, so all 40 are open before the first retires
            {
                Assert.True(quic.EnqueueStreamData(i * 4, Get(lines: 0), fin: true), "the recv ring rejected the item");
            }
            quic.SignalDataArrived();
            int pooled = ((ICollection)typeof(Http3Connection)
                .GetField("_reqPool", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(connection)!).Count;
            quic.MarkClosed();

            Assert.True(run.IsCompleted, "the run loop should have finished inline");
            Assert.Equal(40, served);
            Assert.Equal(32, pooled);
        });

        runner.Test("h3 request (ioxide.http3): a warm connection's request allocates none of the request objects", () =>
        {
            const int warm = 4;
            const int measured = 12;
            long[] marks = new long[2];
            int[] threads = new int[2];
            int served = 0;

            int udpPort = Start(Shape.Synchronous, _ =>
            {
                // On the reactor's thread: what it allocated between these two requests.
                int n = ++served;
                int mark = n == warm ? 0 : n == warm + measured ? 1 : -1;
                if (mark >= 0)
                {
                    marks[mark] = GC.GetAllocatedBytesForCurrentThread();
                    threads[mark] = Environment.CurrentManagedThreadId;
                }
            });

            using H3TestClient client = Connect(udpPort);
            for (int i = 0; i < warm + measured; i++)
            {
                (int status, string body) = client.Request("GET", $"/{i}", null, [("x-n", $"{i}")], timeoutMs: 5000);
                Assert.Equal(200, status);
                Assert.Equal("ok", body);
            }

            Assert.True(threads[0] == threads[1] && marks[1] >= marks[0], "both marks come from the reactor's thread");

            // Allows for the QUIC layer's per-stream send state, about 185 B, which this connection does not own.
            long perRequest = (marks[1] - marks[0]) / measured;
            Assert.True(perRequest < 400, $"a request on a warm connection allocated {perRequest} B on the reactor");
        });
    }

    private static readonly Http3Response Ok = Http3Response.Text("ok");   // shared, so the handler allocates nothing

    // One connection's server, answering "ok" through the handler shape asked for.
    private static int Start(Shape shape, Action<Http3Request> observe)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: (reactor, conn) =>
            {
                var connection = new Http3Connection(conn);
                switch (shape)
                {
                    case Shape.Synchronous:
                        return connection.RunAsync(request =>
                        {
                            observe(request);
                            return Ok;
                        });

                    case Shape.Completed:
                        return connection.RunAsync(request =>
                        {
                            observe(request);
                            return new ValueTask<Http3Response>(new ReadOnce(Ok), 0);
                        });

                    case Shape.Parked:
                        var timer = new RingTimer(reactor);
                        return connection.RunAsync(async request =>
                        {
                            observe(request);
                            await timer.DelayAsync(1);
                            return Ok;
                        });

                    default:
                        return connection.RunAsync(async (request, writer) =>
                        {
                            observe(request);
                            writer.WriteHeaders(new Http3Response { Status = 200 });
                            "ok"u8.CopyTo(writer.GetSpan(2));
                            writer.Advance(2);
                            await writer.FlushAsync();
                        });
                }
            });
        return udpPort;
    }

    // Each request in a read of its own, over a transport with no engine, so the run loop does everything inline.
    private static void ServeInTurn(byte[][] requests, Action<Http3Request> observe)
    {
        var quic = new H3ErrorCodeTests.RecordingQuic();
        Task run = new Http3Connection(quic).RunAsync(request =>
        {
            observe(request);
            return Ok;
        });

        for (int i = 0; i < requests.Length; i++)
        {
            Assert.True(quic.EnqueueStreamData(i * 4, requests[i], fin: true), "the recv ring rejected the item");
            quic.SignalDataArrived();
        }
        quic.MarkClosed();
        Assert.True(run.IsCompleted, "the run loop should have finished inline");
    }

    // A GET framed by hand, as the test client sends at most 64 fields: the static table, then literal "x-a" lines.
    private static byte[] Get(int lines, int value = 1)
    {
        var block = new List<byte> { 0x00, 0x00, 0xD1, 0xD7, 0xC1, 0xC0 };
        for (int i = 0; i < lines; i++)
        {
            block.AddRange([0x23, (byte)'x', (byte)'-', (byte)'a']);
            if (value < 127)
            {
                block.Add((byte)value);
            }
            else
            {
                block.Add(0x7F);
                int rest = value - 127;
                for (; rest >= 128; rest >>= 7)
                {
                    block.Add((byte)(rest | 0x80));
                }
                block.Add((byte)rest);
            }
            block.AddRange(Enumerable.Repeat((byte)'v', value));
        }
        return [0x01, (byte)(0x40 | (block.Count >> 8)), (byte)block.Count, .. block];
    }

    private static H3TestClient Connect(int udpPort)
    {
        var client = new H3TestClient("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;
    }

    private static string Describe(Http3Request request)
    {
        var fields = new List<string>();
        foreach ((ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) in request.Headers)
        {
            fields.Add($"{Ascii(name)}={Ascii(value)}");
        }

        string authority = request.Authority.IsEmpty ? "-" : Ascii(request.Authority);
        return $"{Ascii(request.Method)} {authority} {Ascii(request.Path)} [{string.Join(' ', fields)}] "
             + (request.Body.IsEmpty ? "-" : Ascii(request.Body));
    }

    // Complete before it is returned and readable once, as a pooled source is: a second read throws.
    private sealed class ReadOnce(Http3Response response) : IValueTaskSource<Http3Response>
    {
        private bool _read;

        public Http3Response GetResult(short token)
        {
            if (_read)
            {
                throw new InvalidOperationException("the handler's ValueTask was read twice");
            }
            _read = true;
            return response;
        }

        public ValueTaskSourceStatus GetStatus(short token) => ValueTaskSourceStatus.Succeeded;

        public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => continuation(state);
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);
}
