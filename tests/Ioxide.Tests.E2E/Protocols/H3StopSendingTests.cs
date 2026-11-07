using System.Buffers;
using ioxide;
using ioxide.http3;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// A STOP_SENDING and nothing else (RFC 9000 19.5): the peer wants no more of the response, and may still be
/// sending its request. So the request goes on, and only the response ends.
/// </summary>
internal static class H3StopSendingTests
{
    private const int Body = 1000;
    private const int FirstPart = 400;
    private const ulong H3NoError = 0x100;

    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            string stack = native ? "nghttp3" : "http3";

            runner.Test($"{stack}: a STOP_SENDING alone leaves a buffered request whose upload is still arriving", () =>
                Assert.Equal($"got {Body}", BufferedOutcome(native)));

            runner.Test($"{stack}: a STOP_SENDING alone leaves a streamed body reading to its end", () =>
                Assert.Equal($"body ended after {Body}", StreamedBodyOutcome(native)));

            foreach (bool uploadOpen in new[] { true, false })
            {
                bool open = uploadOpen;
                string request = open ? "whose upload stays open" : "that has ended";
                runner.Test($"{stack}: a handler writing until it is told hears a STOP_SENDING on a request {request}", () =>
                    Assert.Equal("told", WritesUntilToldOutcome(native, open)));
            }

            runner.Test($"{stack}: a handler parked on send capacity wakes for a STOP_SENDING", () =>
                Assert.Equal("told", ParkedOutcome(native, stopFirst: false)));

            runner.Test($"{stack}: a STOP_SENDING before a request's first bytes reaches the handler answering it", () =>
                Assert.Equal("told", ParkedOutcome(native, stopFirst: true)));
        }
    }

    private static string BufferedOutcome(bool native)
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        int udpPort = Start((_, conn) => native
            ? new Nghttp3Connection(conn).RunAsync(request =>
            {
                outcome.TrySetResult($"got {request.Body.Length}");
                return Nghttp3Response.Text("answer");
            })
            : new Http3Connection(conn).RunAsync(request =>
            {
                outcome.TrySetResult($"got {request.Body.Length}");
                return Http3Response.Text("answer");
            }));

        using RawH3Client client = Connect(udpPort);
        client.OpenRequestStream();
        client.Write([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(Body), .. new byte[FirstPart]], fin: false);
        client.StopSending(H3NoError);
        client.Write(new byte[Body - FirstPart], fin: true);

        Assert.True(client.WaitFor(outcome.Task, timeoutMs: 5000), $"the handler never ran (connection closed: {client.PeerClosed})");
        Assert.True(!client.PeerClosed, "the rest of the upload closed the connection");
        return outcome.Task.Result;
    }

    private static string StreamedBodyOutcome(bool native)
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        async ValueTask ReadBody(Func<ValueTask<ReadOnlyMemory<byte>>> read)
        {
            int length = 0;
            try
            {
                while (true)
                {
                    ReadOnlyMemory<byte> chunk = await read();
                    if (chunk.IsEmpty)
                    {
                        outcome.TrySetResult($"body ended after {length}");
                        return;
                    }
                    length += chunk.Length;
                }
            }
            catch (IOException)
            {
                outcome.TrySetResult($"body raised after {length}");
            }
        }

        int udpPort = Start((_, conn) => native
            ? new Nghttp3Connection(conn).RunAsync(async (_, reader, writer) =>
            {
                writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                await ReadBody(reader.ReadAsync);
            })
            : new Http3Connection(conn).RunAsync(async (_, reader, writer) =>
            {
                writer.WriteHeaders(new Http3Response { Status = 200 });
                await ReadBody(reader.ReadAsync);
            }));

        using RawH3Client client = Connect(udpPort);
        client.OpenRequestStream();
        client.Write([.. RawH3Client.RequestHeaders("POST"), .. RawH3Client.DataFrameHeader(Body), .. new byte[FirstPart]], fin: false);
        client.StopSending(H3NoError);
        client.Write(new byte[Body - FirstPart], fin: true);

        Assert.True(client.WaitFor(outcome.Task, timeoutMs: 5000), $"the body read never ended (connection closed: {client.PeerClosed})");
        Assert.True(!client.PeerClosed, "the rest of the upload closed the connection");
        return outcome.Task.Result;
    }

    // A handler on the reactor that writes until a flush says stop: nothing else gives the reactor back to it.
    private static string WritesUntilToldOutcome(bool native, bool uploadOpen)
    {
        const int limit = 100_000;
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        int udpPort = Start((reactor, conn) => native
            ? new Nghttp3Connection(conn).RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                await writer.FlushAsync();
                started.TrySetResult();
                await stopped.Task;
                await new ReactorSwitch(reactor);
                for (int flushes = 0; flushes < limit; flushes++)
                {
                    writer.Write("chunk"u8);
                    if ((await writer.FlushAsync()).IsCompleted)
                    {
                        outcome.TrySetResult("told");
                        return;
                    }
                }
                outcome.TrySetResult($"not told after {limit} flushes");
            })
            : new Http3Connection(conn).RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http3Response { Status = 200 });
                await writer.FlushAsync();
                started.TrySetResult();
                await stopped.Task;
                await new ReactorSwitch(reactor);
                for (int flushes = 0; flushes < limit; flushes++)
                {
                    writer.Write("chunk"u8);
                    if ((await writer.FlushAsync()).IsCompleted)
                    {
                        outcome.TrySetResult("told");
                        return;
                    }
                }
                outcome.TrySetResult($"not told after {limit} flushes");
            }));

        using RawH3Client client = Connect(udpPort);
        client.OpenRequestStream();
        client.Write(RawH3Client.RequestHeaders("POST"), fin: !uploadOpen);
        Assert.True(client.WaitFor(started.Task, timeoutMs: 5000), "the handler never started");

        client.StopSending(H3NoError);
        ulong? code = client.WaitForReset(timeoutMs: 5000);
        Assert.True(code == H3NoError, $"the server never answered the STOP_SENDING with a RESET_STREAM, got {(code is ulong c ? $"0x{c:x}" : "nothing")}");

        stopped.SetResult();
        Assert.True(client.WaitFor(outcome.Task, timeoutMs: 10_000), "the handler's flush never returned");
        return outcome.Task.Result;
    }

    // A client that reads nothing, so the handler writes until the connection will hold no more, and parks.
    private static string ParkedOutcome(bool native, bool stopFirst)
    {
        int flushes = 0;
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        byte[] chunk = new byte[64 * 1024];

        int udpPort = Start((_, conn) => native
            ? new Nghttp3Connection(conn).RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Nghttp3Response { Status = 200 });
                while (true)
                {
                    writer.Write(chunk);
                    if ((await writer.FlushAsync()).IsCompleted)
                    {
                        outcome.TrySetResult("told");
                        return;
                    }
                    Interlocked.Increment(ref flushes);
                }
            })
            : new Http3Connection(conn).RunAsync(async (_, _, writer) =>
            {
                writer.WriteHeaders(new Http3Response { Status = 200 });
                while (true)
                {
                    writer.Write(chunk);
                    if ((await writer.FlushAsync()).IsCompleted)
                    {
                        outcome.TrySetResult("told");
                        return;
                    }
                    Interlocked.Increment(ref flushes);
                }
            }));

        using RawH3Client client = Connect(udpPort);
        client.OpenRequestStream();
        if (stopFirst)
        {
            client.StopSending(H3NoError);
        }
        client.Write(RawH3Client.RequestHeaders("POST"), fin: false);

        if (!stopFirst)
        {
            long deadline = Environment.TickCount64 + 10_000;
            int seen = -1;
            while (Environment.TickCount64 < deadline && (Volatile.Read(ref flushes) == 0 || seen != Volatile.Read(ref flushes)))
            {
                seen = Volatile.Read(ref flushes);
                Thread.Sleep(100);
            }
            Assert.True(seen > 0 && seen == Volatile.Read(ref flushes), $"the handler never parked ({seen} flushes)");

            client.StopSending(H3NoError);
        }

        Assert.True(client.WaitFor(outcome.Task, timeoutMs: 10_000), $"the handler's flush never returned, after {Volatile.Read(ref flushes)} flushes");
        return outcome.Task.Result;
    }

    private static int Start(Func<Reactor, QuicConnection, Task> handle)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var engine = TestServer.Own(new QuicEngine(certPath, keyPath, cidLength: 8, alpn: ["h3"]));
        (_, int udpPort) = TestServer.StartDatagram(onDatagram: null, quicFactory: engine.CreateFactory(), quicHandle: handle);
        return udpPort;
    }

    private static RawH3Client Connect(int udpPort)
    {
        var client = new RawH3Client("127.0.0.1", udpPort);
        client.Connect();
        Assert.True(client.CompleteHandshake(timeoutMs: 5000), "handshake did not complete");
        return client;
    }
}
