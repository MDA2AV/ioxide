using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// While the kernel may still read a connection's write slab, the connection must not be recycled
/// (#221) and its handler must not be let go to write into it (#244).
/// </summary>
/// <remarks>
/// io_uring copies from user memory when the socket drains, not when the send is submitted. Recv-side
/// teardown used to release the parked flush and recycle the connection straight away: the next
/// accept wrote its response into the same slab, and the handler itself could overwrite the bytes
/// still being sent.
/// </remarks>
internal static class SendInFlightRecycleTests
{
    private const int BodyBytes = 8000;

    /// <summary>First connection's body byte. Above ASCII, so no header byte can collide.</summary>
    private const byte FirstMarker = 0xA1;

    /// <summary>
    /// Enough pipelined responses to outrun the server's socket send queue, not only the peer's 4 KB
    /// window. Each test asserts the send really parked rather than trusting this margin.
    /// </summary>
    private const int Requests = 400;

    public static void Register(Runner runner)
    {
        // Both clocks off: a sweep firing mid-run would end the send by another route.
        var tcp = new TcpOptions
        {
            WriteSlabSize = 16 * 1024,
            PoolMax = 64,
            RecvQueueEntries = 64,
            ReadTimeoutMs = 0,
            SendTimeoutMs = 0,
        };

        RegisterSlabLeak(runner, "plain SEND", tcp);

        // A 4 KB slab under an 8 KB response: every flush goes out as one SENDMSG.
        RegisterSlabLeak(runner, "vectored SENDMSG", tcp with
        {
            WriteSlabSize = 4 * 1024,
            WriteOverflow = WriteOverflowStrategy.Segmented,
        });

        // The kernel keeps the slab's pages past the data CQE, until the notif.
        RegisterSlabLeak(runner, "SEND_ZC", tcp with { ZeroCopySend = true });

        RegisterWriteAfterHalfClose(runner, tcp);
        RegisterOffConnectionPark(runner, tcp);
    }

    private static void RegisterSlabLeak(Runner runner, string shape, TcpOptions tcp)
    {
        runner.Test($"send in flight ({shape}): a recycled connection does not leak its slab to the next peer", () =>
        {
            // Every connection answers with a body of its own marker byte, so one foreign byte is proof.
            var marker = 0;

            int port = StartPipelined(tcp, (ref byte[]? response) =>
            {
                // Claimed on first data: TestServer's connect-and-drop probe must not take a marker.
                response ??= BuildResponse((byte)(FirstMarker + Interlocked.Increment(ref marker) - 1));
                return response;
            });

            // Connection A parks a send, then half-closes to drive recv-side teardown.
            using TcpClient first = ParkThenHalfClose(port);

            // Connection B connects while A's send is still in the kernel.
            using (var second = new TcpClient())
            {
                second.Connect("127.0.0.1", port);
                second.ReceiveTimeout = 20_000;
                second.Client.Send("\n\n\n"u8.ToArray());
                Drain(second, 3 * BodyBytes / 2);
            }

            byte[] received = Drain(first, int.MaxValue);
            AssertParked(received);

            int foreign = 0;
            int firstAt = -1;
            for (int i = 0; i < received.Length; i++)
            {
                byte b = received[i];
                if (b >= FirstMarker && b != FirstMarker)
                {
                    foreign++;
                    if (firstAt < 0)
                    {
                        firstAt = i;
                    }
                }
            }

            Assert.True(foreign == 0,
                $"another connection's response bytes reached the first peer: {foreign} foreign "
                + $"bytes, first at offset {firstAt} of {received.Length}");
        });
    }

    private static void RegisterWriteAfterHalfClose(Runner runner, TcpOptions tcp)
    {
        runner.Test("send in flight: a handler that keeps writing after the peer half-closes does not tear the response being sent", () =>
        {
            // One marker per response, so a later response's bytes inside an earlier one show up.
            var index = 0;

            int port = StartPipelined(tcp, (ref byte[]? _) => BuildResponse(Marker(index++)));

            using TcpClient client = ParkThenHalfClose(port);

            byte[] received = Drain(client, int.MaxValue);
            AssertParked(received);

            byte[] head = BuildResponse(0)[..^BodyBytes];
            int stride = head.Length + BodyBytes;
            for (int i = 0; i < received.Length; i++)
            {
                int at = i % stride;
                byte expected = at < head.Length ? head[at] : Marker(i / stride);
                if (received[i] != expected)
                {
                    Assert.True(false,
                        $"response {i / stride} was overwritten while it was being sent: byte {at} "
                        + $"is 0x{received[i]:X2}, expected 0x{expected:X2}");
                }
            }
        });
    }

    /// <summary>Big enough to outrun the server's socket send buffer, so ONE send parks.</summary>
    private const int ParkingBytes = 4 * 1024 * 1024;

    /// <summary>How long the handler stays parked on something that is not this connection.</summary>
    private const int HandlerParkMs = 900;

    private static void RegisterOffConnectionPark(Runner runner, TcpOptions tcp)
    {
        runner.Test("send in flight: a send completing while the handler is parked elsewhere still recycles", () =>
        {
            // The teardown waits for the send, and the handler is away on an unrelated await when that
            // send completes - so the completion alone has to let the connection go. One that is never
            // let go never closes its fd, so descriptors climb once per round.
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                try
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            conn.ReturnBuffer(in item);
                        }
                    }

                    // One write far past the slab, which the peer's 4 KB window cannot drain.
                    conn.Write(new byte[ParkingBytes]);
                    ValueTask flush = conn.FlushAsync();

                    await Task.Delay(HandlerParkMs);

                    await flush;
                }
                catch
                {
                    // The peer goes away mid-send by design; the fd accounting is what is on trial.
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config(tcp)).Port;

            Round(port);                 // warm up: pool, slab and JIT settle before the baseline
            int baseline = OpenFds();

            const int rounds = 5;
            for (int i = 0; i < rounds; i++)
            {
                Round(port);
            }

            int leaked = OpenFds() - baseline;
            Assert.True(leaked <= 2,
                $"descriptors grew by {leaked} over {rounds} rounds: a connection whose send "
                + "completed while its handler was parked elsewhere was never recycled");
        });
    }

    private delegate byte[] NextResponse(ref byte[]? cached);

    /// <summary>A server answering every '\n' with one response, each written and flushed alone.</summary>
    private static int StartPipelined(TcpOptions tcp, NextResponse next) =>
        TestServer.StartConfigured(async (_, conn) =>
        {
            byte[]? cached = null;

            try
            {
                while (true)
                {
                    RecvSnapshot snapshot = await conn.ReadAsync();

                    int requests = 0;
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            requests += Count(item.AsSpan(), (byte)'\n');
                            conn.ReturnBuffer(in item);
                        }
                    }

                    for (int i = 0; i < requests; i++)
                    {
                        conn.Write(next(ref cached));
                        await conn.FlushAsync();
                    }

                    if (snapshot.IsClosed)
                    {
                        return;
                    }
                    conn.ResetRead();
                }
            }
            finally
            {
                conn.DecRef();
            }
        }, Config(tcp)).Port;

    private static ServerConfig Config(TcpOptions tcp) => new()
    {
        RecvBufferSize = 16 * 1024,
        RecvSlots = 256,
        Tcp = tcp,
    };

    /// <summary>
    /// Pipelines <see cref="Requests"/> requests into a window too small to take the answers, stops
    /// reading so the server parks with a send in the kernel, then half-closes.
    /// </summary>
    private static TcpClient ParkThenHalfClose(int port)
    {
        var client = new TcpClient();
        client.ReceiveBufferSize = 4096;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 20_000;

        var pipeline = new byte[Requests];
        Array.Fill(pipeline, (byte)'\n');
        client.Client.Send(pipeline);

        Thread.Sleep(1_500);                          // the server fills the window and parks
        client.Client.Shutdown(SocketShutdown.Send);  // FIN: recv-side teardown
        Thread.Sleep(200);

        return client;
    }

    /// <summary>
    /// The precondition, asserted rather than assumed: a peer that got every response means nothing
    /// was in flight at the FIN, and the checks after it would pass without exercising anything.
    /// </summary>
    private static void AssertParked(byte[] received)
    {
        int whole = BuildResponse(FirstMarker).Length * Requests;
        Assert.True(received.Length < whole,
            $"the server's send never parked: {received.Length} of {whole} bytes arrived, so "
            + "nothing was in flight at the FIN and this test proved nothing");
    }

    /// <summary>Response <paramref name="index"/>'s body byte: above ASCII, and unlike its neighbours'.</summary>
    private static byte Marker(int index) => (byte)(0x80 + index % 128);

    /// <summary>
    /// One connection through the whole window: park the send, half-close while the handler is away,
    /// then read so the parked send completes inside it.
    /// </summary>
    private static void Round(int port)
    {
        using var client = new TcpClient();
        client.ReceiveBufferSize = 4096;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 20_000;

        client.Client.Send("\n"u8.ToArray());

        Thread.Sleep(250);                            // the send fills the window and parks
        client.Client.Shutdown(SocketShutdown.Send);  // FIN: recv-side teardown, handler still away

        // The WHOLE send, so it completes while the handler is still away.
        Thread.Sleep(100);
        Drain(client, ParkingBytes);

        // Past the handler's delay, so its DecRef and the recycle have run before the count.
        Thread.Sleep(HandlerParkMs);
    }

    /// <summary>Descriptors this process holds. /proc/self/fd has one entry per open fd.</summary>
    private static int OpenFds() => Directory.GetFileSystemEntries("/proc/self/fd").Length;

    private static byte[] BuildResponse(byte mark)
    {
        byte[] head = System.Text.Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\nContent-Length: {BodyBytes}\r\n\r\n");

        var response = new byte[head.Length + BodyBytes];
        head.CopyTo(response, 0);
        Array.Fill(response, mark, head.Length, BodyBytes);

        return response;
    }

    private static int Count(ReadOnlySpan<byte> span, byte value)
    {
        int n = 0;
        foreach (byte b in span)
        {
            if (b == value)
            {
                n++;
            }
        }
        return n;
    }

    /// <summary>Reads until EOF, or until <paramref name="stopAfter"/> bytes have arrived.</summary>
    private static byte[] Drain(TcpClient client, int stopAfter)
    {
        var buffer = new byte[64 * 1024];
        using var received = new MemoryStream();

        while (received.Length < stopAfter)
        {
            int n;
            try
            {
                n = client.Client.Receive(buffer);
            }
            catch (SocketException)
            {
                break;
            }

            if (n <= 0)
            {
                break;
            }
            received.Write(buffer, 0, n);
        }

        return received.ToArray();
    }
}
