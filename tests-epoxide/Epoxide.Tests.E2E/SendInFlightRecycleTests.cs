using System.Net.Sockets;
using epoxide;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// While a flush is parked - the rest of it waiting in the write slab for the reactor to send at
/// the next writable edge - the connection must not be recycled under it, a reactor-side end must
/// release it rather than strand its caller, and nothing written next may tear what is being sent.
/// </summary>
/// <remarks>
/// ioxide's versions (#221, #244) protect a slab the kernel still reads after the send was
/// submitted. An epoll send copies at the syscall, so what is at stake here is the parked remainder:
/// a connection recycled with it still pending would hand the next peer the previous one's bytes,
/// and a handler let go early could write over it. And where ioxide reads a peer's FIN as teardown
/// at once, epoxide sees it only when the handler next reads, so a half-close no longer ends the
/// flush - the reactor's end is driven by a reset instead, and the half-close test asserts that the
/// whole response stream arrives.
///
/// Not ported: the SEND_ZC variant - epoxide has no zero-copy send.
/// </remarks>
internal static class SendInFlightRecycleTests
{
    private const int BodyBytes = 8000;

    /// <summary>First connection's body byte. Above ASCII, so no header byte can collide.</summary>
    private const byte FirstMarker = 0xA1;

    /// <summary>
    /// Enough pipelined responses to outrun the server's socket send queue, not only the peer's 4 KB
    /// window. Each test asserts the flush really parked rather than trusting this margin.
    /// </summary>
    private const int Requests = 400;

    public static void Register(Runner runner)
    {
        // Both clocks off: a sweep firing mid-run would end the flush by another route.
        var tcp = new TcpOptions
        {
            WriteSlabSize = 16 * 1024,
            PoolMax = 64,
            RecvQueueEntries = 64,
            ReadTimeoutMs = 0,
            SendTimeoutMs = 0,
        };

        RegisterSlabLeak(runner, "plain send", tcp);

        // A 4 KB slab under an 8 KB response: every flush goes out as one sendmsg.
        RegisterSlabLeak(runner, "vectored sendmsg", tcp with
        {
            WriteSlabSize = 4 * 1024,
            WriteOverflow = WriteOverflowStrategy.Segmented,
        });

        RegisterWriteAfterHalfClose(runner, tcp);
        RegisterOffConnectionPark(runner, tcp);
    }

    private static void RegisterSlabLeak(Runner runner, string shape, TcpOptions tcp)
    {
        runner.Test($"send in flight ({shape}): a connection reset with a flush parked releases it, and its recycled successor sends only its own bytes", () =>
        {
            // Every connection answers with a body of its own marker byte, so one foreign byte is proof.
            var probe = new Probe();
            int port = StartPipelined(tcp, probe, (int index, ref byte[]? response) =>
                response ??= BuildResponse((byte)(FirstMarker + index)));

            // Connection A parks a flush, then resets, which the reactor ends while the flush is parked.
            using (TcpClient first = ParkThenReset(port, probe))
            {
            }

            Assert.True(probe.Released[0].Wait(10_000),
                "the handler of the reset connection never finished: its parked flush was never released");

            // Connection B connects once A has been let go, so the accept can be handed A's object.
            byte[] received;
            using (var second = new TcpClient())
            {
                second.Connect("127.0.0.1", port);
                second.ReceiveTimeout = 20_000;
                second.Client.Send("\n\n\n"u8.ToArray());
                received = Drain(second, 3 * BuildResponse(0).Length);
            }

            Assert.True(ReferenceEquals(probe.Connections[1], probe.Connections[0]),
                "the second connection was not handed the first one's recycled object, so nothing could leak into it");
            Assert.Equal(3 * BuildResponse(0).Length, received.Length);

            int foreign = 0;
            int firstAt = -1;
            for (int i = 0; i < received.Length; i++)
            {
                byte b = received[i];
                if (b >= 0x80 && b != FirstMarker + 1)
                {
                    foreign++;
                    if (firstAt < 0)
                    {
                        firstAt = i;
                    }
                }
            }

            Assert.True(foreign == 0,
                $"the reset connection's response bytes reached its successor's peer: {foreign} foreign "
                + $"bytes, first at offset {firstAt} of {received.Length}");
        });
    }

    private static void RegisterWriteAfterHalfClose(Runner runner, TcpOptions tcp)
    {
        runner.Test("send in flight: a handler that keeps writing after the peer half-closes does not tear the response being sent", () =>
        {
            // One marker per response, so a later response's bytes inside an earlier one show up.
            var probe = new Probe();
            var index = 0;
            int port = StartPipelined(tcp, probe, (int _, ref byte[]? _) => BuildResponse(Marker(index++)));

            using TcpClient client = ParkThenHalfClose(port, probe);

            byte[] received = Drain(client, int.MaxValue);

            // The half-close reaches the handler only when it next reads, after the last response: the
            // whole stream arrives, every response intact.
            byte[] head = BuildResponse(0)[..^BodyBytes];
            int stride = head.Length + BodyBytes;
            Assert.True(received.Length == stride * Requests,
                $"{received.Length} of {stride * Requests} bytes arrived: the half-close cut the response stream short");
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

    /// <summary>Big enough to outrun the server's socket send buffer, so ONE flush parks.</summary>
    private const int ParkingBytes = 4 * 1024 * 1024;

    /// <summary>How long the handler stays parked on something that is not this connection.</summary>
    private const int HandlerParkMs = 900;

    private static void RegisterOffConnectionPark(Runner runner, TcpOptions tcp)
    {
        runner.Test("send in flight: a send completing while the handler is parked elsewhere still recycles", () =>
        {
            // The handler is away on an unrelated await when its parked flush completes - so the
            // completion alone has to leave the connection in a state the handler can let go of. One
            // that is never let go never closes its fd, so descriptors climb once per round.
            int port = TestServer.StartConfigured(async (r, conn) =>
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
                    if (snapshot.IsClosed)
                    {
                        return;   // the harness's listen probe
                    }

                    // One write far past the slab, which the peer's 4 KB window cannot drain.
                    conn.Write(new byte[ParkingBytes]);
                    ValueTask flush = conn.FlushAsync();

                    await new ReactorTimer(r).DelayAsync(HandlerParkMs);

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

    /// <summary>What the pipelined server saw, per connection that sent data, in arrival order.</summary>
    private sealed class Probe
    {
        public readonly TcpConnection?[] Connections = new TcpConnection?[8];
        public readonly ManualResetEventSlim[] Released = [.. Enumerable.Range(0, 8).Select(_ => new ManualResetEventSlim())];
        public int Claimed;

        /// <summary>Flushes that came back still in flight: the socket would not take them whole.</summary>
        public int Parked;
    }

    private delegate byte[] NextResponse(int connection, ref byte[]? cached);

    /// <summary>A server answering every '\n' with one response, each written and flushed alone.</summary>
    private static int StartPipelined(TcpOptions tcp, Probe probe, NextResponse next) =>
        TestServer.StartConfigured(async (_, conn) =>
        {
            byte[]? cached = null;
            int index = -1;

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

                    // Claimed on first data: TestServer's connect-and-drop probe must not take a slot.
                    if (requests > 0 && index < 0)
                    {
                        index = Interlocked.Increment(ref probe.Claimed) - 1;
                        probe.Connections[index] = conn;
                    }

                    for (int i = 0; i < requests; i++)
                    {
                        conn.Write(next(index, ref cached));
                        ValueTask flush = conn.FlushAsync();
                        if (!flush.IsCompleted)
                        {
                            Interlocked.Increment(ref probe.Parked);
                        }
                        await flush;
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
                if (index >= 0)
                {
                    probe.Released[index].Set();
                }
            }
        }, Config(tcp)).Port;

    private static ServerConfig Config(TcpOptions tcp) => new()
    {
        RecvBufferSize = 16 * 1024,
        Tcp = tcp,
    };

    /// <summary>
    /// Pipelines <see cref="Requests"/> requests into a window too small to take the answers and
    /// stops reading, until the server's flush has parked - asserted, not assumed: a flush that never
    /// parked means nothing was in flight and the checks after it exercise nothing.
    /// </summary>
    private static TcpClient Pipeline(int port, Probe probe)
    {
        var client = new TcpClient();
        client.ReceiveBufferSize = 4096;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 20_000;

        var pipeline = new byte[Requests];
        Array.Fill(pipeline, (byte)'\n');
        client.Client.Send(pipeline);

        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref probe.Parked) > 0, 10_000),
            "the server's flush never parked, so nothing was in flight and this test proved nothing");
        Thread.Sleep(200);   // the parked flush fills what the socket will take

        return client;
    }

    /// <summary>Parks the server's flush, then an abortive close: the reactor ends the connection under it.</summary>
    private static TcpClient ParkThenReset(int port, Probe probe)
    {
        TcpClient client = Pipeline(port, probe);
        client.LingerState = new LingerOption(true, 0);   // RST on close
        client.Close();
        return client;
    }

    /// <summary>Parks the server's flush, then half-closes: a FIN the handler has not read yet.</summary>
    private static TcpClient ParkThenHalfClose(int port, Probe probe)
    {
        TcpClient client = Pipeline(port, probe);
        client.Client.Shutdown(SocketShutdown.Send);
        Thread.Sleep(200);
        return client;
    }

    /// <summary>Response <paramref name="index"/>'s body byte: above ASCII, and unlike its neighbours'.</summary>
    private static byte Marker(int index) => (byte)(0x80 + index % 128);

    /// <summary>
    /// One connection through the whole window: park the flush, half-close while the handler is away,
    /// then read so the parked flush completes inside it.
    /// </summary>
    private static void Round(int port)
    {
        using var client = new TcpClient();
        client.ReceiveBufferSize = 4096;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 20_000;

        client.Client.Send("\n"u8.ToArray());

        Thread.Sleep(250);                            // the flush fills the window and parks
        client.Client.Shutdown(SocketShutdown.Send);  // FIN, handler still away

        // The WHOLE flush, so it completes while the handler is still away.
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
