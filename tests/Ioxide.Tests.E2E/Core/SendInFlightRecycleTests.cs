using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// A connection must not be recycled while the kernel may still read its write slab (#221).
/// </summary>
/// <remarks>
/// io_uring copies from user memory when the socket drains, not when the send is submitted. So a
/// connection torn down from the recv side with a send still parked used to go straight back to the
/// pool: <c>close(fd)</c>, <c>Clear()</c>, push. The next accept popped the same object, wrote its
/// response into the same slab, and the kernel's retry sent the NEW peer's bytes to the OLD one.
///
/// Measured before the fix, at this exact shape: 2,970 bytes of connection B's body arrived inside
/// connection A's response, at body offset 5030 of 8000. Same object, same slab pointer, same fd.
/// </remarks>
internal static class SendInFlightRecycleTests
{
    private const int BodyBytes = 8000;

    /// <summary>First connection's body byte. Above ASCII, so no header byte can collide.</summary>
    private const byte FirstMarker = 0xA1;

    /// <summary>
    /// Enough pipelined responses to outrun the server's socket SEND queue - not the peer's 4 KB
    /// receive window, which only stops the queue from draining. ~3.2 MB against a queue that
    /// parks around 1.8 MB here; the assertion below checks it really parked rather than trusting
    /// the margin, since tcp_wmem, BBR's sndbuf_expand and initcwnd all move that number.
    /// </summary>
    private const int Requests = 400;

    public static void Register(Runner runner)
    {
        runner.Test("send in flight: a recycled connection does not leak its slab to the next peer", () =>
        {
            // Every connection answers with a body made only of its own marker byte, so a single
            // foreign byte in the stream is proof and needs no timing assertion to interpret.
            var marker = 0;

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                byte[]? response = null;

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

                        // Claimed on first data, not at accept: TestServer proves the port is
                        // listening by connecting and dropping, and that probe must not take a
                        // marker or every later connection's bytes look foreign.
                        if (requests > 0)
                        {
                            response ??= BuildResponse((byte)(FirstMarker + Interlocked.Increment(ref marker) - 1));
                        }

                        for (int i = 0; i < requests && response is not null; i++)
                        {
                            conn.Write(response);
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
            }, new ServerConfig
            {
                RecvBufferSize = 16 * 1024,
                RecvSlots = 256,
                Tcp = new TcpOptions
                {
                    WriteSlabSize = 16 * 1024,
                    PoolMax = 64,
                    RecvQueueEntries = 64,

                    // Off: this test is about teardown ordering, and a sweep firing mid-run would
                    // release the send by a different route and hide what is being measured.
                    IdleTimeoutMs = 0,
                    SendTimeoutMs = 0,
                },
            }).Port;

            // Connection A: a window too small to absorb the pipeline, then stop reading entirely so
            // the server parks with a send in flight, then half-close to drive recv-side teardown.
            using var first = new TcpClient();
            first.ReceiveBufferSize = 4096;
            first.Connect("127.0.0.1", port);
            first.ReceiveTimeout = 20_000;

            var pipeline = new byte[Requests];
            Array.Fill(pipeline, (byte)'\n');
            first.Client.Send(pipeline);

            Thread.Sleep(1_500);                       // let the server fill the window and park
            first.Client.Shutdown(SocketShutdown.Send); // FIN: recv side tears the connection down

            // Connection B takes the pooled object, and its slab, while A's send is still live.
            Thread.Sleep(200);
            using (var second = new TcpClient())
            {
                second.Connect("127.0.0.1", port);
                second.ReceiveTimeout = 20_000;
                second.Client.Send("\n\n\n"u8.ToArray());
                Drain(second, 3 * BodyBytes / 2);
            }

            // Now let A drain what it was owed and inspect every byte of it.
            byte[] received = Drain(first, int.MaxValue);

            // The precondition, asserted rather than assumed: if A got every response then the
            // send never parked, there was no in-flight slab at teardown, and the byte check below
            // would pass without exercising anything.
            int whole = BuildResponse(FirstMarker).Length * Requests;
            Assert.True(received.Length < whole,
                $"the server's send never parked: A received {received.Length} bytes of {whole}, "
                + "so nothing was in flight at the FIN and this test proved nothing");

            // Body bytes are >= FirstMarker, which no ASCII header byte can be - so anything in
            // that range that is not this connection's own marker came from another connection.
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

        RegisterOffConnectionPark(runner);
    }

    /// <summary>Big enough to outrun the server's socket send buffer, so ONE send parks.</summary>
    private const int ParkingBytes = 4 * 1024 * 1024;

    /// <summary>How long the handler stays parked on something that is not this connection.</summary>
    private const int HandlerParkMs = 900;

    private static void RegisterOffConnectionPark(Runner runner)
    {
        runner.Test("send in flight: a send completing while the handler is parked elsewhere still recycles", () =>
        {
            // The first fix tracked the in-flight send from Recycle, which runs at refcount ZERO -
            // both refs. The reactor's goes first, at recv-side teardown, and a handler awaiting
            // anything that is not this connection (a query, an upstream call, a delay) still holds
            // the other one. In that window the connection is off the table and not yet tracked, so
            // a send completing in it found no owner, the count was never cleared, and the
            // connection was then held for the life of the process - fd, slab and all.
            //
            // Descriptors are the assertion: a connection that is never recycled never closes its
            // fd, so the count climbs once per round and cannot be explained away by timing.
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

                    // One write far past the slab, so Grow hands the send a single oversized buffer
                    // and the peer's 4 KB window cannot drain it. The send is still in flight when
                    // the delay below starts.
                    conn.Write(new byte[ParkingBytes]);
                    ValueTask flush = conn.FlushAsync();

                    // The point of the test: parked OFF this connection. MarkClosed completes the
                    // read and flush signals, so only an unrelated await keeps the handler ref.
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
            }, new ServerConfig
            {
                RecvBufferSize = 16 * 1024,
                RecvSlots = 256,
                Tcp = new TcpOptions
                {
                    WriteSlabSize = 16 * 1024,
                    PoolMax = 64,
                    RecvQueueEntries = 64,

                    // Off, so nothing but the deferred-send bookkeeping can release a connection -
                    // a sweep firing mid-run would close the fd by another route and hide the leak.
                    IdleTimeoutMs = 0,
                    SendTimeoutMs = 0,
                },
            }).Port;

            Round(port);                 // warm up: pool, slab and JIT settle before the baseline
            int baseline = OpenFds();

            const int rounds = 5;
            for (int i = 0; i < rounds; i++)
            {
                Round(port);
            }

            // Each unrecycled connection holds its fd forever, so a leak shows as +1 per round.
            int leaked = OpenFds() - baseline;
            Assert.True(leaked <= 2,
                $"descriptors grew by {leaked} over {rounds} rounds: a connection whose send "
                + "completed while its handler was parked elsewhere was never recycled");
        });
    }

    /// <summary>
    /// One connection through the whole window: park the send, half-close so the recv side tears
    /// down while the handler is still away, then read so the parked send completes inside it.
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

        // The WHOLE send, not a slice of it: the defect is a terminal CQE arriving while the
        // connection is off the table and the handler is still away, so the send has to actually
        // finish here - a partial drain leaves it in flight and the window is never entered.
        Thread.Sleep(100);
        Drain(client, ParkingBytes);

        // Well past the handler's delay, so its DecRef and the recycle it triggers have both run
        // before the descriptors are counted.
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
