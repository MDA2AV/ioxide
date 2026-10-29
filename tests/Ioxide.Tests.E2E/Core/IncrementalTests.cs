using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using ioxide;
using ioxide.timer;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Incremental mode (IOU_PBUF_RING_INC, Linux 6.12+): each connection receives into a ring of its own,
/// whose buffers take slice after slice and go back only once the kernel has filled them and the reader
/// has handed back every slice. These drive what a reader does with its ring - holds it, hands it back
/// through a pipe or from another thread, gives it up at recycle - on rings of a few KiB, where a buffer
/// that never comes back stalls the connection at once.
/// </summary>
/// <remarks>
/// Already covered elsewhere: one echo over a ring (CoreTests), a ring the handler drains only after it
/// ran dry, a recv ended by a full completion queue, the group-id cap and a ring the kernel refuses
/// (HardeningTests). Ported from kron's BufferRingTest and IncrementalPortsTest (#427).
/// </remarks>
internal static class IncrementalTests
{
    // A connection's ring: four 1 KiB buffers.
    private const int Slots = 4;
    private const int BufferBytes = 1024;
    private const int RingBytes = Slots * BufferBytes;

    // What a holding handler reads first: less than a buffer, so the flood's first slice lands mid-buffer.
    private const int First = 1000;

    public static void Register(Runner runner)
    {
        bool unsupported = !TestServer.KernelAtLeast(6, 12);

        runner.Test("incremental: the pipe hands its own ring's buffers back as it advances", () =>
        {
            // Four 32-byte buffers: a pipe that kept what it consumed would dry the ring within 128 bytes
            // and stall the connection. Messages of 1 to 7 bytes, so many straddle two buffers.
            const int Rounds = 2_000;
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                long served = 0;
                try
                {
                    while (true)
                    {
                        ReadResult result = await reader.ReadAsync();
                        if (result.Buffer.IsEmpty && result.IsCompleted)
                        {
                            break;
                        }

                        foreach (ReadOnlyMemory<byte> segment in result.Buffer)
                        {
                            conn.Write(segment.Span);
                        }
                        served += result.Buffer.Length;
                        reader.AdvanceTo(result.Buffer.End);
                        await conn.FlushAsync();

                        if (result.IsCompleted)
                        {
                            break;
                        }
                    }

                    if (served > 0)   // not the harness's listen probe
                    {
                        report.TrySetResult($"served {served}");
                    }
                }
                catch (Exception e)
                {
                    report.TrySetResult($"{e.GetType().Name}: {e.Message} (after {served})");
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            }, Rings(bufferBytes: 32)).Port;

            long sent = 0;
            using (TcpClient client = Connect(port))
            {
                for (int round = 0; round < Rounds; round++)
                {
                    byte[] message = Pattern(sent, round % 7 + 1);
                    client.GetStream().Write(message);
                    AssertEchoed(client, message, $"round {round}, after {sent} bytes");
                    sent += message.Length;
                }
            }

            Assert.True(report.Task.Wait(10_000), "the handler never reported");
            Assert.Equal($"served {sent}", report.Task.Result);
        }, skip: unsupported);

        runner.Test("incremental: a slow reader pauses its connection and resumes it without losing a byte", () =>
        {
            const int Total = 64 * RingBytes;
            var holder = new Holder();
            int port = TestServer.StartConfigured(HoldThenDrain(holder, Total), Rings()).Port;
            byte[] payload = Pattern(0, Total);

            using TcpClient client = Connect(port);
            NetworkStream stream = client.GetStream();
            stream.Write(payload, 0, First);
            Assert.True(holder.Holding.Task.Wait(10_000), "the handler never got the first bytes");

            Flood flood = Flood.Start(stream, payload, First);
            Assert.True(Paused(holder.Holding.Task.Result),
                "the ring never ran dry while the handler held it, so the connection was never paused" + flood.Failure);

            Volatile.Write(ref holder.Released, 1);
            Assert.True(holder.Report.Task.Wait(30_000), "the handler never read the rest" + flood.Failure);
            Assert.Equal($"{Total} bytes, first wrong at -1", holder.Report.Task.Result);
            AssertDone(stream);
            flood.Join();
        }, skip: unsupported);

        runner.Test("incremental: other connections are served while one is paused on its own ring", () =>
        {
            const int Total = 16 * RingBytes;
            var holder = new Holder();
            int port = TestServer.StartConfigured(HoldThenDrain(holder, Total), Rings()).Port;
            byte[] payload = Pattern(0, Total);

            using TcpClient flooder = Connect(port);
            NetworkStream stream = flooder.GetStream();
            stream.Write(payload, 0, First);
            Assert.True(holder.Holding.Task.Wait(10_000), "the first connection's handler never got its first bytes");
            TcpConnection holding = holder.Holding.Task.Result;

            Flood flood = Flood.Start(stream, payload, First);
            Assert.True(Paused(holding), "the first connection's ring never ran dry, so it was never paused" + flood.Failure);
            int waiting = Unread(holding.ClientFd);

            using (TcpClient other = Connect(port))
            {
                for (int round = 0; round < 20; round++)
                {
                    byte[] message = Encoding.ASCII.GetBytes($"while the first waits, round {round}");
                    other.GetStream().Write(message);
                    AssertEchoed(other, message, $"round {round}");
                }
            }

            // None of what was waiting was taken meanwhile: the other was served while the first stayed paused.
            Assert.True(Unread(holding.ClientFd) >= waiting, "the first connection resumed while the other was being served");

            Volatile.Write(ref holder.Released, 1);
            Assert.True(holder.Report.Task.Wait(30_000), "the first connection never resumed" + flood.Failure);
            Assert.Equal($"{Total} bytes, first wrong at -1", holder.Report.Task.Result);
            AssertDone(stream);
            flood.Join();
        }, skip: unsupported);

        runner.Test("incremental: slices handed back from another thread return their buffers to the ring", () =>
        {
            // Sixteen rings' worth, read on the reactor and handed back only by a thread of the test's own:
            // the stream gets through only if those returns reach the ring.
            const int Total = 16 * RingBytes;
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var batches = new BlockingCollection<(TcpConnection Conn, SpscRecvRing.Item[] Items)>();
            using var stop = new CancellationTokenSource();
            int returned = 0;

            var returner = new Thread(() =>
            {
                try
                {
                    foreach ((TcpConnection conn, SpscRecvRing.Item[] items) in batches.GetConsumingEnumerable(stop.Token))
                    {
                        foreach (SpscRecvRing.Item item in items)
                        {
                            conn.ReturnBuffer(in item);
                        }
                        Interlocked.Add(ref returned, items.Length);
                    }
                }
                catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException)
                {
                    // the test is over
                }
            })
            {
                IsBackground = true,
                Name = "incremental-returner",
            };
            returner.Start();

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var check = new Checker();
                bool answered = false;
                try
                {
                    while (true)
                    {
                        RecvSnapshot snapshot = await conn.ReadAsync();
                        var items = new List<SpscRecvRing.Item>();
                        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                        {
                            if (item.HasBuffer)
                            {
                                check.Take(item.AsSpan());
                                items.Add(item);
                            }
                        }
                        if (items.Count > 0)
                        {
                            batches.Add((conn, items.ToArray()));
                        }

                        if (check.Got >= Total && !answered)
                        {
                            answered = true;
                            report.TrySetResult(check.ToString());
                            conn.Write("done"u8);
                            await conn.FlushAsync();
                        }

                        if (snapshot.IsClosed)
                        {
                            return;
                        }
                    }
                }
                finally
                {
                    conn.DecRef();
                }
            }, Rings()).Port;

            try
            {
                using TcpClient client = Connect(port);
                client.GetStream().Write(Pattern(0, Total));

                Assert.True(report.Task.Wait(15_000),
                    $"the stream stalled with {Volatile.Read(ref returned)} slices handed back: they never reached the ring");
                Assert.Equal($"{Total} bytes, first wrong at -1", report.Task.Result);
                AssertDone(client.GetStream());
            }
            finally
            {
                stop.Cancel();
                returner.Join(5_000);
            }
        }, skip: unsupported);

        runner.Test("incremental: a recycled connection gives its ring and its group id back", () =>
        {
            // Two group ids, and forty connections in turn: each is served only if an earlier one's id came
            // back with its ring unregistered, as the kernel refuses an id it still holds. Each echoes words
            // of its own, so a ring that kept the last connection's offsets answers with other bytes.
            int port = TestServer.StartConfigured(Echo, Rings(maxConnections: 2)).Port;

            for (int i = 0; i < 40; i++)
            {
                byte[] message = Encoding.ASCII.GetBytes($"connection {i:D2}, on a recycled ring");
                using TcpClient client = ConnectServed(port, message, $"connection {i}");
            }
        }, skip: unsupported);

        runner.Test("incremental: every extra-port listener is served on the incremental ring, with its ListenerPort", () =>
        {
            ushort[] extra = [(ushort)TestServer.NextPort(), (ushort)TestServer.NextPort()];
            int port = TestServer.StartConfigured(AnswerListenerPort, Rings(extraPorts: extra)).Port;

            // Twice around, so each listener is seen to go on accepting, onto connections back from the pool.
            for (int round = 0; round < 2; round++)
            {
                foreach (int dialed in new[] { port, extra[0], extra[1] })
                {
                    (int status, string body) = Client.Get(dialed, "/");
                    Assert.True(status == 200 && body == dialed.ToString(),
                        $"round {round}: the connection dialed to {dialed} was answered {status} \"{body}\"");
                }
            }
        }, skip: unsupported);

        // A handler not reading leaves the completions in the receive queue; each slice continuing the last
        // one queued grows it, so 200 one-byte sends fit a 64-entry queue (#431).
        runner.Test("incremental: a peer trickling bytes to a reader that is not reading does not overflow its recv queue", () =>
        {
            Assert.Equal("all 200 bytes, in order", Trickle(segments: 200));
        }, skip: unsupported);

        runner.Test("incremental: a reader taking slices on another thread while the peer trickles gets every byte", () =>
        {
            // The reactor grows the last item while that thread may be taking it: one of the two has its length,
            // and a growth the take missed would leave a gap in what the reader sees.
            const int Total = 20_000;
            var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var reader = new Thread(() =>
                {
                    var check = new Checker();
                    try
                    {
                        RecvSnapshot snapshot;
                        do
                        {
                            ValueTask<RecvSnapshot> read = conn.ReadAsync();
                            snapshot = read.IsCompleted ? read.Result : read.AsTask().Result;
                            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                            {
                                if (item.HasBuffer)
                                {
                                    check.Take(item.AsSpan());
                                    conn.ReturnBuffer(in item);
                                }
                            }
                        }
                        while (check.Got < Total && !snapshot.IsClosed);

                        if (check.Got > 0)   // not the harness's listen probe
                        {
                            report.TrySetResult(check.ToString());
                        }
                    }
                    catch (Exception e)
                    {
                        report.TrySetResult($"{e.GetType().Name} after {check.Got} bytes: {e.Message}");
                    }
                    finally
                    {
                        done.TrySetResult();
                    }
                })
                {
                    IsBackground = true,
                    Name = "incremental-reader",
                };
                reader.Start();

                try
                {
                    await done.Task;
                }
                finally
                {
                    conn.DecRef();
                }
            }, Rings()).Port;

            using TcpClient client = Connect(port);
            NetworkStream stream = client.GetStream();
            byte[] bytes = Pattern(0, Total);
            for (int i = 0; i < Total; i++)
            {
                stream.Write(bytes, i, 1);
            }

            Assert.True(report.Task.Wait(30_000), "the reader never got every byte");
            Assert.Equal($"{Total} bytes, first wrong at -1", report.Task.Result);
        }, skip: unsupported);

        runner.Test("incremental: control: the same bytes in a few large segments reach a reader that is not reading", () =>
        {
            Assert.Equal("all 200 bytes, in order", Trickle(segments: 4));
        }, skip: unsupported);
    }

    // One reactor whose connections each receive into four buffers of `bufferBytes`.
    private static ServerConfig Rings(int bufferBytes = BufferBytes, int maxConnections = 8, ushort[]? extraPorts = null) => new()
    {
        Incremental = new IncrementalOptions { MaxConnections = maxConnections, RecvSlots = Slots, RecvBufferSize = bufferBytes },
        Tcp = new TcpOptions
        {
            WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64, ExtraPorts = extraPorts ?? [],
        },
    };

    // Byte i of a stream: a hash of its position, so a byte lost, repeated or out of place shows wherever it falls.
    private static byte At(long i) => (byte)(((ulong)i * 0x9E3779B97F4A7C15UL) >> 56);

    private static byte[] Pattern(long from, int count)
    {
        var bytes = new byte[count];
        for (int k = 0; k < count; k++)
        {
            bytes[k] = At(from + k);
        }
        return bytes;
    }

    // Takes a stream slice by slice and remembers where its first wrong byte was.
    private sealed class Checker
    {
        public long Got;
        public long FirstWrong = -1;

        public void Take(ReadOnlySpan<byte> slice)
        {
            Check(slice, Got);
            Got += slice.Length;
        }

        public void Check(ReadOnlySpan<byte> slice, long at)
        {
            for (int k = 0; k < slice.Length && FirstWrong < 0; k++)
            {
                if (slice[k] != At(at + k))
                {
                    FirstWrong = at + k;
                }
            }
        }

        public override string ToString() => $"{Got} bytes, first wrong at {FirstWrong}";
    }

    // The connection that holds its ring, handed over once it holds, then what it read.
    private sealed class Holder
    {
        public readonly TaskCompletionSource<TcpConnection> Holding = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<string> Report = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Released;
        public int Claimed;
    }

    /// <summary>
    /// The first connection to deliver data reads once and holds what it got until released, then reads the
    /// rest with a ring wait before each read, so its peer gets ahead and the ring runs dry again and again,
    /// and answers "done". Every byte is checked, the held ones again once the flood has landed around them.
    /// Every other connection echoes.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> HoldThenDrain(Holder holder, int total) => async (reactor, conn) =>
    {
        try
        {
            RecvSnapshot snapshot = await conn.ReadAsync();
            var first = new List<SpscRecvRing.Item>();
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    first.Add(item);
                }
            }

            if (first.Count == 0)
            {
                return;   // the harness's listen probe
            }

            if (Interlocked.Exchange(ref holder.Claimed, 1) != 0)
            {
                foreach (SpscRecvRing.Item item in first)
                {
                    conn.Write(item.AsSpan());
                    conn.ReturnBuffer(in item);
                }
                await conn.FlushAsync();
                await EchoUntilClosed(conn, snapshot);
                return;
            }

            var check = new Checker();
            var held = new List<(SpscRecvRing.Item Item, long At)>();
            foreach (SpscRecvRing.Item item in first)
            {
                held.Add((item, check.Got));
                check.Take(item.AsSpan());
            }
            holder.Holding.TrySetResult(conn);

            var timer = new RingTimer(reactor);
            while (Volatile.Read(ref holder.Released) == 0)
            {
                await timer.DelayAsync(5);
            }

            foreach ((SpscRecvRing.Item item, long at) in held)
            {
                check.Check(item.AsSpan(), at);
                conn.ReturnBuffer(in item);
            }

            while (check.Got < total && !snapshot.IsClosed)
            {
                await timer.DelayAsync(1);
                snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        check.Take(item.AsSpan());
                        conn.ReturnBuffer(in item);
                    }
                }
            }

            holder.Report.TrySetResult(check.ToString());
            conn.Write("done"u8);
            await conn.FlushAsync();
        }
        finally
        {
            conn.DecRef();
        }
    };

    // Echoes each slice and hands its buffer straight back.
    private static async Task Echo(Reactor _, TcpConnection conn)
    {
        try
        {
            await EchoUntilClosed(conn, new RecvSnapshot(0, isClosed: false));
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task EchoUntilClosed(TcpConnection conn, RecvSnapshot last)
    {
        while (!last.IsClosed)
        {
            last = await conn.ReadAsync();
            while (conn.TryGetItem(last, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    conn.Write(item.AsSpan());
                    conn.ReturnBuffer(in item);
                }
            }
            await conn.FlushAsync();
        }
    }

    // Answers each request with the port its connection was accepted on.
    private static async Task AnswerListenerPort(Reactor _, TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                bool request = false;
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        request = true;
                        conn.ReturnBuffer(in item);
                    }
                }

                if (request)
                {
                    Wire.Write(conn, 200, conn.ListenerPort.ToString());
                    await conn.FlushAsync();
                }

                if (snapshot.IsClosed)
                {
                    return;
                }
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    /// <summary>
    /// 200 bytes in <paramref name="segments"/> sends, apart, so each lands as a recv completion of its own,
    /// to a handler that takes no snapshot until they have all been sent. Says what the handler got.
    /// </summary>
    private static string Trickle(int segments)
    {
        const int Bytes = 200;
        var report = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        int released = 0;

        int port = TestServer.StartConfigured(async (reactor, conn) =>
        {
            try
            {
                var timer = new RingTimer(reactor);
                while (Volatile.Read(ref released) == 0 && !conn.IsClosed)
                {
                    await timer.DelayAsync(5);
                }

                var check = new Checker();
                RecvSnapshot snapshot;
                do
                {
                    snapshot = await conn.ReadAsync();
                    while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                    {
                        if (item.HasBuffer)
                        {
                            check.Take(item.AsSpan());
                            conn.ReturnBuffer(in item);
                        }
                    }
                }
                while (check.Got < Bytes && !snapshot.IsClosed);

                if (check.Got == 0)
                {
                    return;   // the harness's listen probe
                }

                string got = check.Got == Bytes && check.FirstWrong < 0 ? $"all {Bytes} bytes, in order" : check.ToString();
                if (check.Got < Bytes)
                {
                    got += ", then the connection closed" + (conn.RecvOverflowed ? " on a receive-queue overflow" : "");
                }
                report.TrySetResult(got);
            }
            finally
            {
                conn.DecRef();
            }
        }, Rings()).Port;

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        client.Connect(IPAddress.Loopback, port);

        byte[] bytes = Pattern(0, Bytes);
        int size = Bytes / segments;
        string failed = "";
        try
        {
            for (int sent = 0; sent < Bytes; sent += size)
            {
                client.Send(bytes, sent, size, SocketFlags.None);
                Thread.Sleep(2);
            }
        }
        catch (SocketException e)
        {
            failed = $"; a send failed with {e.SocketErrorCode}";
        }

        Thread.Sleep(50);
        Volatile.Write(ref released, 1);

        Assert.True(report.Task.Wait(10_000), "the handler never reported" + failed);
        return report.Task.Result + failed;
    }

    private static TcpClient Connect(int port)
    {
        var client = new TcpClient { NoDelay = true };
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 10_000;
        client.SendTimeout = 30_000;   // longer than any hold, so only a server that stopped reading for good trips it
        return client;
    }

    // Connects until one is served: past the group-id cap a connection is shed, and an id frees when the
    // reactor recycles a connection, on its own schedule. A connection served the wrong bytes fails at once.
    private static TcpClient ConnectServed(int port, byte[] message, string what)
    {
        long deadline = Environment.TickCount64 + 10_000;
        string last = "";

        while (Environment.TickCount64 < deadline)
        {
            TcpClient client = Connect(port);
            client.ReceiveTimeout = 2_000;
            byte[] echoed = new byte[message.Length];
            int got = 0;
            try
            {
                client.GetStream().Write(message);
                int n;
                while (got < echoed.Length && (n = client.GetStream().Read(echoed, got, echoed.Length - got)) > 0)
                {
                    got += n;
                }
                last = $"closed after {got} bytes";
            }
            catch (IOException e)
            {
                last = e.Message;
            }

            if (got == message.Length)
            {
                if (!echoed.AsSpan().SequenceEqual(message))
                {
                    client.Dispose();
                    throw new Exception($"{what} was answered \"{Encoding.ASCII.GetString(echoed)}\" for \"{Encoding.ASCII.GetString(message)}\"");
                }
                return client;
            }

            client.Dispose();
            Thread.Sleep(20);
        }

        throw new Exception($"{what} was never served: {last}");
    }

    private static void AssertEchoed(TcpClient client, byte[] message, string when)
    {
        byte[] echoed = new byte[message.Length];
        try
        {
            client.GetStream().ReadExactly(echoed);
        }
        catch (IOException e)
        {
            throw new IOException($"{when}: no echo: {e.Message}", e);
        }
        Assert.True(echoed.AsSpan().SequenceEqual(message),
            $"{when}: echoed [{Convert.ToHexString(echoed)}] for [{Convert.ToHexString(message)}]");
    }

    private static void AssertDone(NetworkStream stream)
    {
        byte[] done = new byte[4];
        stream.ReadExactly(done);
        Assert.Equal("done", Encoding.ASCII.GetString(done));
    }

    // The rest of a payload, written from a thread of its own: the write blocks while the server holds its ring.
    private sealed class Flood
    {
        private readonly Thread _thread;
        private Exception? _failure;

        private Flood(NetworkStream stream, byte[] payload, int from)
        {
            _thread = new Thread(() =>
            {
                try
                {
                    stream.Write(payload, from, payload.Length - from);
                }
                catch (Exception e)
                {
                    _failure = e;
                }
            })
            {
                IsBackground = true,
                Name = "incremental-flood",
            };
        }

        public static Flood Start(NetworkStream stream, byte[] payload, int from)
        {
            var flood = new Flood(stream, payload, from);
            flood._thread.Start();
            return flood;
        }

        public string Failure => Volatile.Read(ref _failure) is { } e ? $" (the flood failed: {e.Message})" : "";

        public void Join()
        {
            Assert.True(_thread.Join(10_000), "the flood never finished sending");
            Assert.True(Volatile.Read(ref _failure) is null, $"the flood failed: {_failure?.Message}");
        }
    }

    /// <summary>
    /// Whether <paramref name="conn"/> is paused: still open, with bytes waiting on its socket that a quarter
    /// of a second later are all still there. An armed recv takes them as they land, so they stay only while
    /// the recv is parked.
    /// </summary>
    private static bool Paused(TcpConnection conn)
    {
        long deadline = Environment.TickCount64 + 10_000;
        int last = -1;
        int still = 0;

        while (Environment.TickCount64 < deadline)
        {
            int waiting = Unread(conn.ClientFd);
            still = waiting > 0 && waiting == last && !conn.IsClosed ? still + 1 : 0;
            if (still == 5)
            {
                return true;
            }

            last = waiting;
            Thread.Sleep(50);
        }

        return false;
    }

    private const ulong Fionread = 0x541B;

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request, out int value);

    // Bytes received on the socket that nothing has read yet.
    private static int Unread(int fd) => ioctl(fd, Fionread, out int waiting) == 0 ? waiting : -1;
}
