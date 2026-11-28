using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Echo servers whose connections are moved from reactor to reactor all the time, and clients that check every byte that
/// comes back: none lost, none twice, none out of place, whichever way the handler reads and writes, wherever it runs, and
/// whatever a connection has for buffers.
/// </summary>
internal static class MoveStreamTests
{
    private const int Clients = 24;
    private const int RunMs = 1_500;

    public static void Register(Runner runner)
    {
        (string Name, Func<TcpConnection, Task> Handle)[] handlers =
        [
            ("raw", Raw),
            ("memories", Memories),
            ("pipes", Pipes),
            ("a stream", Streamed),
            ("on the thread pool", OnPool),
            ("reading and writing at once", Duplex),
        ];

        foreach ((string name, Func<TcpConnection, Task> handle) in handlers)
        {
            foreach ((string mode, Func<ServerConfig> config, bool skip) in MoveFleet.Modes())
            {
                Register(runner, $"{name}, {mode}", handle, config(), skip);
            }
        }

        bool incremental = TestServer.KernelAtLeast(6, 12);
        Register(runner, "raw, a ring of two 256-byte buffers per connection", Raw, MoveFleet.Incremental(slots: 2, size: 256), !incremental, moves: 10);   // mostly without a recv, for want of a buffer
        Register(runner, "raw, so few buffers that recvs go without", Raw, MoveFleet.Shared() with { RecvSlots = 8, RecvBufferSize = 1024 }, false);
        Register(runner, "raw, zero-copy sends", Raw, MoveFleet.Shared(new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, ZeroCopySend = true }), !TestServer.KernelAtLeast(6, 0));
        Register(runner, "raw, segments, short sends", Raw,
            MoveFleet.Shared(new TcpOptions { WriteSlabSize = 1024, PoolMax = 64, WriteOverflow = WriteOverflowStrategy.Segmented, SendWaitAll = false }), false);
    }

    private static void Register(Runner runner, string name, Func<TcpConnection, Task> handle, ServerConfig config, bool skip, int moves = 50)
    {
        runner.Test($"move stream: every byte comes back, once and in place, from connections moved all the time ({name})", () =>
        {
            using var fleet = new MoveFleet(4, handle, config);
            using var shuffle = new Moves.Shuffle(fleet.Reactors);
            using var over = new CancellationTokenSource(RunMs);

            Task<long>[] echoes = Enumerable.Range(0, Clients).Select(i => Task.Run(() => Echo(fleet.Port, i, over.Token))).ToArray();
            Assert.True(Task.WaitAll(echoes, 60_000), $"{echoes.Count(e => !e.IsCompleted)} of {Clients} clients never got all they sent back");
            long bytes = echoes.Sum(e => e.Result);

            Assert.True(bytes > 50_000, $"only {bytes} bytes came back");
            Assert.True(shuffle.Made > moves, $"only {shuffle.Made} moves were made");
        }, skip);
    }

    // Sends a stream it can recompute, in messages of random length, and checks what comes back, until all of it has.
    // Returns how much.
    private static async Task<long> Echo(int port, int id, CancellationToken over)
    {
        const int Window = 48 * 1024;
        const int MaxMessages = 16;   // in flight: a receive queue holds so many deliveries

        using Socket client = Moves.Connect(port);
        long sent = 0, back = 0;
        var unanswered = new System.Collections.Concurrent.ConcurrentQueue<long>();   // where each message ends
        using var room = new SemaphoreSlim(0);

        Task sending = Task.Run(async () =>
        {
            var random = new Random(id);
            var message = new byte[20_000];
            while (!over.IsCancellationRequested)
            {
                int length = random.Next(4) == 0 ? random.Next(1, message.Length) : random.Next(1, 300);
                while (sent + length - Volatile.Read(ref back) > Window || unanswered.Count >= MaxMessages)
                {
                    await room.WaitAsync(TimeSpan.FromSeconds(30));
                }
                for (int i = 0; i < length; i++)
                {
                    message[i] = At(id, sent + i);
                }
                unanswered.Enqueue(sent + length);
                Volatile.Write(ref sent, sent + length);
                for (int from = 0; from < length;)
                {
                    from += await client.SendAsync(message.AsMemory(from, length - from));
                }
            }
        });

        var buffer = new byte[32 * 1024];
        for (long last = Environment.TickCount64; !sending.IsCompleted || back < sent;)
        {
            using var pause = new CancellationTokenSource(500);
            int n;
            try
            {
                n = await client.ReceiveAsync(buffer, pause.Token);
                last = Environment.TickCount64;
            }
            catch (OperationCanceledException)
            {
                Assert.True(Environment.TickCount64 - last < 20_000, $"client {id}: {back} of {sent} bytes came back, and then nothing");
                continue;
            }
            Assert.True(n > 0, $"client {id}: closed after {back} of {sent} bytes");
            for (int i = 0; i < n; i++)
            {
                if (buffer[i] != At(id, back + i))
                {
                    throw new Exception($"client {id}: byte {back + i} came back wrong");
                }
            }
            Volatile.Write(ref back, back + n);
            while (unanswered.TryPeek(out long end) && end <= back)
            {
                unanswered.TryDequeue(out _);
            }
            room.Release();
        }
        await sending;
        return back;
    }

    private static byte At(int id, long position)
    {
        ulong x = ((ulong)position * 0x9E3779B97F4A7C15) + ((ulong)id * 0xC2B2AE3D27D4EB4F);
        x ^= x >> 29;
        return (byte)((x * 0xBF58476D1CE4E5B9) >> 56);
    }

    private static async Task Raw(TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                if (Copy(conn, snapshot))
                {
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

    private static bool Copy(TcpConnection conn, RecvSnapshot snapshot)
    {
        bool any = false;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                conn.Write(item.AsSpan());
                conn.ReturnBuffer(in item);
                any = true;
            }
        }
        return any;
    }

    private static async Task Memories(TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                UnmanagedMemoryManager[] memories = conn.GetSnapshotMemories(snapshot);
                foreach (UnmanagedMemoryManager memory in memories)
                {
                    conn.Write(memory.GetSpan());
                }
                conn.ReturnBuffers(memories);
                await conn.FlushAsync();
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

    private static async Task Pipes(TcpConnection conn)
    {
        var pipe = new TcpConnectionDualPipe(conn);
        try
        {
            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();
                foreach (ReadOnlyMemory<byte> segment in read.Buffer)
                {
                    pipe.Output.Write(segment.Span);
                }
                pipe.Input.AdvanceTo(read.Buffer.End);
                await pipe.Output.FlushAsync();
                if (read.IsCompleted)
                {
                    return;
                }
            }
        }
        finally
        {
            pipe.Input.Complete();
            conn.DecRef();
        }
    }

    private static async Task Streamed(TcpConnection conn)
    {
        var stream = new TcpConnectionStream(conn);
        try
        {
            var buffer = new byte[3_000];
            int n;
            while ((n = await stream.ReadAsync(buffer)) > 0)
            {
                await stream.WriteAsync(buffer.AsMemory(0, n));
            }
        }
        finally
        {
            stream.Dispose();
            conn.DecRef();
        }
    }

    // Off the reactor between its reads: what it gives back, writes and flushes, it does from the thread pool.
    private static async Task OnPool(TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync().ConfigureAwait(false);
                await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
                if (Copy(conn, snapshot))
                {
                    await conn.FlushAsync().ConfigureAwait(false);
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

    // A read waits nearly all the time, and what writes goes to the connection's reactor for it: as an HTTP/2 stack does.
    private static async Task Duplex(TcpConnection conn)
    {
        var chunks = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
            new System.Threading.Channels.UnboundedChannelOptions { AllowSynchronousContinuations = false });

        Task writing = Task.Run(async () =>
        {
            await foreach (byte[] chunk in chunks.Reader.ReadAllAsync())
            {
                await new ReactorSwitch(conn.RingHost);
                conn.Write(chunk);
                while (chunks.Reader.TryRead(out byte[]? more))
                {
                    conn.Write(more);
                }
                await conn.FlushAsync();
            }
        });

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        chunks.Writer.TryWrite(item.AsSpan().ToArray());
                        conn.ReturnBuffer(in item);
                    }
                }
                if (snapshot.IsClosed)
                {
                    return;
                }
            }
        }
        finally
        {
            chunks.Writer.Complete();
            await writing;
            conn.DecRef();
        }
    }
}
