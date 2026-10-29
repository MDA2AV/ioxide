using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Full, compacting collections forced from the test thread while reactors echo data and hold handlers
/// parked in a read. A parked handler is reachable only through its connection, so a handler held where
/// a collection can take it, or a buffer the kernel reads where a collection can move it, shows here.
/// </summary>
internal static class GcTests
{
    private const int Raw = 32;
    private const int Piped = 8;
    private const int ParkedRaw = 4;
    private const int ParkedPiped = 2;
    private const long Total = 1 << 20;
    private static readonly int[] Chunks = [1, 7, 1500, 4096, 4097, 9000, 16384, 65536, 32768, 333];

    private sealed class Run
    {
        public int Collections;
        public int Finished;
        public int HandlersEnded;
    }

    public static void Register(Runner runner)
    {
        runner.Test("gc: forced compacting collections during 40 echo transfers and parked reads leave every byte and every handler intact", () =>
        {
            var run = new Run();
            int rawPort = TestServer.StartConfigured((_, conn) => RawEcho(conn, run), Config()).Port;
            int pipedPort = TestServer.StartConfigured((_, conn) => PipedEcho(conn, run), Config()).Port;

            var parked = new List<Socket>();
            var transfers = new List<Thread>();
            try
            {
                for (int i = 0; i < ParkedRaw + ParkedPiped; i++)
                {
                    parked.Add(ParkedOn(i < ParkedRaw ? rawPort : pipedPort, i));
                }

                using var go = new ManualResetEventSlim();
                long deadline = Environment.TickCount64 + 60_000;
                var failures = new string?[Raw + Piped];
                for (int i = 0; i < Raw + Piped; i++)
                {
                    int seed = i;
                    int port = i < Raw ? rawPort : pipedPort;
                    var transfer = new Thread(() =>
                    {
                        try
                        {
                            failures[seed] = go.Wait(10_000) ? Transfer(port, seed, deadline, run) : "never started";
                        }
                        catch (Exception e)
                        {
                            failures[seed] = $"{e.GetType().Name}: {e.Message}";
                        }
                        finally
                        {
                            Interlocked.Increment(ref run.Finished);
                        }
                    })
                    {
                        IsBackground = true,
                        Name = $"gc-transfer-{i}",
                    };
                    transfer.Start();
                    transfers.Add(transfer);
                }

                go.Set();
                while (Volatile.Read(ref run.Finished) < Raw + Piped && Environment.TickCount64 < deadline)
                {
                    GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
                    GC.WaitForPendingFinalizers();
                    Interlocked.Increment(ref run.Collections);
                }

                Assert.True(Volatile.Read(ref run.Finished) == Raw + Piped,
                    $"{Raw + Piped - run.Finished} of {Raw + Piped} transfers never finished");
                string[] failed = failures.Select((f, i) => f is null ? null : $"connection {i}: {f}").OfType<string>().ToArray();
                Assert.True(failed.Length == 0,
                    $"{failed.Length} of {Raw + Piped} transfers did not get every byte back as sent, through "
                    + $"{run.Collections} collections; first: {failed.FirstOrDefault()}");

                // Parked through every collection, the handlers still answer.
                for (int i = 0; i < parked.Count; i++)
                {
                    byte[] again = Encoding.ASCII.GetBytes($"again {i}");
                    parked[i].Send(again);
                    Assert.Equal($"again {i}", Encoding.ASCII.GetString(ReadExactly(parked[i], again.Length)));
                }

                // And every handler ends once its peer has gone.
                foreach (Socket socket in parked)
                {
                    socket.Dispose();
                }
                parked.Clear();

                const int handlers = Raw + Piped + ParkedRaw + ParkedPiped;
                long until = Environment.TickCount64 + 10_000;
                while (Volatile.Read(ref run.HandlersEnded) < handlers && Environment.TickCount64 < until)
                {
                    Thread.Sleep(5);
                }
                Assert.Equal(handlers, Volatile.Read(ref run.HandlersEnded));
            }
            finally
            {
                foreach (Socket socket in parked)
                {
                    socket.Dispose();
                }
                foreach (Thread transfer in transfers)
                {
                    transfer.Join(TimeSpan.FromSeconds(30));
                }
            }
        });
    }

    private static ServerConfig Config() => new()
    {
        RecvBufferSize = 4096, RecvSlots = 256,
        Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
    };

    // Echoes each delivery through the connection's own read and write. A handler counts once its peer has
    // sent something, so the harness's readiness probe is not one of them.
    private static async Task RawEcho(TcpConnection conn, Run run)
    {
        bool served = false;
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        conn.Write(item.AsSpan());
                        conn.ReturnBuffer(in item);
                        served = true;
                    }
                }

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
            if (served)
            {
                Interlocked.Increment(ref run.HandlersEnded);
            }
        }
    }

    // The same echo through the pipe adapters, which park on the connection themselves.
    private static async Task PipedEcho(TcpConnection conn, Run run)
    {
        var pipe = new TcpConnectionDualPipe(conn);
        bool served = false;
        try
        {
            while (true)
            {
                ReadResult result = await pipe.Input.ReadAsync();
                ReadOnlySequence<byte> buffer = result.Buffer;
                foreach (ReadOnlyMemory<byte> segment in buffer)
                {
                    pipe.Output.Write(segment.Span);
                    served = true;
                }

                pipe.Input.AdvanceTo(buffer.End);
                if (pipe.Output.UnflushedBytes > 0)
                {
                    await pipe.Output.FlushAsync();
                }

                if (result.IsCompleted)
                {
                    return;
                }
            }
        }
        finally
        {
            pipe.Input.Complete();
            pipe.Output.Complete();
            conn.DecRef();
            if (served)
            {
                Interlocked.Increment(ref run.HandlersEnded);
            }
        }
    }

    // The byte at offset of connection seed's stream: bytes lost, repeated, reordered or crossed from
    // another connection all show.
    private static byte ByteAt(int seed, long offset) => unchecked((byte)(offset * 131 + seed * 7919 + (offset >> 11)));

    // Sends the stream in chunks of many sizes, each read back before the next, past Total until three
    // collections have run during it. Null when every byte came back as sent.
    private static string? Transfer(int port, int seed, long deadline, Run run)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            ReceiveTimeout = 20_000,
            SendTimeout = 20_000,
        };
        socket.Connect(IPAddress.Loopback, port);

        byte[] chunk = new byte[Chunks.Max()];
        int startedAt = Volatile.Read(ref run.Collections);
        long offset = 0;
        for (int round = 0; offset < Total || Volatile.Read(ref run.Collections) - startedAt < 3; round++)
        {
            if (Environment.TickCount64 > deadline)
            {
                return $"out of time at offset {offset}, {run.Collections - startedAt} collections in";
            }

            int size = Chunks[round % Chunks.Length];
            for (int i = 0; i < size; i++)
            {
                chunk[i] = ByteAt(seed, offset + i);
            }

            for (int sent = 0; sent < size;)
            {
                sent += socket.Send(chunk, sent, size - sent, SocketFlags.None);
            }

            byte[] back = ReadExactly(socket, size);
            int same = back.AsSpan().CommonPrefixLength(chunk.AsSpan(0, size));
            if (same < size)
            {
                return $"byte {offset + same} was {back[same]}, not {chunk[same]}";
            }

            offset += size;
        }

        return null;
    }

    // A connection whose handler has echoed one message and gone back to wait in its read.
    private static Socket ParkedOn(int port, int i)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 10_000 };
        try
        {
            socket.Connect(IPAddress.Loopback, port);
            byte[] hello = Encoding.ASCII.GetBytes($"hello {i}");
            socket.Send(hello);
            Assert.Equal($"hello {i}", Encoding.ASCII.GetString(ReadExactly(socket, hello.Length)));
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static byte[] ReadExactly(Socket socket, int count)
    {
        byte[] buffer = new byte[count];
        for (int got = 0; got < count;)
        {
            int n = socket.Receive(buffer, got, count - got, SocketFlags.None);
            if (n == 0)
            {
                throw new IOException($"the server closed after {got} of {count} bytes");
            }
            got += n;
        }
        return buffer;
    }
}
