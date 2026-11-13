using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.utils;
using Microsoft.Win32.SafeHandles;

namespace Ioxide.Tests;

/// <summary>
/// The TCP write side as an <see cref="IBufferWriter{T}"/> and a <see cref="PipeWriter"/>: GetSpan past
/// the slab, Advance past what was handed out, the counts a writer reads, and a write and flush made
/// after the peer has gone. And a file read into the write buffer (ReadFileAsync, AdvanceWrite): where
/// its bytes land behind what was written before them, a read during a flush, and one after the peer
/// has gone.
/// </summary>
/// <remarks>
/// Already pinned elsewhere: Write past the slab in both overflow strategies, a GetSpan the slab cannot
/// grow to (CoreTests), the size of each spill segment (SpillSegmentTests), the TLS writer above
/// this one (the TLS suite's WriterContractTests), and a file served through ReadFileAsync (the File
/// suite's FileTests).
/// </remarks>
internal static class WriteContractTests
{
    // Small, so modest writes outgrow it.
    private const int Slab = 4096;

    public static void Register(Runner runner)
    {
        foreach (WriteOverflowStrategy strategy in new[] { WriteOverflowStrategy.Grow, WriteOverflowStrategy.Segmented })
        {
            runner.Test($"tcp writer: GetSpan asking for more than the slab grows it, and the bytes arrive ({strategy})", () =>
            {
                byte[] body = Pattern(100_000, 1);

                (List<string> noted, byte[] received) = Exchange(strategy, async (conn, _, notes) =>
                {
                    if (StageThroughGetSpan(conn, body, notes))
                    {
                        await conn.FlushAsync();
                    }
                });

                Assert.Equal("handed out at least 100000: True", string.Join(" | ", noted));
                AssertReceived(body, received);
            });
        }

        foreach (WriteOverflowStrategy strategy in new[] { WriteOverflowStrategy.Grow, WriteOverflowStrategy.Segmented })
        {
            runner.Test($"tcp writer: Advance past what GetSpan handed out throws, and commits nothing ({strategy})", () =>
            {
                // Segmented fills the slab first, so the span comes from an overflow segment, twice the slab.
                bool spill = strategy == WriteOverflowStrategy.Segmented;
                byte[] lead = spill ? Pattern(Slab, 3) : [];
                int handedOut = spill ? 2 * Slab : Slab;
                byte[] body = Pattern(handedOut, 2);

                (List<string> noted, byte[] received) = Exchange(strategy, async (_, writer, notes) =>
                {
                    if (lead.Length > 0)
                    {
                        writer.Write(lead);
                    }

                    // A count that was taken leaves the slab claiming bytes past its end, so it is not flushed.
                    if (AdvancePastHandedOut(writer, body, notes))
                    {
                        await writer.FlushAsync();
                    }
                });

                Assert.Equal(string.Join(" | ",
                    $"handed out {handedOut}",
                    $"advance({handedOut + 1}): refused",
                    $"advance({int.MaxValue}): refused",
                    "advance(-1): refused",
                    $"unflushed {lead.Length}, writable {handedOut}",
                    $"unflushed {lead.Length + handedOut}"), string.Join(" | ", noted));
                AssertReceived([.. lead, .. body], received);
            });
        }

        runner.Test("tcp writer: the unflushed and writable counts are exact, through a growth and a flush", () =>
        {
            byte[] body = Pattern(4100, 3);

            (List<string> noted, byte[] received) = Exchange(WriteOverflowStrategy.Grow, async (_, writer, notes) =>
            {
                void Note(string step) => notes.Add($"{step}: unflushed {writer.UnflushedBytes}, writable {writer.GetSpan(1).Length}");

                Note("fresh");
                writer.Write(body.AsSpan(0, 1000));
                Note("write 1000");
                body.AsSpan(1000, 100).CopyTo(writer.GetSpan(100));
                Note("GetSpan(100)");
                writer.Advance(100);
                Note("advance 100");
                writer.Write(body.AsSpan(1100, 3000));   // past the slab, which doubles
                Note("write 3000");
                await writer.FlushAsync();
                Note("flush");   // the slab keeps its growth until the connection is recycled
            });

            Assert.Equal(string.Join(" | ",
                $"fresh: unflushed 0, writable {Slab}",
                "write 1000: unflushed 1000, writable 3096",
                "GetSpan(100): unflushed 1000, writable 3096",
                "advance 100: unflushed 1100, writable 2996",
                "write 3000: unflushed 4100, writable 4092",
                $"flush: unflushed 0, writable {2 * Slab}"), string.Join(" | ", noted));
            AssertReceived(body, received);
        });

        runner.Test("tcp writer: a write and a flush after the peer has gone are dropped, not thrown", () =>
        {
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var writer = new TcpConnectionPipeWriter(conn);
                bool peerSent = false;
                try
                {
                    RecvSnapshot snapshot;
                    do
                    {
                        snapshot = await conn.ReadAsync();
                        peerSent |= Discard(conn, snapshot);
                    }
                    while (!snapshot.IsClosed);

                    if (peerSent)   // not the harness's readiness probe
                    {
                        outcome.TrySetResult(await WriteToGonePeer(conn, writer));
                    }
                }
                catch (Exception e) when (peerSent)
                {
                    outcome.TrySetResult($"threw {e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    writer.Complete();
                    conn.DecRef();
                }
            }, Config(WriteOverflowStrategy.Grow)).Port;

            using (var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                client.Connect(IPAddress.Loopback, port);
                client.Send("bye"u8);
            }

            Assert.True(outcome.Task.Wait(TimeSpan.FromSeconds(10)), "the handler never saw the peer go");
            Assert.Equal(string.Join(" | ",
                "connection: 65537 B given back",
                "pipe: staged 65537, 65537 B given back, completed True",
                "again: completed True, closed True"), outcome.Task.Result);
        });

        RegisterFileRead(runner);
    }

    // ReadFileAsync reads a file into the write buffer where the next write would go, and AdvanceWrite
    // commits it there. Each file is a pattern of its own, so a byte out of place names where it came from.
    private static void RegisterFileRead(Runner runner)
    {
        foreach (WriteOverflowStrategy strategy in new[] { WriteOverflowStrategy.Grow, WriteOverflowStrategy.Segmented })
        {
            runner.Test($"tcp writer: a file read goes out after the head written before it, when that head outgrew the slab ({strategy})", () =>
            {
                byte[] content = Pattern(3000, 5);
                using SafeFileHandle file = FileOf(content);
                int fd = (int)file.DangerousGetHandle();

                // Two responses behind one flush, as pipelined requests are answered. The first fits the slab
                // and leaves less than the second's head, which Segmented spills: its file read has to follow
                // it into the spill segment, as every write after a spill does.
                byte[] first = Pattern(100, 6);
                byte[] second = Pattern(1500, 7);

                (List<string> noted, byte[] received) = Exchange(strategy, async (conn, writer, notes) =>
                {
                    writer.Write(first);
                    int a = await conn.ReadFileAsync(fd, content.Length, 0);
                    conn.AdvanceWrite(a);
                    writer.Write(second);
                    int b = await conn.ReadFileAsync(fd, content.Length, 0);
                    conn.AdvanceWrite(b);
                    await writer.FlushAsync();
                    notes.Add($"read {a} and {b}");
                });

                Assert.Equal("read 3000 and 3000", string.Join(" | ", noted));
                AssertReceived([.. first, .. content, .. second, .. content], received);
            });
        }

        runner.Test("tcp writer: under Segmented, a file read the slab cannot hold spills into a segment, and the slab keeps its size", () =>
        {
            byte[] content = Pattern(6000, 8);   // more than the slab has left behind the head
            using SafeFileHandle file = FileOf(content);
            int fd = (int)file.DangerousGetHandle();
            byte[] head = Pattern(100, 9);

            (List<string> noted, byte[] received) = Exchange(WriteOverflowStrategy.Segmented, async (conn, writer, notes) =>
            {
                writer.Write(head);
                conn.AdvanceWrite(await conn.ReadFileAsync(fd, content.Length, 0));
                await writer.FlushAsync();
                notes.Add($"writable {conn.GetSpan(1).Length}");   // a grown slab keeps its growth until the connection is recycled
            });

            AssertReceived([.. head, .. content], received);
            Assert.Equal($"writable {Slab}", string.Join(" | ", noted));
        });

        runner.Test("tcp writer: a file read and its commit are refused while a flush is in flight, and taken once it is done", () =>
        {
            byte[] content = Pattern(3000, 10);
            using SafeFileHandle file = FileOf(content);
            int fd = (int)file.DangerousGetHandle();
            byte[] head = Pattern(3000, 11);   // with the file, more than the slab holds: a read let through grows it

            (List<string> noted, byte[] received) = Exchange(WriteOverflowStrategy.Grow, async (conn, writer, notes) =>
            {
                writer.Write(head);

                // The handler runs on the reactor, which can complete the flush only once the handler awaits, so
                // both calls below are made while it is in flight.
                ValueTask<FlushResult> flush = writer.FlushAsync();
                ValueTask<int> during = ReadDuringFlush(conn, fd, content.Length, notes);
                CommitDuringFlush(conn, notes);
                await flush;
                await during;   // one let through still has to land before the next read

                int n = await conn.ReadFileAsync(fd, content.Length, 0);
                conn.AdvanceWrite(n);
                notes.Add($"after the flush: read {n}");
                await writer.FlushAsync();
            });

            Assert.Equal(string.Join(" | ",
                "read during the flush: refused (Cannot write while flush is in progress.)",
                "commit during the flush: refused (Cannot write while flush is in progress.)",
                "after the flush: read 3000"), string.Join(" | ", noted));
            AssertReceived([.. head, .. content], received);
        });

        runner.Test("tcp writer: neither a file read nor its commit goes past what the write buffer handed out", () =>
        {
            byte[] content = Pattern(3000, 12);
            using SafeFileHandle file = FileOf(content);
            int fd = (int)file.DangerousGetHandle();
            byte[] head = Pattern(100, 13);

            (List<string> noted, byte[] received) = Exchange(WriteOverflowStrategy.Grow, async (conn, writer, notes) =>
            {
                writer.Write(head);

                // The kernel is told the length, not the buffer: -1 is some 4 GiB to it, and int.MaxValue
                // overflows the tail's bound. The file is small, so one let through still fits.
                foreach (int length in new[] { -1, int.MaxValue })
                {
                    notes.Add($"read of {length}: {await TryReadFile(conn, fd, length)}");
                }

                int n = await conn.ReadFileAsync(fd, content.Length, 0);
                if (CommitPastHandedOut(conn, n, notes))
                {
                    await writer.FlushAsync();
                }
            });

            Assert.Equal(string.Join(" | ",
                "read of -1: refused (len)",
                $"read of {int.MaxValue}: refused (len)",
                $"commit({Slab - head.Length + 1}): refused",
                $"commit({int.MaxValue}): refused",
                "commit(3000): taken"), string.Join(" | ", noted));
            AssertReceived([.. head, .. content], received);
        });

        runner.Test("tcp writer: a file read once the peer has gone returns -EPIPE, where the end of the file returns 0", () =>
        {
            const int EPIPE = 32;
            byte[] content = Pattern(3000, 14);
            using SafeFileHandle file = FileOf(content);
            int fd = (int)file.DangerousGetHandle();
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                bool peerSent = false;
                try
                {
                    RecvSnapshot snapshot;
                    do
                    {
                        snapshot = await conn.ReadAsync();
                        peerSent = Discard(conn, snapshot);
                    }
                    while (!peerSent && !snapshot.IsClosed);

                    if (!peerSent)   // the harness's readiness probe
                    {
                        return;
                    }

                    // The control, while the peer waits for the reply: a read at the end of the file is 0.
                    int atEnd = await conn.ReadFileAsync(fd, 100, fileOffset: content.Length);
                    conn.Write("ready"u8);
                    await conn.FlushAsync();

                    while (!snapshot.IsClosed)
                    {
                        snapshot = await conn.ReadAsync();
                        Discard(conn, snapshot);
                    }

                    int gone = await conn.ReadFileAsync(fd, 100, fileOffset: 0);
                    outcome.TrySetResult($"at the end of the file: {atEnd} | once the peer has gone: {gone}");
                }
                catch (Exception e) when (peerSent)
                {
                    outcome.TrySetResult($"threw {e.GetType().Name}: {e.Message}");
                }
                finally
                {
                    conn.DecRef();
                }
            }, Config(WriteOverflowStrategy.Grow)).Port;

            using (var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 10_000 })
            {
                client.Connect(IPAddress.Loopback, port);
                client.Send("go"u8);

                byte[] reply = new byte[5];
                for (int got = 0, n; got < reply.Length; got += n)
                {
                    n = client.Receive(reply, got, reply.Length - got, SocketFlags.None);
                    Assert.True(n > 0, "the server closed before it replied");
                }
            }

            Assert.True(outcome.Task.Wait(TimeSpan.FromSeconds(10)), "the handler never saw the peer go");
            Assert.Equal($"at the end of the file: 0 | once the peer has gone: {-EPIPE}", outcome.Task.Result);
        });
    }

    // Synchronous, so the flush it is made during cannot finish first. One that is let through is returned to
    // be awaited, and one refused is noted with the reason.
    private static ValueTask<int> ReadDuringFlush(TcpConnection conn, int fd, int length, List<string> notes)
    {
        try
        {
            ValueTask<int> read = conn.ReadFileAsync(fd, length, 0);
            notes.Add("read during the flush: taken");
            return read;
        }
        catch (InvalidOperationException e)
        {
            notes.Add($"read during the flush: refused ({e.Message})");
            return default;
        }
    }

    private static void CommitDuringFlush(TcpConnection conn, List<string> notes)
    {
        try
        {
            conn.AdvanceWrite(1);
            notes.Add("commit during the flush: taken");
        }
        catch (InvalidOperationException e)
        {
            notes.Add($"commit during the flush: refused ({e.Message})");
        }
    }

    // A read refused is noted with the parameter it was refused for; one let through is awaited, never committed.
    private static async ValueTask<string> TryReadFile(TcpConnection conn, int fd, int length)
    {
        ValueTask<int> read;
        try
        {
            read = conn.ReadFileAsync(fd, length, 0);
        }
        catch (ArgumentOutOfRangeException e)
        {
            return $"refused ({e.ParamName})";
        }
        return $"taken, read {await read}";
    }

    // Synchronous, like AdvancePastHandedOut. False once a count past the rest of the buffer was taken, which
    // leaves the slab claiming bytes past its end, so it is not flushed.
    private static bool CommitPastHandedOut(TcpConnection conn, int read, List<string> notes)
    {
        int handedOut = conn.GetSpan(1).Length;
        foreach (int count in new[] { handedOut + 1, int.MaxValue })
        {
            try
            {
                conn.AdvanceWrite(count);
                notes.Add($"commit({count}): taken");
                return false;
            }
            catch (ArgumentOutOfRangeException)
            {
                notes.Add($"commit({count}): refused");
            }
        }

        // The control: what the read returned is taken.
        conn.AdvanceWrite(read);
        notes.Add($"commit({read}): taken");
        return true;
    }

    // A file holding `content`, already unlinked: the descriptor is all a read needs, and nothing is left behind.
    private static SafeFileHandle FileOf(byte[] content)
    {
        string path = Path.Combine(Path.GetTempPath(), $"ioxide-e2e-file-read-{Environment.ProcessId}-{Guid.NewGuid():N}");
        File.WriteAllBytes(path, content);
        SafeFileHandle file = File.OpenHandle(path);
        File.Delete(path);
        return file;
    }

    // Past the slab, so a drop is not the slab's limit at work: once through the connection's own flush,
    // then through the pipe writer's, whose result says the peer is gone. "Given back" is what the flush
    // returned to the slab.
    private static async Task<string> WriteToGonePeer(TcpConnection conn, TcpConnectionPipeWriter writer)
    {
        conn.Write(new byte[64 * 1024]);
        conn.GetSpan(1)[0] = 1;
        conn.Advance(1);
        int before = conn.GetSpan(1).Length;
        await conn.FlushAsync();
        string connection = $"connection: {conn.GetSpan(1).Length - before} B given back";

        writer.Write(new byte[64 * 1024]);
        writer.GetSpan(1)[0] = 1;
        writer.Advance(1);
        long staged = writer.UnflushedBytes;
        before = writer.GetSpan(1).Length;
        FlushResult flushed = await writer.FlushAsync();
        string pipe = $"pipe: staged {staged}, {writer.GetSpan(1).Length - before} B given back, completed {flushed.IsCompleted}";

        FlushResult again = await writer.FlushAsync();
        return $"{connection} | {pipe} | again: completed {again.IsCompleted}, closed {conn.IsClosed}";
    }

    // Synchronous, as a span cannot live across an await. False when GetSpan handed out less than asked.
    private static bool StageThroughGetSpan(TcpConnection conn, byte[] body, List<string> notes)
    {
        Span<byte> span = conn.GetSpan(body.Length);
        notes.Add($"handed out at least {body.Length}: {span.Length >= body.Length}");
        if (span.Length < body.Length)
        {
            return false;
        }

        body.CopyTo(span);
        conn.Advance(body.Length);
        return true;
    }

    // Synchronous too. False once a count past the span was taken.
    private static bool AdvancePastHandedOut(TcpConnectionPipeWriter writer, byte[] body, List<string> notes)
    {
        Span<byte> span = writer.GetSpan(10);
        int handedOut = span.Length;
        notes.Add($"handed out {handedOut}");

        foreach (int count in new[] { handedOut + 1, int.MaxValue, -1 })
        {
            try
            {
                writer.Advance(count);
                notes.Add($"advance({count}): taken");
                return false;
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException)
            {
                notes.Add($"advance({count}): refused");
            }
        }
        notes.Add($"unflushed {writer.UnflushedBytes}, writable {writer.GetSpan(1).Length}");

        // The control: exactly what was handed out is taken.
        body.AsSpan(0, handedOut).CopyTo(span);
        writer.Advance(handedOut);
        notes.Add($"unflushed {writer.UnflushedBytes}");
        return true;
    }

    private static ServerConfig Config(WriteOverflowStrategy strategy) => new()
    {
        RecvBufferSize = 4096, RecvSlots = 64,
        Tcp = new TcpOptions { WriteSlabSize = Slab, PoolMax = 8, RecvQueueEntries = 64, WriteOverflow = strategy },
    };

    /// <summary>
    /// Serves one client that sends "go" with <paramref name="write"/>, and returns what the handler noted
    /// and every byte the client read before the connection ended.
    /// </summary>
    private static (List<string> Notes, byte[] Received) Exchange(WriteOverflowStrategy strategy,
        Func<TcpConnection, TcpConnectionPipeWriter, List<string>, Task> write)
    {
        var recorded = new TaskCompletionSource<List<string>>(TaskCreationOptions.RunContinuationsAsynchronously);

        int port = TestServer.StartConfigured(async (_, conn) =>
        {
            var writer = new TcpConnectionPipeWriter(conn);
            var notes = new List<string>();
            bool peerSent = false;
            try
            {
                RecvSnapshot snapshot;
                do
                {
                    snapshot = await conn.ReadAsync();
                    peerSent = Discard(conn, snapshot);
                }
                while (!peerSent && !snapshot.IsClosed);

                if (peerSent)   // not the harness's readiness probe
                {
                    await write(conn, writer, notes);
                }
            }
            catch (Exception e)
            {
                notes.Add($"threw {e.GetType().Name}: {e.Message}");
            }
            finally
            {
                writer.Complete();
                conn.DecRef();
                if (peerSent)
                {
                    recorded.TrySetResult(notes);
                }
            }
        }, Config(strategy)).Port;

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 10_000 };
        client.Connect(IPAddress.Loopback, port);
        client.Send("go"u8);

        // To the end: the handler lets go once it has written, so a timeout here means it never ended.
        var received = new MemoryStream();
        byte[] buffer = new byte[64 * 1024];
        int n;
        while ((n = client.Receive(buffer)) > 0)
        {
            received.Write(buffer, 0, n);
        }

        Assert.True(recorded.Task.Wait(TimeSpan.FromSeconds(10)), "the handler never ran");
        return (recorded.Task.Result, received.ToArray());
    }

    // Takes everything the snapshot holds and hands it back; true when any of it was data.
    private static bool Discard(TcpConnection conn, RecvSnapshot snapshot)
    {
        bool any = false;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                any = true;
                conn.ReturnBuffer(in item);
            }
        }
        return any;
    }

    private static byte[] Pattern(int size, int seed)
    {
        var bytes = new byte[size];
        for (int i = 0; i < size; i++)
        {
            bytes[i] = unchecked((byte)((i * 31 + seed) ^ (i >> 9)));
        }
        return bytes;
    }

    private static void AssertReceived(byte[] expected, byte[] received)
    {
        Assert.Equal(expected.Length, received.Length);
        int same = received.AsSpan().CommonPrefixLength(expected);
        if (same < expected.Length)
        {
            Assert.True(false, $"byte {same} arrived as {received[same]}, not {expected[same]}");
        }
    }
}
