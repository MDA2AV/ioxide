using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// The TCP write side as an <see cref="IBufferWriter{T}"/> and a <see cref="PipeWriter"/>: GetSpan past
/// the slab, Advance past what was handed out, the counts a writer reads, and a write and flush made
/// after the peer has gone.
/// </summary>
/// <remarks>
/// Already pinned elsewhere: Write past the slab in both overflow strategies, a GetSpan the slab cannot
/// grow to (CoreTests), the size of each spill segment (SpillSegmentTests), and the TLS writer above
/// this one (the TLS suite's WriterContractTests).
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
