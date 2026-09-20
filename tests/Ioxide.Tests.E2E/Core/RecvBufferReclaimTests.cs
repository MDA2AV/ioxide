using System.IO.Pipelines;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Recv buffers a <see cref="TcpConnectionPipeReader"/> is still holding when its connection is
/// recycled.
/// </summary>
/// <remarks>
/// The reader pulls buffers out of the connection's recv queue to hand their memory straight to the
/// caller - <c>TryGetItem</c> is a dequeue, so from that moment the connection has no record of
/// them. <c>DrainRecv</c> at recycle walks that queue and finds nothing, so anything the reader
/// holds comes back only if someone calls <c>Complete()</c>.
///
/// Nothing enforces that on the plaintext path: <see cref="TcpConnectionDualPipe"/> is two
/// properties with no disposal, unlike the TLS pipe. A handler that returns early - the ordinary
/// shape when a peer disconnects mid-request - takes its buffers with it, and in shared mode those
/// are slots out of one group the whole reactor draws from, gone for the life of the process.
/// </remarks>
internal static class RecvBufferReclaimTests
{
    /// <summary>Small enough that a per-connection leak exhausts it well inside the run.</summary>
    private const int RecvSlots = 16;

    /// <summary>Several times the group, so a leak cannot hide behind slack.</summary>
    private const int Connections = 64;

    private static ServerConfig SmallGroup() => new()
    {
        RecvBufferSize = 1024,
        RecvSlots = RecvSlots,
        Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 64, RecvQueueEntries = 16 },
    };

    /// <summary>
    /// Opens <see cref="Connections"/> connections in turn, each sending a request and expecting a
    /// one-byte answer, and says how many were served. A stranded buffer per connection empties the
    /// group after about <see cref="RecvSlots"/> of them, and the rest go unanswered.
    /// </summary>
    private static int DriveConnections(int port, byte[]? request = null, int delayMs = 0)
    {
        request ??= "x"u8.ToArray();
        int answered = 0;

        for (int i = 0; i < Connections; i++)
        {
            try
            {
                using var client = new TcpClient();
                client.Connect("127.0.0.1", port);
                client.ReceiveTimeout = 2_000;

                if (delayMs > 0)
                {
                    Thread.Sleep(delayMs);   // let the handler reach the state under test first
                }

                client.GetStream().Write(request);

                var reply = new byte[1];
                if (client.GetStream().Read(reply, 0, 1) == 1)
                {
                    answered++;
                }
            }
            catch (Exception)
            {
                break;   // the group is empty: this connection can no longer be read from
            }
        }

        return answered;
    }

    public static void Register(Runner runner)
    {
        runner.Test("recv buffers: a handler that never completes its reader does not strand them", () =>
        {
            // The leaky shape, on purpose: read (which pulls a buffer into the reader's chain),
            // answer, and return without Complete() and without advancing. Every connection walks
            // off with at least one buffer.
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);

                ReadResult result = await reader.ReadAsync();

                if (!result.Buffer.IsEmpty)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                // No reader.Complete() - the whole point.
                conn.DecRef();
            }, SmallGroup()).Port;

            // Every connection must be served. Without reclaim this stops at about RecvSlots, once
            // the group has been emptied one stranded buffer at a time.
            Assert.Equal(Connections, DriveConnections(port));
        });

        runner.Test("recv buffers: completing one reader does not de-register a live one", () =>
        {
            // The reclaim hangs off a single slot on the connection, so the de-registration has to
            // check it still points at the reader doing the completing. It did not: a reader that
            // holds nothing, completed after a second one registered, evicted the LIVE holder and
            // put the original leak straight back - silently, because the common path has one
            // reader and never notices.
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var first = new TcpConnectionPipeReader(conn);
                var second = new TcpConnectionPipeReader(conn);   // now the registered holder

                ReadResult result = await second.ReadAsync();     // 'second' is the one holding

                if (!result.Buffer.IsEmpty)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                first.Complete();     // holds nothing - and must not evict 'second'
                conn.DecRef();        // 'second' never completed: recycle has to reclaim from it
            }, SmallGroup()).Port;

            Assert.Equal(Connections, DriveConnections(port));
        });

        runner.Test("recv buffers: completing a reader with a read still parked does not strand what lands after", () =>
        {
            // Complete() must not de-register, because completing does not disarm a parked read.
            // The awaiter stays armed, the next recv CQE resumes it, and the reader ingests buffers
            // AFTER it was completed - with nobody registered to reclaim them, which is the original
            // leak reintroduced by the fix for it. TlsConnectionDualPipe.DisposeAsync produces this
            // shape on the kTLS RX column, and so does any read-timeout handler, since
            // CancelPendingRead only sets a flag and never wakes a parked read.
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);

                // Parks: the client deliberately has not sent yet.
                Task<ReadResult> parked = reader.ReadAsync().AsTask();

                reader.Complete();            // completed, but that read is still armed

                ReadResult result = await parked;   // the client's bytes land in a completed reader

                if (!result.Buffer.IsEmpty)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                conn.DecRef();
            }, SmallGroup()).Port;

            Assert.Equal(Connections, DriveConnections(port, delayMs: 30));
        });

        runner.Test("recv buffers: a stream stopped mid-slice does not strand its buffer", () =>
        {
            // TcpConnectionStream is the other holder: it keeps the slice it is copying out and
            // returns it only once drained, and it has no disposal of its own. Reading one byte of
            // several leaves that buffer held - the shape an aborted SslStream handshake or a
            // truncated record produces, which is what Playground/Tls/SslStream runs on.
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var stream = new TcpConnectionStream(conn);

                var one = new byte[1];
                int n = await stream.ReadAsync(one);              // one byte out of eight

                if (n > 0)
                {
                    conn.Write("."u8);
                    await conn.FlushAsync();
                }

                // Neither drained nor disposed: the rest of the slice is still held.
                conn.DecRef();
            }, SmallGroup()).Port;

            Assert.Equal(Connections, DriveConnections(port, request: "xxxxxxxx"u8.ToArray()));
        });

        runner.Test("recv buffers: disposing a stream returns its buffer without waiting for recycle", () =>
        {
            // Recycle cannot help here: one connection, held open for the whole run, so the reclaim
            // never fires. The only thing that can give a buffer back is Dispose - which this type
            // inherited from Stream as a no-op, making the idiomatic
            // `new SslStream(stream, leaveInnerStreamOpen: false)` silently fail to return anything.
            // A fresh stream per round, each reading one byte of eight and leaving the rest held.
            var report = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                int served = 0;
                try
                {
                    for (int i = 0; i < Connections; i++)
                    {
                        var stream = new TcpConnectionStream(conn);

                        var one = new byte[1];
                        if (await stream.ReadAsync(one) <= 0)
                        {
                            break;
                        }

                        stream.Dispose();   // returns the slice, with seven bytes still unread in it

                        // A stream abandoned mid-snapshot never drains it, so the connection's read
                        // signal is still armed from that read; the next stream needs it re-armed.
                        conn.ResetRead();

                        conn.Write("."u8);
                        await conn.FlushAsync();
                        served++;
                    }
                }
                catch (Exception)
                {
                    // Reported as a short count.
                }
                finally
                {
                    report.TrySetResult(served);
                    conn.DecRef();
                }
            }, SmallGroup()).Port;

            using var client = new TcpClient();
            client.Connect("127.0.0.1", port);
            client.ReceiveTimeout = 2_000;
            NetworkStream io = client.GetStream();

            int answered = 0;
            for (int i = 0; i < Connections; i++)
            {
                try
                {
                    io.Write("xxxxxxxx"u8);

                    var reply = new byte[1];
                    if (io.Read(reply, 0, 1) != 1)
                    {
                        break;
                    }
                    answered++;
                }
                catch (Exception)
                {
                    break;   // the group is empty and this connection can no longer be read from
                }
            }

            // Many times the slot count, on ONE connection that never recycled.
            Assert.Equal(Connections, answered);
        });

        runner.Test("recv buffers: completing the reader returns them, with or without reclaim", () =>
        {
            // The control. Same shape, same tiny group, but the handler completes its reader - the
            // path that already worked. If this ever fails, the group is being drained by something
            // other than the defect under test and the assertion above proves nothing.
            int port = TestServer.StartConfigured(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                try
                {
                    ReadResult result = await reader.ReadAsync();

                    if (!result.Buffer.IsEmpty)
                    {
                        conn.Write("."u8);
                        await conn.FlushAsync();
                    }
                }
                finally
                {
                    reader.Complete();
                    conn.DecRef();
                }
            }, SmallGroup()).Port;

            Assert.Equal(Connections, DriveConnections(port));
        });
    }
}
