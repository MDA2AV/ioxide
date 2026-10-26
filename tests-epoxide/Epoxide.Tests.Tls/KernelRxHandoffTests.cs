using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using epoxide;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// The kTLS RX handoff when the client's first records leave in the same send as its last
/// handshake record: every byte after that record has to reach the kernel, which decrypts it.
/// </summary>
/// <remarks>
/// The client holds back everything it writes after its ClientHello and sends it in one go once the
/// request is written. Over loopback that send arrives whole, so where each of the server's recvs
/// ends is set by TestServer's 4 KiB recv buffers, not by timing.
/// </remarks>
internal static class KernelRxHandoffTests
{
    // TestServer's recv buffers: one recv takes at most this much.
    private const int RecvBufferSize = 4096;

    // A TLS 1.3 AES-GCM record on the wire: the 5-byte header, the plaintext, its content type byte
    // and a 16-byte tag.
    private const int RecordOverhead = 5 + 1 + 16;

    private enum Burst
    {
        /// <summary>A 40,000-byte request: the first recv ends inside its first record.</summary>
        Large,

        /// <summary>A first record that ends exactly where the first recv does, then a second one.</summary>
        Aligned,

        /// <summary>The send stops halfway through the first record for a moment, then goes on.</summary>
        Paused,
    }

    public static void Register(Runner runner, bool ktls)
    {
        // The same bursts with BoringSSL decrypting, so a failure below is about the handoff and not
        // about the client.
        runner.Test("ktls rx: control - the same bursts arrive intact when BoringSSL decrypts", () =>
        {
            foreach (Burst burst in new[] { Burst.Large, Burst.Aligned })
            {
                Outcome outcome = Serve(Options(kernelRx: false), burst, lateHandshake: false);
                Assert.True(outcome.Intact, $"{burst}: the request did not arrive as sent: {outcome}");
            }
        });

        runner.Test("ktls rx: a request larger than one recv, sent with the client's last handshake record, is decrypted by the kernel", () =>
        {
            Outcome outcome = Serve(Options(kernelRx: true), Burst.Large, lateHandshake: false);
            Assert.True(outcome.Intact, "the request did not arrive as sent: " + outcome);
            Assert.True(outcome.KernelRx, "the handshake did not hand the read side to the kernel: " + outcome);
        }, skip: !ktls);

        runner.Test("ktls rx: a record behind the one that fills the first recv is decrypted, not handed over as ciphertext", () =>
        {
            Outcome outcome = Serve(Options(kernelRx: true), Burst.Aligned, lateHandshake: false);
            Assert.True(outcome.Intact, "the request did not arrive as sent: " + outcome);
            Assert.True(outcome.KernelRx, "the handshake did not hand the read side to the kernel: " + outcome);
        }, skip: !ktls);

        // On epoll a read takes one recv and the queue never overflows - a full one stops the
        // reading - so what this keeps true is that a queue far shorter than the burst still hands
        // off at the right record.
        runner.Test("ktls rx: a burst with more completions than the receive queue holds does not overflow it during the handoff", () =>
        {
            Outcome outcome = Serve(Options(kernelRx: true), Burst.Large, lateHandshake: false, config: new ServerConfig
            {
                RecvBufferSize = RecvBufferSize,
                Tcp = new TcpOptions { RecvQueueEntries = 4 },
            });
            Assert.True(outcome.Intact, "the request did not arrive as sent: " + outcome);
            Assert.True(outcome.KernelRx, "the handshake did not hand the read side to the kernel: " + outcome);
        }, skip: !ktls);

        // The handshake's last read ends inside a record; the handoff waits for its rest.
        runner.Test("ktls rx: a record cut by a pause in the client's send is waited for, then decrypted by the kernel", () =>
        {
            Outcome outcome = Serve(Options(kernelRx: true), Burst.Paused, lateHandshake: false);
            Assert.True(outcome.Intact, "the request did not arrive as sent: " + outcome);
            Assert.True(outcome.KernelRx, "the handshake did not hand the read side to the kernel: " + outcome);
        }, skip: !ktls);

        // Nothing in the handoff depends on when the handler starts the handshake.
        runner.Test("ktls rx: a handshake started after the handler's first await is decrypted by the kernel too", () =>
        {
            Outcome outcome = Serve(Options(kernelRx: true), Burst.Large, lateHandshake: true);
            Assert.True(outcome.Intact, "the request did not arrive as sent: " + outcome);
            Assert.True(outcome.KernelRx, "the handshake did not hand the read side to the kernel: " + outcome);
        }, skip: !ktls);

        // A record cut by the end of what has arrived holds the handoff until its rest does. A client
        // that never sends it is dropped by the handshake timeout, and one that closes there ends the
        // handshake at once. Either way the connection is released.
        //
        // Known to fail on today's core: the closing client's FIN comes in the same epoll edge as its
        // half record, the recv for the parked handshake takes the half and stops short, and no edge
        // is left to report the FIN - so that client is dropped by the handshake timeout instead.
        const string cutRecordName = "ktls rx: a client that stops or closes halfway through a record after its handshake is dropped";
        Action cutRecord = () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            int port = TestServer.Start(HandshakeOnly, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath = keyPath,
                KernelTx = true,
                KernelRx = true,
                HandshakeTimeoutMs = 1_500,
            }));
            int baseline = FdCount.Stable();

            foreach (bool closes in new[] { false, true })
            {
                using TcpClient client = Connect(port);
                NetworkStream net = client.GetStream();
                var corked = new CorkedStream(net);
                using var ssl = new SslStream(corked, leaveInnerStreamOpen: true, (_, _, _, _) => true);
                ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    EnabledSslProtocols = SslProtocols.Tls13,
                });

                int handshakeBytes = corked.HeldBytes;
                ssl.Write(new byte[1_000]);
                corked.UncorkPart(handshakeBytes + (corked.HeldBytes - handshakeBytes) / 2);
                if (closes)
                {
                    client.Client.Shutdown(SocketShutdown.Send);
                }

                long start = Environment.TickCount64;
                Assert.True(ReadsToEnd(net), $"closes={closes}: the server never dropped the connection");
                long elapsed = Environment.TickCount64 - start;
                Assert.True(elapsed < (closes ? 1_000 : 4_000), $"closes={closes}: dropped only after {elapsed} ms");
            }

            int after = FdCount.Stable();
            Assert.True(after <= baseline + 2,
                $"descriptors went from {baseline} to {after}: a dropped connection was never released");
        };

        if (ktls)
        {
            runner.Test(cutRecordName, cutRecord);
        }
        else
        {
            runner.Test(cutRecordName, cutRecord, skip: true);
        }
    }

    private static TcpClient Connect(int port)
    {
        var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 6_000;
        return client;
    }

    /// <summary>Reads until the server closes. False when it never did within the receive timeout.</summary>
    private static bool ReadsToEnd(NetworkStream stream)
    {
        var buffer = new byte[256];
        try
        {
            while (stream.Read(buffer) > 0)
            {
            }
            return true;
        }
        catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
        {
            return false;
        }
        catch (IOException)
        {
            return true;   // a reset is the server giving up too
        }
    }

    private static async Task HandshakeOnly(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
        }
        catch
        {
            // Failing is what these connections are for.
        }
        finally
        {
            session?.Dispose();
            connection.DecRef();
        }
    }

    private static TlsOptions Options(bool kernelRx)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        return new TlsOptions
        {
            CertificatePath = certPath,
            KeyPath = keyPath,
            KernelTx = kernelRx,
            KernelRx = kernelRx,
        };
    }

    private sealed record Outcome(bool KernelRx, bool Intact, int Received, string Detail)
    {
        public override string ToString() => $"kernelRx={KernelRx} intact={Intact} received={Received} B {Detail}";
    }

    /// <summary>
    /// One connection: the handshake, then the burst in a single send, and what the handler made of
    /// it. The socket stays open until the handler has reported, so the server is never reading a
    /// connection the client already closed.
    /// </summary>
    private static Outcome Serve(TlsOptions options, Burst burst, bool lateHandshake, ServerConfig? config = null)
    {
        var report = new TaskCompletionSource<Outcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        Func<Reactor, TcpConnection, Task> handler = Handler(report, lateHandshake);
        Action<Reactor> start = r => TlsService.Start(r, options);
        int port = config is not null
            ? TestServer.StartConfigured(handler, config, start).Port
            : TestServer.Start(handler, start);

        using var sock = new TcpClient();
        sock.Connect("127.0.0.1", port);
        sock.NoDelay = true;
        sock.SendTimeout = 10_000;
        sock.ReceiveTimeout = 10_000;

        var corked = new CorkedStream(sock.GetStream());
        using var ssl = new SslStream(corked, leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        // What the handshake left held: the client's last handshake records.
        int handshakeBytes = corked.HeldBytes;
        int firstRecord = 0;
        foreach (byte[] record in Records(burst, handshakeBytes))
        {
            ssl.Write(record);   // one record each: none is over 16 KiB
            firstRecord = firstRecord == 0 ? corked.HeldBytes - handshakeBytes : firstRecord;
        }

        if (burst == Burst.Paused)
        {
            corked.UncorkPart(handshakeBytes + firstRecord / 2);
            Thread.Sleep(200);
        }
        corked.Uncork();

        Assert.True(report.Task.Wait(TimeSpan.FromSeconds(20)), $"{burst}: the server never reported the request");
        return report.Task.Result;
    }

    /// <summary>
    /// The request, cut into the records the burst calls for. Its first 4 bytes carry its length and
    /// the rest follow <see cref="Expected"/>, so the handler can check it without being told.
    /// </summary>
    private static IEnumerable<byte[]> Records(Burst burst, int handshakeBytes)
    {
        int[] sizes = burst switch
        {
            Burst.Large => [16 * 1024, 16 * 1024, 40_000 - 32 * 1024],
            Burst.Paused => [2_000, 64],
            _ => [RecvBufferSize - handshakeBytes - RecordOverhead, 64],
        };

        byte[] message = new byte[sizes.Sum()];
        BinaryPrimitives.WriteInt32BigEndian(message, message.Length);
        for (int i = 4; i < message.Length; i++)
        {
            message[i] = Expected(i);
        }

        int offset = 0;
        foreach (int size in sizes)
        {
            yield return message[offset..(offset + size)];
            offset += size;
        }
    }

    private static byte Expected(int index) => (byte)(index * 7 + 13);

    private static Func<Reactor, TcpConnection, Task> Handler(TaskCompletionSource<Outcome> report, bool lateHandshake)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                if (lateHandshake)
                {
                    await Task.Yield();   // continues on the thread pool, so the handshake starts from there
                }

                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness probes the port with a raw TCP connection
                }

                pipe = new TlsConnectionDualPipe(connection, session);
                report.TrySetResult(await ReadMessage(pipe.Input, session));
            }
            catch (Exception e)
            {
                report.TrySetResult(new Outcome(session?.KernelRx ?? false, false, 0, "fault: " + e.Message));
            }
            finally
            {
                if (pipe is not null)
                {
                    await pipe.DisposeAsync();
                }
                else
                {
                    session?.Dispose();
                }
                connection.DecRef();
            }
        };

    private static async Task<Outcome> ReadMessage(PipeReader input, TlsSession session)
    {
        byte[] head = new byte[4];
        int total = -1;
        int seen = 0;
        int firstWrong = -1;

        while (true)
        {
            ReadResult read = await input.ReadAsync();
            foreach (ReadOnlyMemory<byte> segment in read.Buffer)
            {
                foreach (byte b in segment.Span)
                {
                    if (seen < 4)
                    {
                        head[seen] = b;
                    }
                    else if (b != Expected(seen) && firstWrong < 0)
                    {
                        firstWrong = seen;
                    }

                    if (++seen == 4)
                    {
                        total = BinaryPrimitives.ReadInt32BigEndian(head);
                    }
                }
            }
            input.AdvanceTo(read.Buffer.End);

            if ((total >= 0 && seen >= total) || read.IsCompleted)
            {
                break;
            }
        }

        return new Outcome(session.KernelRx, seen == total && firstWrong < 0, seen,
            $"(expected {total} B, first wrong byte at {firstWrong})");
    }

    /// <summary>
    /// Sends the first write (the ClientHello) at once and holds every later one until
    /// <see cref="Uncork"/>, which sends them all in one write.
    /// </summary>
    private sealed class CorkedStream(Stream inner) : Stream
    {
        private readonly MemoryStream _held = new();
        private bool _helloSent;

        public int HeldBytes => (int)_held.Length;

        public void Uncork()
        {
            inner.Write(_held.GetBuffer(), 0, (int)_held.Length);
            _held.SetLength(0);
        }

        /// <summary>Sends the first <paramref name="count"/> held bytes and keeps holding the rest.</summary>
        public void UncorkPart(int count)
        {
            byte[] held = _held.ToArray();
            inner.Write(held, 0, count);
            _held.SetLength(0);
            _held.Write(held, count, held.Length - count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!_helloSent)
            {
                _helloSent = true;
                inner.Write(buffer);
                return;
            }
            _held.Write(buffer);
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }

        public override int Read(Span<byte> buffer) => inner.Read(buffer);

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => inner.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => inner.ReadAsync(buffer, offset, count, cancellationToken);

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
