using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using epoxide;
using epoxide.tls;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// What epoxide adds to ioxide's TLS: a session used from the thread pool - its handshake, its
/// reader and its writer, two of them at once - with nothing handed back to the reactor. An SSL
/// object is not thread-safe, so every BoringSSL call on a session takes the session's lock; these
/// are the shapes that lock exists for.
/// </summary>
internal static class ThreadPoolTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tls threadpool: a handshake, then reads and writes on two pool threads at once, keep both directions intact", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            const int Total = 8 << 20;
            var faults = new ConcurrentQueue<string>();
            var report = new TaskCompletionSource<(long Received, bool Intact, int OnReactor, bool Overlapped)>(
                TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(DuplexHandler(Total, faults, report), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = 10_000;
            tcp.SendTimeout = 10_000;
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            // Both directions at once from the client too, so the server's reader and writer overlap.
            string? sendFault = null;
            var sender = new Thread(() =>
            {
                try
                {
                    byte[] up = new byte[16 * 1024];
                    for (long sent = 0; sent < Total; sent += up.Length)
                    {
                        Fill(up, sent);
                        ssl.Write(up);
                    }
                }
                catch (Exception e)
                {
                    sendFault = $"{e.GetType().Name}: {e.Message}";
                }
            }) { IsBackground = true, Name = "tls-threadpool-client-sender" };
            sender.Start();

            (long received, string? readFault) = ReadPattern(ssl, Total);
            sender.Join(10_000);
            if (readFault is null && sendFault is null)
            {
                ssl.ShutdownAsync().Wait(5_000);
            }

            Assert.True(readFault is null && sendFault is null,
                $"client: received {received} of {Total}: {readFault ?? "ok"}; sending: {sendFault ?? "ok"}");
            Assert.True(report.Task.Wait(10_000), "the handler never reported");
            (long serverReceived, bool intact, int onReactor, bool overlapped) = report.Task.Result;
            Assert.True(faults.IsEmpty, "server: " + string.Join(" | ", faults));
            Assert.True(serverReceived == Total && intact,
                $"the server read {serverReceived} of {Total} bytes, intact={intact}");

            // Non-vacuous: the handshake, every read and every flush ran off the reactor, and the two
            // loops were on the session over the same stretch of time - the case its lock is for.
            // (With the lock taken out, most runs of this test fail with a TLS decrypt error.)
            Assert.True(onReactor == 0, $"{onReactor} of the handler's TLS operations ran on the reactor");
            Assert.True(overlapped, "the reader and the writer never ran over the same stretch of time");
        });

        runner.Test("tls threadpool: a session keeps serving from the thread pool after ConfigureAwait(false)", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var drift = new ConcurrentQueue<string>();
            int port = TestServer.Start(ConfigureAwaitFalseHandler(drift), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = 10_000;
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            // Keep-alive: every request after the first is read and answered from the pool.
            for (int i = 0; i < 5; i++)
            {
                Client.Send(ssl, $"/{i}");
                (int status, string body) = Client.ReadResponse(ssl);
                Assert.Equal(200, status);
                Assert.Equal($"pool-{i}", body);
            }

            ssl.ShutdownAsync().Wait(5_000);
            Assert.True(drift.IsEmpty, "the handler was back on its reactor: " + string.Join("; ", drift));
        });
    }

    // Byte i of the stream is (i % 251) in both directions, so either end can check every byte.
    private static void Fill(Span<byte> span, long offset)
    {
        for (int i = 0; i < span.Length; i++)
        {
            span[i] = (byte)((offset + i) % 251);
        }
    }

    private static (long Received, string? Fault) ReadPattern(SslStream ssl, int total)
    {
        long received = 0;
        byte[] buffer = new byte[64 * 1024];
        try
        {
            while (received < total)
            {
                int n = ssl.Read(buffer);
                if (n == 0)
                {
                    return (received, "the server closed the connection");
                }
                for (int i = 0; i < n; i++)
                {
                    if (buffer[i] != (byte)((received + i) % 251))
                    {
                        return (received, $"byte {received + i} arrived corrupted");
                    }
                }
                received += n;
            }
        }
        catch (Exception e)
        {
            return (received, $"{e.GetType().Name}: {e.Message}");
        }
        return (received, null);
    }

    // Leaves the reactor before the handshake, then reads and writes on two pool tasks at once.
    private static Func<Reactor, TcpConnection, Task> DuplexHandler(int total, ConcurrentQueue<string> faults,
        TaskCompletionSource<(long Received, bool Intact, int OnReactor, bool Overlapped)> report)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            int onReactor = 0;

            // When each loop's first operation began and its last one ended.
            long readFirst = 0, readLast = 0, writeFirst = 0, writeLast = 0;

            void Observe()
            {
                if (reactor.OnReactorThread)
                {
                    Interlocked.Increment(ref onReactor);
                }
            }

            try
            {
                await Hop.ToThreadPool();

                try
                {
                    Observe();
                    session = await reactor.GetService<TlsService>().AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness's readiness probe never completes a handshake
                }

                pipe = new TlsConnectionDualPipe(connection, session);
                PipeReader input = pipe.Input;
                PipeWriter output = pipe.Output;

                // Released together, so neither loop can be done before the other has begun.
                using var start = new Barrier(2);

                Task<(long, bool)> reading = Task.Run(async () =>
                {
                    start.SignalAndWait();
                    readFirst = System.Diagnostics.Stopwatch.GetTimestamp();
                    long received = 0;
                    bool intact = true;
                    while (true)
                    {
                        Observe();
                        ReadResult read = await input.ReadAsync();

                        foreach (ReadOnlyMemory<byte> segment in read.Buffer)
                        {
                            ReadOnlySpan<byte> span = segment.Span;
                            for (int i = 0; i < span.Length && intact; i++)
                            {
                                intact = span[i] == (byte)((received + i) % 251);
                            }
                            received += span.Length;
                        }
                        input.AdvanceTo(read.Buffer.End);

                        if (received >= total || read.IsCompleted)
                        {
                            readLast = System.Diagnostics.Stopwatch.GetTimestamp();
                            return (received, intact);
                        }
                    }
                });

                Task writing = Task.Run(async () =>
                {
                    start.SignalAndWait();
                    writeFirst = System.Diagnostics.Stopwatch.GetTimestamp();
                    const int Chunk = 16 * 1024;
                    for (long sent = 0; sent < total; sent += Chunk)
                    {
                        Fill(output.GetSpan(Chunk)[..Chunk], sent);
                        output.Advance(Chunk);

                        Observe();
                        await output.FlushAsync();
                    }
                    writeLast = System.Diagnostics.Stopwatch.GetTimestamp();
                });

                await Task.WhenAll(reading, writing);
                (long got, bool ok) = await reading;
                bool overlapped = readFirst < writeLast && writeFirst < readLast;
                report.TrySetResult((got, ok, Volatile.Read(ref onReactor), overlapped));
            }
            catch (Exception e)
            {
                faults.Enqueue($"{e.GetType().Name}: {e.Message}");
                report.TrySetResult((-1, false, Volatile.Read(ref onReactor), false));
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

    // Handshakes on the reactor, then moves off it with ConfigureAwait(false) and serves keep-alive
    // requests through the raw session API from wherever it resumes.
    private static Func<Reactor, TcpConnection, Task> ConfigureAwaitFalseHandler(ConcurrentQueue<string> drift)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            try
            {
                try
                {
                    session = await reactor.GetService<TlsService>().AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness's readiness probe never completes a handshake
                }

                // A wait that really suspends, so the rest runs on the pool with no context to post it back.
                await Task.Delay(1).ConfigureAwait(false);

                var carry = new List<byte>();
                carry.AddRange(session.DrainPlaintext().ToArray());
                int answered = 0;

                while (true)
                {
                    // Answer every request already decrypted before reading again.
                    answered = Answer(session, connection, carry, answered);
                    if (reactor.OnReactorThread)
                    {
                        drift.Enqueue($"request {answered}: on the reactor");
                    }
                    await connection.FlushAsync().ConfigureAwait(false);

                    RecvSnapshot snapshot = await connection.ReadAsync().ConfigureAwait(false);
                    Decrypt(session, connection, snapshot, carry);
                    if (snapshot.IsClosed || session.Closed)
                    {
                        return;
                    }
                }
            }
            finally
            {
                session?.Dispose();
                connection.DecRef();
            }
        };

    // Writes one response per complete request head in the carry, numbered from `answered`.
    private static int Answer(TlsSession session, TcpConnection connection, List<byte> carry, int answered)
    {
        int end;
        while ((end = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(carry).IndexOf("\r\n\r\n"u8)) >= 0)
        {
            carry.RemoveRange(0, end + 4);
            string body = $"pool-{answered++}";
            session.Write(connection, Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
        }
        return answered;
    }

    private static unsafe void Decrypt(TlsSession session, TcpConnection connection, in RecvSnapshot snapshot, List<byte> carry)
    {
        while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                try
                {
                    carry.AddRange(session.Decrypt(item.Ptr, item.Len).ToArray());
                }
                finally
                {
                    connection.ReturnBuffer(in item);
                }
            }
        }
    }
}
