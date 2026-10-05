using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// A TLS handler that writes from a thread other than its reactor, while the reactor decrypts what
/// the client sends on the same session (#249).
/// </summary>
internal static class OffReactorFlushTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tls pipe: a flush from another thread while the reactor decrypts keeps the session intact", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            const int Total = 16 << 20;
            const int Chunk = 1024;
            var faults = new ConcurrentQueue<string>();
            var handlerDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(Handler(faults, handlerDone, Total, Chunk), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = 10_000;
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            // Keeps the reactor decrypting for as long as the handler's thread is encrypting.
            int sending = 1;
            var sender = new Thread(() =>
            {
                byte[] up = new byte[16 * 1024];
                try
                {
                    while (Volatile.Read(ref sending) == 1)
                    {
                        ssl.Write(up);
                    }
                }
                catch (Exception)
                {
                    // The read side below reports what went wrong.
                }
            }) { IsBackground = true, Name = "tls-249-client-sender" };
            sender.Start();

            long received = 0;
            string? clientFault = null;
            byte[] buffer = new byte[64 * 1024];
            try
            {
                while (received < Total && clientFault is null)
                {
                    int n = ssl.Read(buffer);
                    if (n == 0)
                    {
                        clientFault = "the server closed the connection";
                        break;
                    }
                    for (int i = 0; i < n; i++)
                    {
                        if (buffer[i] != (byte)((received + i) % 251))
                        {
                            clientFault = $"byte {received + i} arrived corrupted";
                            break;
                        }
                    }
                    received += n;
                }
            }
            catch (Exception e)
            {
                clientFault = $"{e.GetType().Name}: {e.Message}";
            }

            Volatile.Write(ref sending, 0);
            sender.Join(5_000);
            if (clientFault is null)
            {
                ssl.ShutdownAsync().Wait(5_000);
            }
            ssl.Dispose();

            bool finished = handlerDone.Task.Wait(10_000);

            Assert.True(clientFault is null && faults.IsEmpty,
                $"received {received} of {Total} bytes; client: {clientFault ?? "ok"}; server: {(faults.IsEmpty ? "ok" : string.Join(" | ", faults))}");
            Assert.True(finished, "the handler never finished after the client closed");
        });

        runner.Test("tls pipe: Complete from another thread commits what was staged", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            byte[] payload = "staged on another thread, committed by Complete"u8.ToArray();
            var faults = new ConcurrentQueue<string>();

            int port = TestServer.Start(CompleteHandler(payload, faults), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = 10_000;
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            var received = new MemoryStream();
            byte[] buffer = new byte[4096];
            int n;
            while ((n = ssl.Read(buffer)) > 0)
            {
                received.Write(buffer, 0, n);
            }

            Assert.True(faults.IsEmpty, $"server: {string.Join(" | ", faults)}");
            Assert.True(received.ToArray().AsSpan().SequenceEqual(payload),
                $"expected the {payload.Length} staged bytes, got {received.Length}");
        });

        runner.Test("tls pipe: a flush allocates nothing, on the reactor or handed to it from another thread", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            const int Flushes = 2000;
            var report = new TaskCompletionSource<(double OnReactor, double OffCaller, double OffReactor)>(
                TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(AllocationHandler(Flushes, report), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = 10_000;
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            byte[] buffer = new byte[64 * 1024];
            while (ssl.Read(buffer) > 0)
            {
            }

            Assert.True(report.Task.Wait(10_000), "the handler never reported");
            (double onReactor, double offCaller, double offReactor) = report.Task.Result;
            Assert.True(onReactor < 8 && offCaller < 8 && offReactor < 8,
                $"bytes allocated per flush: {onReactor:F1} on the reactor; handed over, {offCaller:F1} on the caller and {offReactor:F1} on the reactor");
        });

        runner.Test("tls session: Write from another thread is refused rather than racing the reactor", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(SessionWriteHandler(outcome), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            Assert.True(outcome.Task.Wait(10_000), "the handler never reported");
            Assert.Equal(nameof(InvalidOperationException), outcome.Task.Result);
        });
    }

    private static Func<Reactor, TcpConnection, Task> AllocationHandler(
        int flushes, TaskCompletionSource<(double OnReactor, double OffCaller, double OffReactor)> report)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness's readiness probe never completes a handshake
                }

                pipe = new TlsConnectionDualPipe(connection, session);
                PipeWriter output = pipe.Output;

                // Inline loops: an async helper would allocate a state machine of its own per call.
                for (int i = 0; i < 64; i++)
                {
                    output.GetSpan(1024);
                    output.Advance(1024);
                    await output.FlushAsync();
                }
                long before = GC.GetAllocatedBytesForCurrentThread();
                for (int i = 0; i < flushes; i++)
                {
                    output.GetSpan(1024);
                    output.Advance(1024);
                    await output.FlushAsync();
                }
                double onReactor = (GC.GetAllocatedBytesForCurrentThread() - before) / (double)flushes;

                double offCaller = 0;
                var done = new TaskCompletionSource();
                var writer = new Thread(() =>
                {
                    using var signal = new ManualResetEventSlim();
                    Action wake = signal.Set;
                    long callerBefore = 0;
                    for (int i = 0; i < 64 + flushes; i++)
                    {
                        if (i == 64)
                        {
                            callerBefore = GC.GetAllocatedBytesForCurrentThread();
                        }
                        output.GetSpan(1024);
                        output.Advance(1024);
                        ValueTask<FlushResult> flush = output.FlushAsync();
                        if (!flush.IsCompleted)
                        {
                            signal.Reset();
                            flush.GetAwaiter().UnsafeOnCompleted(wake);
                            signal.Wait();
                        }
                        flush.GetAwaiter().GetResult();
                    }
                    offCaller = (GC.GetAllocatedBytesForCurrentThread() - callerBefore) / (double)flushes;
                    reactor.ScheduleOnReactor(static s => ((TaskCompletionSource)s!).SetResult(), done);
                }) { IsBackground = true, Name = "tls-alloc-writer" };
                writer.Start();

                long reactorBefore = GC.GetAllocatedBytesForCurrentThread();
                await done.Task;
                double offReactor = (GC.GetAllocatedBytesForCurrentThread() - reactorBefore) / (double)(64 + flushes);

                report.TrySetResult((onReactor, offCaller, offReactor));
            }
            catch (Exception e)
            {
                report.TrySetException(e);
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

    private static Func<Reactor, TcpConnection, Task> CompleteHandler(byte[] payload, ConcurrentQueue<string> faults)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness's readiness probe never completes a handshake
                }

                pipe = new TlsConnectionDualPipe(connection, session);
                PipeWriter output = pipe.Output;

                var done = new TaskCompletionSource();
                new Thread(() =>
                {
                    try
                    {
                        payload.CopyTo(output.GetSpan(payload.Length));
                        output.Advance(payload.Length);
                        output.Complete();
                    }
                    catch (Exception e)
                    {
                        faults.Enqueue($"{e.GetType().Name}: {e.Message}");
                    }
                    reactor.ScheduleOnReactor(static s => ((TaskCompletionSource)s!).SetResult(), done);
                }) { IsBackground = true, Name = "tls-249-completer" }.Start();

                await done.Task;
            }
            catch (Exception e)
            {
                faults.Enqueue($"{e.GetType().Name}: {e.Message}");
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

    private static Func<Reactor, TcpConnection, Task> SessionWriteHandler(TaskCompletionSource<string> outcome)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            try
            {
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness's readiness probe never completes a handshake
                }

                TlsSession tls = session;
                var done = new TaskCompletionSource<string>();
                new Thread(() =>
                {
                    string result = "no exception";
                    try
                    {
                        tls.Write(connection, "written from another thread"u8);
                    }
                    catch (Exception e)
                    {
                        result = e.GetType().Name;
                    }
                    reactor.ScheduleOnReactor(static s =>
                    {
                        var (d, r) = ((TaskCompletionSource<string>, string))s!;
                        d.SetResult(r);
                    }, (done, result));
                }) { IsBackground = true, Name = "tls-249-session-writer" }.Start();

                outcome.TrySetResult(await done.Task);
            }
            finally
            {
                session?.Dispose();
                connection.DecRef();
            }
        };

    private static Func<Reactor, TcpConnection, Task> Handler(
        ConcurrentQueue<string> faults, TaskCompletionSource handlerDone, int total, int chunk)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            TaskCompletionSource? writerDone = null;
            int stop = 0;
            try
            {
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;   // the harness's readiness probe never completes a handshake
                }

                pipe = new TlsConnectionDualPipe(connection, session);
                PipeWriter output = pipe.Output;

                // Completed through the reactor, so the await below resumes there.
                writerDone = new TaskCompletionSource();
                var writer = new Thread(() =>
                {
                    try
                    {
                        for (long sent = 0; sent < total && Volatile.Read(ref stop) == 0; sent += chunk)
                        {
                            Span<byte> span = output.GetSpan(chunk);
                            for (int i = 0; i < chunk; i++)
                            {
                                span[i] = (byte)((sent + i) % 251);
                            }
                            output.Advance(chunk);
                            output.FlushAsync().AsTask().Wait();
                        }
                    }
                    catch (Exception e)
                    {
                        Exception root = e.GetBaseException();
                        faults.Enqueue($"writer: {root.GetType().Name}: {root.Message}");
                    }
                    reactor.ScheduleOnReactor(static s => ((TaskCompletionSource)s!).SetResult(), writerDone);
                }) { IsBackground = true, Name = "tls-249-writer" };
                writer.Start();

                while (true)
                {
                    ReadResult read = await pipe.Input.ReadAsync();
                    pipe.Input.AdvanceTo(read.Buffer.End);
                    if (read.IsCompleted)
                    {
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                faults.Enqueue($"reader: {e.GetType().Name}: {e.Message}");
            }
            finally
            {
                // The writer must be out of the session before it is disposed under it.
                Volatile.Write(ref stop, 1);
                if (writerDone is not null)
                {
                    await writerDone.Task;
                }
                if (pipe is not null)
                {
                    await pipe.DisposeAsync();
                }
                else
                {
                    session?.Dispose();
                }
                connection.DecRef();
                if (writerDone is not null)
                {
                    handlerDone.TrySetResult();
                }
            }
        };
}
