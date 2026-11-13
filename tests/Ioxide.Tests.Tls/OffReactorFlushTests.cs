using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// A TLS handler working from a thread other than its reactor: writing while the reactor decrypts
/// what the client sends on the same session (#249), reading, tearing the connection down, and
/// outliving the reactor.
/// </summary>
internal static class OffReactorFlushTests
{
    private const int ReadyReads = 8;

    public static void Register(Runner runner, bool ktls)
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

        runner.Test("tls pipe: a handler that left the reactor disposes with its staged bytes delivered", () =>
        {
            // The disposal commits what was staged and frees the session: off the reactor, the commit was
            // posted and the free ran first, so the reactor encrypted on a freed session.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            byte[] payload = "staged off the reactor, delivered by the disposal"u8.ToArray();
            var faults = new ConcurrentQueue<string>();
            int port = TestServer.Start(DisposeOffReactorHandler(payload, faults), r => TlsService.Start(r, options));

            const int Clients = 20;
            var received = new string?[Clients];
            Parallel.For(0, Clients, new ParallelOptions { MaxDegreeOfParallelism = Clients }, i =>
            {
                try
                {
                    using var tcp = new TcpClient();
                    tcp.Connect("127.0.0.1", port);
                    tcp.ReceiveTimeout = 10_000;
                    using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
                    ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });
                    ssl.Write("GET / HTTP/1.1\r\nHost: x\r\n\r\n"u8);

                    var all = new MemoryStream();
                    byte[] buffer = new byte[4096];
                    int n;
                    while ((n = ssl.Read(buffer)) > 0)
                    {
                        all.Write(buffer, 0, n);
                    }
                    received[i] = all.ToArray().AsSpan().SequenceEqual(payload) ? null : $"{all.Length} of {payload.Length} bytes";
                }
                catch (Exception e)
                {
                    received[i] = $"{e.GetType().Name}: {e.Message}";
                }
            });

            string[] wrong = received.Where(r => r is not null).Select(r => r!).ToArray();
            Assert.True(wrong.Length == 0 && faults.IsEmpty,
                $"{wrong.Length} of {Clients} clients: {string.Join(" | ", wrong.Distinct())}; server: {string.Join(" | ", faults)}");
        });

        runner.Test("tls pipe: a read from another thread of what is already decrypted completes there, without the reactor", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(ReadOffReactorHandler, r => TlsService.Start(r, options));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal($"{ReadyReads} of {ReadyReads}", body);
        });

        runner.Test("tls pipe: a read from another thread that has to decrypt does so on the reactor", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            const int Rounds = 32;
            using var send = new SemaphoreSlim(0);
            var outcome = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            int port = TestServer.Start(DecryptOffReactorHandler(send, Rounds, outcome), r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });

            byte[] one = [1];
            ssl.Write(one);   // read on the reactor, taking whatever the handshake left on the connection
            for (int round = 0; round < Rounds; round++)
            {
                Assert.True(send.Wait(10_000), "the handler stopped asking for bytes");
                ssl.Write(one);
            }

            Assert.True(outcome.Task.Wait(10_000), "the handler never finished");

            // Where the handler lands isn't promised, since the reactor can finish before it awaits. But a decrypt
            // on its own thread, beside the reactor's SSL_write, completes the read there, so it never lands on the reactor.
            Assert.True(outcome.Task.Result >= Rounds / 2, $"the handler resumed on the reactor after {outcome.Task.Result} of {Rounds} decrypts");
        });

        runner.Test("tls pipe: a read from another thread that has to decrypt fails once the reactor has stopped, instead of waiting forever", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var offReactor = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var stopped = new ManualResetEventSlim();
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(
                StoppedReadHandler(offReactor, stopped, outcome),
                new ServerConfig
                {
                    RecvBufferSize = 4096, RecvSlots = 256,
                    Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
                },
                r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });
            ssl.Write(new byte[] { 1 });

            Assert.True(offReactor.Task.Wait(10_000), "the handler never left the reactor");
            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");
            stopped.Set();

            Assert.True(outcome.Task.Wait(10_000), "the read never finished, and nothing will ever run it now");
            Assert.Equal("ObjectDisposedException", outcome.Task.Result);
        });

        runner.Test("tls pipe: a flush from another thread once the reactor has stopped returns completed at once, instead of waiting forever", () =>
        {
            // A stopped reactor drops what is posted to it: this flush was posted, and its caller left waiting forever (#568).
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            Assert.Equal("completed at once", FlushAfterTheStop(options, typeof(TlsEncryptingPipeWriter)));
        });

        runner.Test("tls pipe: control: under kTLS TX a flush from another thread once the reactor has stopped returns completed at once", () =>
        {
            // The connection's own writer, which the dual pipe hands out instead: the stop closed the connection, which is
            // what it reports.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = true };

            Assert.Equal("completed at once", FlushAfterTheStop(options, typeof(TcpConnectionPipeWriter)));
        }, skip: !ktls);

        runner.Test("tls pipe: a flush from another thread still queued when the reactor stops completes, instead of waiting forever", () =>
        {
            // Posted before the stop, but after the reactor last ran its posts: the stop dropped it (#568).
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(
                QueuedFlushHandler(outcome),
                new ServerConfig
                {
                    RecvBufferSize = 4096, RecvSlots = 256,
                    Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
                },
                r => TlsService.Start(r, options));

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });
            ssl.Write(new byte[] { 1 });

            // The handler stops the reactor itself, in the pass the flush was posted in.
            bool stopped = thread.Join(TimeSpan.FromSeconds(10));
            if (!stopped)
            {
                reactor.Stop();
            }
            Assert.True(stopped, $"the handler never stopped the reactor: {(outcome.Task.IsCompleted ? outcome.Task.Result : "no outcome")}");

            // A flush the reactor ran before its stop would have found the connection open, and returned not completed.
            Assert.True(outcome.Task.Wait(20_000), "the handler never reported");
            Assert.Equal("completed", outcome.Task.Result);
        });
    }

    // The handler leaves the reactor, waits on its own thread until the reactor has stopped, then writes and flushes there.
    private static string FlushAfterTheStop(TlsOptions options, Type writer)
    {
        var offReactor = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stopped = new ManualResetEventSlim();
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        (int port, Reactor reactor, Thread thread) = TestServer.StartConfigured(
            StoppedFlushHandler(writer, offReactor, stopped, outcome),
            new ServerConfig
            {
                RecvBufferSize = 4096, RecvSlots = 256,
                Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 64, RecvQueueEntries = 64 },
            },
            r => TlsService.Start(r, options));

        using var tcp = new TcpClient();
        tcp.Connect("127.0.0.1", port);
        using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = "localhost" });
        ssl.Write(new byte[] { 1 });

        try
        {
            Assert.True(offReactor.Task.Wait(10_000), "the handler never left the reactor");
            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");
        }
        finally
        {
            stopped.Set();
        }

        Assert.True(outcome.Task.Wait(20_000), "the handler never reported");
        return outcome.Task.Result;
    }

    // How a flush from another thread ended. Left waiting, it is "never finished", and nothing will ever run it now.
    private static string FlushOutcome(ValueTask<FlushResult> flush)
    {
        bool atOnce = flush.IsCompleted;
        Task<FlushResult> ended = flush.AsTask();
        try
        {
            if (!ended.Wait(10_000))
            {
                return "never finished";
            }
        }
        catch (AggregateException e)
        {
            return e.InnerException?.GetType().Name ?? e.GetType().Name;
        }

        return !ended.Result.IsCompleted ? "returned, not completed"
            : atOnce ? "completed at once"
            : "completed";
    }

    private static Func<Reactor, TcpConnection, Task> StoppedFlushHandler(
        Type writer, TaskCompletionSource offReactor, ManualResetEventSlim stopped, TaskCompletionSource<string> outcome)
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

                ReadResult first = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(first.Buffer.End);

                await Task.Yield();   // leaves the reactor: nothing brings it back
                offReactor.TrySetResult();
                stopped.Wait();

                // The half the handshake chose: under the wrong one this would test the other.
                if (pipe.Output.GetType() != writer)
                {
                    outcome.TrySetResult($"the session's writer is {pipe.Output.GetType().Name}");
                    return;
                }

                pipe.Output.Write("never sent"u8);
                outcome.TrySetResult(FlushOutcome(pipe.Output.FlushAsync()));
            }
            catch (Exception e)
            {
                outcome.TrySetResult(e.GetType().Name);
                offReactor.TrySetResult();
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

    private static Func<Reactor, TcpConnection, Task> QueuedFlushHandler(TaskCompletionSource<string> outcome)
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
                using var posted = new ManualResetEventSlim();

                // Resumed by the client's byte, among the pass's completions: the pass ran its posts before them.
                ReadResult first = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(first.Buffer.End);

                if (pipe.Output is not TlsEncryptingPipeWriter)
                {
                    outcome.TrySetResult($"the session's writer is {pipe.Output.GetType().Name}");
                }
                else
                {
                    // Another thread flushes while this holds the reactor, so the flush is posted, and the stop then ends
                    // the loop with this pass: it never runs its posts again.
                    PipeWriter output = pipe.Output;
                    new Thread(() =>
                    {
                        ValueTask<FlushResult> flush;
                        try
                        {
                            output.Write("never sent"u8);
                            flush = output.FlushAsync();
                        }
                        catch (Exception e)
                        {
                            outcome.TrySetResult(e.GetType().Name);
                            return;
                        }
                        finally
                        {
                            posted.Set();
                        }

                        outcome.TrySetResult(FlushOutcome(flush));
                    }) { IsBackground = true, Name = "tls-568-writer" }.Start();

                    if (!posted.Wait(10_000))
                    {
                        outcome.TrySetResult("the writer never flushed");
                    }
                }

                reactor.Stop();
                await outcome.Task;   // the writer must be out of the session before it is disposed under it
            }
            catch (Exception e)
            {
                outcome.TrySetResult(e.GetType().Name);
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

    // With nothing parked, what a recv brought waits on the connection and this says so.
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_pending")]
    private static extern ref int PendingOf(TcpConnection connection);

    private static Func<Reactor, TcpConnection, Task> DecryptOffReactorHandler(SemaphoreSlim send, int rounds, TaskCompletionSource<int> outcome)
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

                ReadResult first = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(first.Buffer.End);

                int onReactor = 0;
                for (int round = 0; round < rounds; round++)
                {
                    await Task.Yield();   // leaves the reactor: nothing brings it back

                    send.Release();
                    if (!SpinWait.SpinUntil(() => Volatile.Read(ref PendingOf(connection)) == 1, 10_000))
                    {
                        throw new TimeoutException($"round {round}: the client's bytes never reached the connection");
                    }

                    // Nothing decrypted to take, and the next record on the connection.
                    ReadResult read = await pipe.Input.ReadAsync();
                    onReactor += reactor.OnReactorThread ? 1 : 0;
                    pipe.Input.AdvanceTo(read.Buffer.End);
                }

                outcome.TrySetResult(onReactor);
            }
            catch (Exception e)
            {
                outcome.TrySetException(e);
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

    private static Func<Reactor, TcpConnection, Task> StoppedReadHandler(
        TaskCompletionSource offReactor, ManualResetEventSlim stopped, TaskCompletionSource<string> outcome)
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

                ReadResult first = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(first.Buffer.End);

                await Task.Yield();   // leaves the reactor: nothing brings it back
                offReactor.TrySetResult();
                stopped.Wait();

                try
                {
                    await pipe.Input.ReadAsync();
                    outcome.TrySetResult("the read returned");
                }
                catch (Exception e)
                {
                    outcome.TrySetResult(e.GetType().Name);
                }
            }
            catch (Exception e)
            {
                outcome.TrySetResult(e.GetType().Name);
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

    private static Func<Reactor, TcpConnection, Task> DisposeOffReactorHandler(byte[] payload, ConcurrentQueue<string> faults)
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
                ReadResult request = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(request.Buffer.End);

                await Task.Yield();   // leaves the reactor: nothing brings it back
                if (reactor.OnReactorThread)
                {
                    faults.Enqueue("the handler never left the reactor");
                }

                payload.CopyTo(pipe.Output.GetSpan(payload.Length));
                pipe.Output.Advance(payload.Length);   // staged, never flushed: the disposal commits it
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

    private static async Task ReadOffReactorHandler(Reactor reactor, TcpConnection connection)
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

            // The whole head, decrypted on the reactor and left unexamined, so the next read has it at once.
            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();
                var reader = new SequenceReader<byte>(read.Buffer);
                if (reader.TryReadTo(out ReadOnlySequence<byte> _, "\r\n\r\n"u8))
                {
                    pipe.Input.AdvanceTo(read.Buffer.Start);
                    break;
                }
                pipe.Input.AdvanceTo(read.Buffer.Start, read.Buffer.End);
                if (read.IsCompleted)
                {
                    return;
                }
            }

            // More than once: a read that goes to the reactor can still look done, when the reactor beats its caller.
            int atOnceHere = 0;
            for (int i = 0; i < ReadyReads; i++)
            {
                await Task.Yield();   // leaves the reactor: nothing brings it back
                ValueTask<ReadResult> pending = pipe.Input.ReadAsync();
                bool atOnce = pending.IsCompleted;
                ReadResult again = await pending;
                atOnceHere += atOnce && !reactor.OnReactorThread ? 1 : 0;
                pipe.Input.AdvanceTo(again.Buffer.Start);
            }
            string verdict = $"{atOnceHere} of {ReadyReads}";

            pipe.Output.Write(System.Text.Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {verdict.Length}\r\n\r\n{verdict}"));
            await pipe.Output.FlushAsync();
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
