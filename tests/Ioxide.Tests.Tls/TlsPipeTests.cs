using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// Serving TLS over pipes. Under the default both halves are OpenSSL's: the write half encrypts
/// before the bytes reach the slab, the read half decrypts into a Pipe it owns. Under the kTLS TX
/// opt-in the write half is the plaintext connection's own writer. The default needs no kernel
/// module, so these run everywhere; the opt-in round-trip is gated on it.
/// </summary>
internal static class TlsPipeTests
{
    public static void Register(Runner runner, bool ktls)
    {
        runner.Test("tls pipe: a request served entirely through TlsConnectionDualPipe", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(PipeHandler, r => TlsService.Start(r, options));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("pipe-tls-ok", body);
        });

        // The composer picks the plaintext connection's own writer when kTLS TX owns the records -
        // the one dual-pipe configuration the default no longer exercises.
        runner.Test("tls pipe: kTLS TX opt-in through TlsConnectionDualPipe", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, KernelTx = true };

            int port = TestServer.Start(PipeHandler, r => TlsService.Start(r, options));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("pipe-tls-ok", body);
        }, skip: !ktls);

        // A single TLS record delivered in N-byte TCP writes, so the server genuinely holds
        // partial-record state across recvs. Chunking at the SslStream level would NOT do this -
        // SslStream.Write emits one complete record per call, so every recv would carry whole
        // records and the test would pass against a server that cannot reassemble at all. The
        // first version of this test did exactly that and survived the mutation below.
        //
        // Nothing in ioxide reassembles records. OpenSSL's memory BIO does: Feed appends whatever
        // arrived and SSL_read answers WANT_READ until a record is whole, which ShouldKeepReading
        // reports as "not complete yet" rather than as a fault. These tests exist to keep that
        // true, because the failure mode is silent - a half-record looks exactly like a quiet
        // connection.
        foreach (int chunk in new[] { 1, 7, 64, 1024 })
        {
            int size = chunk;
            runner.Test($"tls pipe: TLS records split across {size}-byte TCP writes", () =>
            {
                (string certPath, string keyPath) = TestCert.Ensure();
                var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

                int port = TestServer.Start(WholeRequestHandler, r => TlsService.Start(r, options));

                (int status, string body) = Client.GetTlsSplitRecords(port, "/", size);
                Assert.Equal(200, status);
                Assert.Equal("pipe-tls-ok", body);
            });
        }

        runner.Test("tls pipe: a handler that stops draining a large body can still be disposed", () =>
        {
            // The shape: a client uploads a body, the handler answers from the headers alone and
            // returns without reading the rest. The inbound pipe is then above its pause threshold
            // with the pump parked in FlushAsync - and a writer held there is released by the
            // READER COMPLETING, never by CancelPendingRead, which cancels a pending read and says
            // nothing about a blocked flush. Get that wrong and DisposeAsync awaits a pump that can
            // never finish: the handler's finally never returns, the connection is never released,
            // and the reactor leaks one per occurrence.
            //
            // The assertion has to be on the SERVER side. An earlier version of this test uploaded
            // a body and checked that a SECOND request was answered, which passes either way - the
            // response is written before the handler wedges, and the reactor keeps accepting while
            // one handler task sits abandoned. No client-visible signal separates the two cases. So
            // the handler reports the moment DisposeAsync RETURNS, which is the actual claim.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions
            {
                CertificatePath = certPath,
                KeyPath = keyPath,
                InboundPauseBytes = PausedInboundThreshold,
                InboundResumeBytes = PausedInboundThreshold / 2,
            };

            var disposed = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(HeadersOnlyHandler(disposed), r => TlsService.Start(r, options));

            Assert.True(PostBody(port, kilobytes: 32).Contains("headers-only"),
                "the upload was not answered");

            // Generous on purpose, and the generosity costs nothing: the failure this catches is a
            // pump parked forever, which does not complete at ANY deadline. Ten seconds turned out
            // to be a statement about machine load rather than about the code - it failed one run in
            // four with a dozen suites running at once, which is a bug in the test, not a wedge.
            Assert.True(disposed.Task.Wait(TimeSpan.FromSeconds(60)),
                "DisposeAsync never returned: the pump is parked in FlushAsync and nothing released it");

            // Non-vacuous. The pipe must have been PAST its pause threshold when disposal ran,
            // because that is the only state in which the pump is parked in FlushAsync at all.
            Assert.True(disposed.Task.Result > PausedInboundThreshold,
                $"the pump was never parked: only {disposed.Task.Result} B were unconsumed");
        });

        runner.Test("tls pipe: the pump stops decrypting at TlsOptions.InboundPauseBytes", () =>
        {
            // The handler reads the head and nothing more, so the pump decrypts until the pipe holds
            // the listener's threshold and stops; the rest of the body waits as ciphertext. At the
            // pipe's own 64 KiB default it would have decrypted four records instead of one.
            long unread = UnreadAfterUpload(PausedInboundThreshold, PausedInboundThreshold / 2);

            Assert.True(unread >= PausedInboundThreshold && unread < 48 * 1024,
                $"{unread} B were decrypted and left unread: the pump did not stop at "
                + $"InboundPauseBytes = {PausedInboundThreshold}");
        });

        runner.Test("tls pipe: InboundPauseBytes = 0 lets the pump decrypt the whole upload", () =>
        {
            // No bound, whatever InboundResumeBytes says. A Pipe refuses a resume threshold above a
            // pause threshold of zero, so this also covers the reader not passing the default on.
            long unread = UnreadAfterUpload(0, 32 * 1024);

            Assert.Equal((long)UnreadUploadKilobytes * 1024, unread);
        });

        runner.Test("tls pipe: serving never leaves the reactor thread", () =>
        {
            // ioxide supports off-reactor submission - SubmitClientOp marshals through _remoteOps
            // and wakes the ring - but that is an escape hatch for USER code that deliberately goes
            // cross-thread. None of ioxide's own seams may trip it.
            //
            // TlsConnectionDualPipe did. Its inbound Pipe was built with
            // PipeOptions(useSynchronizationContext: false) and nothing else, and a Pipe's
            // schedulers default to PipeScheduler.ThreadPool - so the first genuinely-async
            // ReadAsync completed on a pool thread with a NULL SynchronizationContext, which is
            // what makes it permanent: with no context, nothing can post the connection back. From
            // there every client call on that connection paid a queue hop and an eventfd wake, and
            // nothing reported it. Only UdpSendTo throws on the wrong thread; the TCP path is
            // silent, so an h3 upstream was the only way to see it at all.
            //
            // Checking OnReactorThread is checking the exact predicate SubmitClientOp branches on.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var affinity = new ReactorAffinity();
            int port = TestServer.Start(AffinityHandler(affinity), r => TlsService.Start(r, options));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("pipe-tls-ok", body);

            // A handler that never ran would leave Drift empty and pass vacuously.
            Assert.True(affinity.Checks >= 2,
                $"expected at least two observations, got {affinity.Checks}");
            Assert.True(affinity.Drift.Count == 0,
                "ioxide moved the handler off its reactor: " + string.Join("; ", affinity.Drift));
        });

        runner.Test("tls pipe: garbage after the handshake faults the reader, not a clean EOF", () =>
        {
            // The property both hand-rolled pumps get wrong. A TLS protocol error must reach the
            // reader as an exception; completing the pipe normally would make a corrupted or
            // truncated stream look exactly like the peer hanging up politely.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var faulted = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(FaultReportingHandler(faulted), r => TlsService.Start(r, options));

            Client.SendTlsGarbageAfterHandshake(port);

            Assert.True(faulted.Task.Wait(TimeSpan.FromSeconds(10)),
                "the reader should have observed a fault within 10 s");

            // Assert on WHAT failed, not merely that something did. The harness's own liveness
            // probe opens a raw TCP connection and fails the handshake on it, so "some exception
            // reached the handler" is satisfied before this test's garbage is even sent - which is
            // exactly how the first version of this test passed against every mutation.
            string reason = faulted.Task.Result;
            Assert.True(reason.Contains("TLS decrypt failed"),
                $"expected the decrypt to fault, got: {reason}");
        });
    }

    // Same shape as PipeHandler, with an affinity observation on either side of the await that
    // matters: the one on the TLS pipe's reader.
    private static Func<Reactor, TcpConnection, Task> AffinityHandler(ReactorAffinity affinity)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                affinity.Check(reactor, "after AcceptAsync");

                pipe = new TlsConnectionDualPipe(connection, session);

                ReadResult read = await pipe.Input.ReadAsync();
                affinity.Check(reactor, "after Input.ReadAsync");
                pipe.Input.AdvanceTo(read.Buffer.End);

                const string body = "pipe-tls-ok";
                pipe.Output.Write(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
                await pipe.Output.FlushAsync();
                affinity.Check(reactor, "after Output.FlushAsync");
            }
            catch
            {
                // The client hung up, or the handshake failed - the harness probes the port with a
                // raw TCP connection, so this fires once per run and is not a test failure.
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

    /// <summary>
    /// Answers only once a COMPLETE request has been reassembled - it reads until it sees the
    /// blank line that ends the head, and never responds otherwise.
    ///
    /// That requirement is the whole test. PipeHandler writes its 200 after a single ReadAsync
    /// whatever that read contained, so it answers just as happily when reassembly is broken and
    /// the pipe completes early - which is exactly how the first two versions of the split-record
    /// tests passed against a deliberately broken pump.
    /// </summary>
    private static async Task WholeRequestHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);

            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();

                if (Terminated(read.Buffer))
                {
                    pipe.Input.AdvanceTo(read.Buffer.End);

                    const string body = "pipe-tls-ok";
                    pipe.Output.Write(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
                    await pipe.Output.FlushAsync();
                    return;
                }

                // Nothing consumed, everything examined: the pipe must wait for more bytes rather
                // than handing back the same partial head forever.
                pipe.Input.AdvanceTo(read.Buffer.Start, read.Buffer.End);

                if (read.IsCompleted)
                {
                    return;   // the stream ended mid-request - no response, and the test fails
                }
            }
        }
        catch
        {
            // The harness probes the port with a raw TCP connection, which fails the handshake.
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

    /// <summary>
    /// The inbound pipe's pause threshold for this test, stated explicitly. The default is 64 KB,
    /// which takes a far larger upload to cross and makes "the pump is parked" a matter of timing
    /// rather than something the test can wait for.
    /// </summary>
    private const int PausedInboundThreshold = 8192;

    /// <summary>
    /// Answers from the request headers and returns WITHOUT draining the body, which is an ordinary
    /// thing for a handler to do (a rejected upload, an early 401) and the case that leaves the
    /// inbound pump parked at the pipe's pause threshold.
    ///
    /// Reports how many bytes were sitting unconsumed once <c>DisposeAsync</c> has RETURNED. A
    /// wedged disposal never completes the task at all, which is what the test waits on.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> HeadersOnlyHandler(TaskCompletionSource<int> disposed)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;

            // Nonzero only on the path that actually parked the pump. The harness's liveness probe
            // opens a raw TCP connection and fails the handshake, so an unguarded signal below
            // would complete the task from a connection that never uploaded anything.
            int parked = 0;

            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);

                pipe = new TlsConnectionDualPipe(connection, session);

                while (true)
                {
                    ReadResult read = await pipe.Input.ReadAsync();

                    if (Terminated(read.Buffer))
                    {
                        // Consume the head only. The body stays in the pipe on purpose.
                        pipe.Input.AdvanceTo(read.Buffer.End);

                        const string body = "headers-only";
                        pipe.Output.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
                        await pipe.Output.FlushAsync();

                        parked = await FillPastPauseThresholdAsync(pipe.Input);
                        return;
                    }

                    pipe.Input.AdvanceTo(read.Buffer.Start, read.Buffer.End);

                    if (read.IsCompleted)
                    {
                        return;
                    }
                }
            }
            catch
            {
                // Harness port probes fail the handshake; not this test's concern.
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

                if (parked > 0)
                {
                    disposed.TrySetResult(parked);
                }
            }
        };

    /// <summary>
    /// Stops consuming and waits until the pipe holds MORE than its pause threshold - the exact
    /// state in which the pump's FlushAsync has parked - then reports that count. Reading without
    /// consuming is what puts it there: every flush wakes this loop, and none of them frees a byte.
    /// </summary>
    private static async Task<int> FillPastPauseThresholdAsync(PipeReader input)
    {
        while (true)
        {
            ReadResult read = await input.ReadAsync();
            long buffered = read.Buffer.Length;

            // Examine everything, consume nothing: the next read then waits for bytes the pump has
            // yet to write instead of handing the same buffer straight back.
            input.AdvanceTo(read.Buffer.Start, read.Buffer.End);

            if (buffered > PausedInboundThreshold)
            {
                return (int)buffered;
            }

            if (read.IsCompleted || read.IsCanceled)
            {
                return 0;   // the stream ended before the pipe filled, so nothing is parked
            }
        }
    }

    /// <summary>
    /// Sends a head plus a body several times the pipe's pause threshold and returns whatever came
    /// back. The body stays small enough to sit in the kernel's receive queue, so the write does not
    /// block once the server stops draining - the point is to park the server's pump, not to
    /// exercise the client.
    /// </summary>
    private static string PostBody(int port, int kilobytes)
    {
        using var sock = new System.Net.Sockets.TcpClient();
        sock.Connect("127.0.0.1", port);
        sock.SendTimeout = 10_000;
        sock.ReceiveTimeout = 10_000;

        using var ssl = new System.Net.Security.SslStream(sock.GetStream(), false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient("localhost");

        int length = kilobytes * 1024;
        ssl.Write(Encoding.ASCII.GetBytes(
            $"POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: {length}\r\n\r\n"));
        ssl.Write(new byte[length]);
        ssl.Flush();

        var buf = new byte[256];
        int n = ssl.Read(buf, 0, buf.Length);
        return n > 0 ? Encoding.ASCII.GetString(buf, 0, n) : "";
    }

    /// <summary>The upload the unread-body tests send: six 16 KiB records after the head.</summary>
    private const int UnreadUploadKilobytes = 96;

    /// <summary>
    /// Uploads <see cref="UnreadUploadKilobytes"/> to a handler that reads the head and nothing more,
    /// and returns how much decrypted body the pipe held once the pump had gone as far as it would.
    /// </summary>
    private static long UnreadAfterUpload(int pauseBytes, int resumeBytes)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        var options = new TlsOptions
        {
            CertificatePath = certPath,
            KeyPath = keyPath,
            InboundPauseBytes = pauseBytes,
            InboundResumeBytes = resumeBytes,
        };

        var unread = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
        int port = TestServer.Start(UnreadBodyHandler(unread), r => TlsService.Start(r, options));

        Assert.True(PostBody(port, UnreadUploadKilobytes).Contains("measured"), "the upload was not answered");
        Assert.True(unread.Task.Wait(TimeSpan.FromSeconds(30)), "the handler never reported");
        return unread.Task.Result;
    }

    /// <summary>
    /// Reads the request head and nothing after it, waits for the pump to stop, then reports how much
    /// decrypted body the pipe held - which is where the pump stopped.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> UnreadBodyHandler(TaskCompletionSource<long> unread)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                pipe = new TlsConnectionDualPipe(connection, session);

                while (true)
                {
                    ReadResult read = await pipe.Input.ReadAsync();

                    var reader = new SequenceReader<byte>(read.Buffer);
                    if (reader.TryReadTo(out ReadOnlySequence<byte> _, "\r\n\r\n"u8, advancePastDelimiter: true))
                    {
                        pipe.Input.AdvanceTo(reader.Position);   // the head only
                        break;
                    }

                    pipe.Input.AdvanceTo(read.Buffer.Start, read.Buffer.End);
                    if (read.IsCompleted)
                    {
                        return;
                    }
                }

                // The body is one write on loopback, so it is all here within milliseconds; this is
                // a backstop for the pump to run as far as it is going to, not a measurement.
                await Task.Delay(500);

                long held = 0;
                if (pipe.Input.TryRead(out ReadResult rest))
                {
                    held = rest.Buffer.Length;
                    pipe.Input.AdvanceTo(rest.Buffer.Start);
                }

                const string body = "measured";
                pipe.Output.Write(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
                await pipe.Output.FlushAsync();

                unread.TrySetResult(held);
            }
            catch
            {
                // Harness port probes fail the handshake; not this test's concern.
            }
            finally
            {
                if (pipe is not null)
                {
                    await pipe.DisposeAsync();   // releases the pump parked at the threshold
                }
                else
                {
                    session?.Dispose();
                }
                connection.DecRef();
            }
        };

    private static bool Terminated(in ReadOnlySequence<byte> buffer)
    {
        var reader = new SequenceReader<byte>(buffer);
        return reader.TryReadTo(out ReadOnlySequence<byte> _, "\r\n\r\n"u8, advancePastDelimiter: true);
    }

    // Serves one request off the decrypted PipeReader and answers as plaintext through the pipe's
    // writer, which is where kTLS takes over.
    private static async Task PipeHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);

            ReadResult read = await pipe.Input.ReadAsync();
            pipe.Input.AdvanceTo(read.Buffer.End);

            const string body = "pipe-tls-ok";
            pipe.Output.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
            await pipe.Output.FlushAsync();
        }
        catch
        {
            // The client hung up, or the handshake failed - either way there is nothing to serve.
        }
        finally
        {
            if (pipe is not null)
            {
                await pipe.DisposeAsync();   // disposes the session too
            }
            else
            {
                session?.Dispose();
            }
            connection.DecRef();
        }
    }

    // Reads until the pipe reports something, and publishes whether that was a fault or an EOF.
    private static Func<Reactor, TcpConnection, Task> FaultReportingHandler(TaskCompletionSource<string> faulted)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                // Outside the reporting try on purpose. The harness probes the port with a raw TCP
                // connection to learn the server is listening, which fails the handshake - and if
                // that counted as "the reader observed a fault" the test would pass without the
                // garbage ever arriving.
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;
                }

                pipe = new TlsConnectionDualPipe(connection, session);

                while (true)
                {
                    ReadResult read = await pipe.Input.ReadAsync();
                    pipe.Input.AdvanceTo(read.Buffer.End);

                    if (read.IsCompleted)
                    {
                        // Clean completion - which for this test is the WRONG answer.
                        faulted.TrySetResult(string.Empty);
                        return;
                    }
                }
            }
            catch (Exception e)
            {
                faulted.TrySetResult(e.Message);
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
}
