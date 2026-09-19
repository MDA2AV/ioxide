using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// TlsEncryptingPipeWriter's side of the PipeWriter contract: what Complete commits, what happens
/// to staged plaintext, and how the staging buffer grows.
/// </summary>
/// <remarks>
/// The writer is only ever driven one way by the rest of the suite - a response well under the
/// 16 KB staging buffer, flushed, then disposed - so the guarantees it states in prose (Complete
/// commits, Complete does not throw, the staging buffer grows to whatever is staged) were unpinned.
/// These tests drive the shapes a real handler produces instead: a response larger than the staging
/// buffer, a response never flushed at all, and a handler that gives up on a flush the peer is not
/// draining and tears down anyway.
/// </remarks>
internal static class WriterContractTests
{
    /// <summary>
    /// Comfortably past both the 16 KB staging buffer and the 16 KB write slab the harness
    /// configures, and past ArrayPool's 1 MB pooled ceiling - so the doubling in Ensure, the slab
    /// growth underneath it, and the rent/return of an array the pool will not keep are all on the
    /// path of one response.
    /// </summary>
    private const int LargeBodyBytes = 2 * 1024 * 1024;

    /// <summary>How much is written per attempt while trying to park the connection's send.</summary>
    private const int ParkChunkBytes = 256 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("tls writer: a response larger than the staging buffer arrives intact", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(LargeBodyHandler, r => TlsService.Start(r, options));

            (int status, int length, bool intact) = GetTlsBody(port);
            Assert.Equal(200, status);
            Assert.Equal(LargeBodyBytes, length);
            Assert.True(intact, "the body arrived at full length but with the wrong bytes in it");
        });

        // The control for the pending test below, and the only test that drives Complete's commit
        // path at all: nothing here flushes, so the response exists solely because Complete
        // encrypted it on the way out.
        runner.Test("tls writer: Complete commits plaintext that was written and never flushed", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(NeverFlushesHandler, r => TlsService.Start(r, options));

            (int status, string body) = Client.GetTls(port, "/");
            Assert.Equal(200, status);
            Assert.Equal("committed-by-complete", body);
        });

        // Same commit path as the control, on a connection whose send is still in flight.
        //
        // PipeWriter.Complete is a notification and may not throw - the type says so itself, in the
        // comment explaining why its commit is wrapped in catch (IOException), and every caller of
        // it is a finally. But IOException is only what SSL_write can report; the commit continues
        // into TlsSession.WriteEncrypted, which drains the records out through
        // TcpConnection.GetSpan, and that refuses to hand out slab while a flush is in progress.
        //
        // The state is reachable from an ordinary handler: give a slow peer a deadline
        // (Task.WhenAny with a timeout), stop waiting on the flush when it passes, and tear the
        // connection down. The disposal path then completes the writer with the connection's send
        // still in flight, and what should be a notification throws out of a teardown - which is
        // where a leaked SSL and its BIOs come from, the exact outcome the IOException catch was
        // added to prevent.
        runner.Pending("tls writer: Complete does not throw while the connection's flush is in flight", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var report = new TaskCompletionSource<Outcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(AbandonedFlushHandler(report), r => TlsService.Start(r, options));

            // Blocks until the handler reports, holding the connection open and never reading a
            // byte of the response - closing it would release the parked send.
            RequestAndStopReading(port, report.Task);

            Assert.True(report.Task.Wait(TimeSpan.FromSeconds(5)),
                "the handler never reached the Complete under test");

            Outcome outcome = report.Task.Result;

            // Non-vacuous: the defect needs a flush genuinely still in flight AND plaintext
            // genuinely staged. Without both, Complete's commit is never reached and this would
            // pass while proving nothing.
            Assert.True(outcome.FlushPending,
                $"no flush was in flight when the writer was completed: {outcome.Error}");
            Assert.True(outcome.Staged > 0,
                $"nothing was staged, so Complete had nothing to commit: {outcome.Staged} B");

            Assert.True(outcome.Error.Length == 0,
                "Complete threw out of a teardown that may not fail: " + outcome.Error);
        }, "Complete catches only IOException, but its commit reaches TcpConnection.GetSpan, which "
           + "throws InvalidOperationException(\"Cannot write while flush is in progress\")");

        // The other half of the same two-line teardown, and the half that reached production: a
        // handler that flushed everything it wrote leaves Complete nothing to commit, so it returns
        // quietly and DisposeAsync's OWN flush is what meets the connection's one-flush-at-a-time
        // guard. Reported as a websocket over TLS faulting with "FlushAsync already in progress"
        // a few times per run (#234), where the throw escapes as a faulted connection handler.
        //
        // Same park as above, because the state is the same one: what differs is only that nothing
        // is staged before the teardown.
        runner.Test("tls writer: disposal does not throw while the connection's flush is in flight", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var report = new TaskCompletionSource<Outcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(AbandonedFlushDisposalHandler(report), r => TlsService.Start(r, options));

            RequestAndStopReading(port, report.Task);

            Assert.True(report.Task.Wait(TimeSpan.FromSeconds(5)),
                "the handler never reached the disposal under test");

            Outcome outcome = report.Task.Result;

            // Non-vacuous in both directions: a flush genuinely still in flight, and nothing staged.
            // Without the first there is no second flush to refuse; with the second this would be
            // measuring the pending test above, which throws a line earlier and for another reason.
            Assert.True(outcome.FlushPending,
                $"no flush was in flight when the pipe was disposed: {outcome.Error}");
            Assert.True(outcome.Staged == 0,
                $"plaintext was staged, so Complete threw before the flush under test: {outcome.Staged} B");

            Assert.True(outcome.Error.Length == 0,
                "disposal threw against a flush the application left in flight: " + outcome.Error);
        });
    }

    /// <summary>
    /// What the handler observed at the moment it completed the writer, or disposed the pipe.
    /// </summary>
    private readonly record struct Outcome(bool FlushPending, long Staged, string Error);

    /// <summary>
    /// Answers a request head with a body several times the staging buffer, in one Write and one
    /// flush - the shape that makes the writer grow its staging buffer and the connection grow its
    /// slab underneath.
    /// </summary>
    private static async Task LargeBodyHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);

            if (!await ReadHeadAsync(pipe.Input))
            {
                return;
            }

            pipe.Output.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {LargeBodyBytes}\r\n\r\n"));
            pipe.Output.Write(Pattern(LargeBodyBytes));
            await pipe.Output.FlushAsync();
        }
        catch
        {
            // The harness probes the port with a raw TCP connection, which fails the handshake.
        }
        finally
        {
            await ReleaseAsync(pipe, session, connection);
        }
    }

    /// <summary>
    /// Writes a whole response and never flushes it, which is a documented way to use this writer:
    /// Complete commits advanced-but-unflushed plaintext and the connection's own final flush
    /// carries it out.
    /// </summary>
    private static async Task NeverFlushesHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);

            if (!await ReadHeadAsync(pipe.Input))
            {
                return;
            }

            const string body = "committed-by-complete";
            pipe.Output.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));

            // No FlushAsync anywhere. DisposeAsync below completes the writer, which is what has to
            // commit these bytes.
        }
        catch
        {
            // Harness port probe.
        }
        finally
        {
            await ReleaseAsync(pipe, session, connection);
        }
    }

    /// <summary>
    /// The handler with a deadline: it writes until one flush stops coming back, gives up on it,
    /// stages a little more, and tears the connection down anyway. Reports what it saw at the
    /// moment it completed the writer - whether a flush was still in flight, how much plaintext was
    /// staged, and whatever Complete threw.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> AbandonedFlushHandler(TaskCompletionSource<Outcome> report)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;

            // Only the connection that got past the request head is this test's; the harness's
            // liveness probe fails the handshake above it and must never fill in the report.
            bool reproducing = false;

            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                pipe = new TlsConnectionDualPipe(connection, session);

                if (!await ReadHeadAsync(pipe.Input))
                {
                    return;
                }
                reproducing = true;

                // The peer never reads, so its window and this socket's send buffer fill and the
                // SEND stops completing. Written in chunks rather than as one guessed-at size:
                // how much a loopback pair absorbs before that happens is a property of the box.
                byte[] chunk = new byte[ParkChunkBytes];
                Task<FlushResult>? parked = null;

                for (int attempt = 0; attempt < 64 && parked is null; attempt++)
                {
                    pipe.Output.Write(chunk);
                    Task<FlushResult> flush = pipe.Output.FlushAsync().AsTask();

                    // A deadline, not a timing assertion: a flush that has not come back is the
                    // state under test, and one that has simply costs another chunk.
                    if (await Task.WhenAny(flush, Task.Delay(TimeSpan.FromSeconds(2))) != flush)
                    {
                        parked = flush;
                    }
                }

                if (parked is null)
                {
                    report.TrySetResult(new Outcome(false, 0,
                        "the peer drained 16 MB; no flush ever stayed in flight"));
                    return;
                }

                // Staged and deliberately not flushed - Complete is documented to commit it, and
                // that commit is what has to survive the flush still being in flight.
                pipe.Output.Write("bye"u8);
                long staged = pipe.Output.UnflushedBytes;

                // Read on the reactor thread with nothing awaited between here and Complete: a
                // flush completes only on this thread, so what is observed here is still true
                // inside Complete rather than a guess about it.
                bool flushPending = !parked.IsCompleted;

                // Called directly rather than through DisposeAsync, which calls exactly this on
                // exactly this state one line before flushing the connection. The claim is about
                // Complete alone: DisposeAsync's own next line, await _conn.FlushAsync(), throws
                // "FlushAsync already in progress" against a flush still in flight, and a test
                // asserting on the disposal would keep failing on that after Complete was fixed.
                string error = "";
                try
                {
                    pipe.Output.Complete();
                }
                catch (Exception e)
                {
                    error = $"{e.GetType().Name}: {e.Message}";
                }

                report.TrySetResult(new Outcome(flushPending, staged, error));

                // Tear down anyway, as the handler's finally would. Complete is idempotent, so the
                // disposal's own call to it is a no-op; whatever the connection's flush guard does
                // to the rest of the disposal is not this test's claim.
                TlsConnectionDualPipe disposing = pipe;
                pipe = null;   // disposed here; the finally must not do it a second time

                try
                {
                    await disposing.DisposeAsync();
                }
                catch
                {
                    // See above.
                }
            }
            catch (Exception e)
            {
                if (reproducing)
                {
                    report.TrySetResult(new Outcome(false, 0,
                        $"the reproduction broke before the disposal: {e.GetType().Name}: {e.Message}"));
                }
            }
            finally
            {
                await ReleaseAsync(pipe, session, connection);
            }
        };

    /// <summary>
    /// The handler of the production report: it writes until one flush stops coming back, gives up
    /// on it, and tears the connection down with nothing staged - so the disposal's own flush is
    /// the only call left that can throw. Reports whether a flush was still in flight, that nothing
    /// was staged, and whatever the disposal threw.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> AbandonedFlushDisposalHandler(TaskCompletionSource<Outcome> report)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;

            bool reproducing = false;

            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                pipe = new TlsConnectionDualPipe(connection, session);

                if (!await ReadHeadAsync(pipe.Input))
                {
                    return;
                }
                reproducing = true;

                byte[] chunk = new byte[ParkChunkBytes];
                Task<FlushResult>? parked = null;

                for (int attempt = 0; attempt < 64 && parked is null; attempt++)
                {
                    pipe.Output.Write(chunk);
                    Task<FlushResult> flush = pipe.Output.FlushAsync().AsTask();

                    if (await Task.WhenAny(flush, Task.Delay(TimeSpan.FromSeconds(2))) != flush)
                    {
                        parked = flush;
                    }
                }

                if (parked is null)
                {
                    report.TrySetResult(new Outcome(false, 0,
                        "the peer drained 16 MB; no flush ever stayed in flight"));
                    return;
                }

                // Deliberately nothing written here, unlike the test above: everything this handler
                // produced went into the flush that parked, which is the shape the report describes
                // - the application's writes were serialized and all of them were flushed.
                long staged = pipe.Output.UnflushedBytes;

                // Read on the reactor thread with nothing awaited before the disposal, so what is
                // reported is the state the disposal actually ran against.
                bool flushPending = !parked.IsCompleted;

                TlsConnectionDualPipe disposing = pipe;
                pipe = null;   // disposed here; the finally must not do it a second time

                string error = "";
                try
                {
                    await disposing.DisposeAsync();
                }
                catch (Exception e)
                {
                    error = $"{e.GetType().Name}: {e.Message}";
                }

                report.TrySetResult(new Outcome(flushPending, staged, error));
            }
            catch (Exception e)
            {
                if (reproducing)
                {
                    report.TrySetResult(new Outcome(false, 0,
                        $"the reproduction broke before the disposal: {e.GetType().Name}: {e.Message}"));
                }
            }
            finally
            {
                await ReleaseAsync(pipe, session, connection);
            }
        };

    /// <summary>
    /// Reads until the request head is complete. False means the stream ended first, which is a
    /// connection this suite has nothing to say about.
    /// </summary>
    private static async Task<bool> ReadHeadAsync(PipeReader input)
    {
        while (true)
        {
            ReadResult read = await input.ReadAsync();

            if (Terminated(read.Buffer))
            {
                input.AdvanceTo(read.Buffer.End);
                return true;
            }

            // Nothing consumed, everything examined: wait for the rest rather than spinning on the
            // same partial head.
            input.AdvanceTo(read.Buffer.Start, read.Buffer.End);

            if (read.IsCompleted)
            {
                return false;
            }
        }
    }

    private static bool Terminated(in ReadOnlySequence<byte> buffer)
    {
        var reader = new SequenceReader<byte>(buffer);
        return reader.TryReadTo(out ReadOnlySequence<byte> _, "\r\n\r\n"u8, advancePastDelimiter: true);
    }

    /// <summary>
    /// Teardown shared by the handlers here. Guarded, because one of these tests exists precisely
    /// because disposal can throw, and a handler that lets that escape its finally reports as a
    /// reactor fault instead of as the test's own result.
    /// </summary>
    private static async Task ReleaseAsync(TlsConnectionDualPipe? pipe, TlsSession? session, TcpConnection connection)
    {
        try
        {
            if (pipe is not null)
            {
                await pipe.DisposeAsync();
            }
            else
            {
                session?.Dispose();
            }
        }
        catch
        {
            // Reported through the test's own channel where it matters.
        }

        connection.DecRef();
    }

    private static byte[] Pattern(int length)
    {
        var body = new byte[length];
        for (int i = 0; i < length; i++)
        {
            body[i] = (byte)('a' + (i % 26));
        }
        return body;
    }

    /// <summary>
    /// Reads a whole Content-Length response over TLS, however large, and says whether the body is
    /// byte-for-byte what <see cref="Pattern"/> produced. Client.ReadResponse tops out at its 64 KB
    /// buffer, which is smaller than the responses these tests are about.
    /// </summary>
    private static (int Status, int Length, bool Intact) GetTlsBody(int port, int timeoutMs = 20_000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        ssl.Write(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n"));
        ssl.Flush();

        var received = new MemoryStream();
        var buffer = new byte[64 * 1024];
        int headEnd = -1;

        while (headEnd < 0)
        {
            int n = ssl.Read(buffer, 0, buffer.Length);
            if (n <= 0)
            {
                throw new Exception("the connection closed before the head arrived");
            }
            received.Write(buffer, 0, n);
            headEnd = received.GetBuffer().AsSpan(0, (int)received.Length).IndexOf("\r\n\r\n"u8);
        }

        string head = Encoding.ASCII.GetString(received.GetBuffer(), 0, headEnd);
        int status = int.Parse(head.AsSpan(9, 3));
        int contentLength = ContentLength(head);
        int bodyStart = headEnd + 4;

        while (received.Length - bodyStart < contentLength)
        {
            int n = ssl.Read(buffer, 0, buffer.Length);
            if (n <= 0)
            {
                break;   // short body: reported as a length mismatch, not as an exception
            }
            received.Write(buffer, 0, n);
        }

        int length = (int)received.Length - bodyStart;
        ReadOnlySpan<byte> body = received.GetBuffer().AsSpan(bodyStart, Math.Max(length, 0));
        bool intact = length == contentLength && body.SequenceEqual(Pattern(contentLength));

        return (status, length, intact);
    }

    private static int ContentLength(string head)
    {
        foreach (string line in head.Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                return int.Parse(line.AsSpan("Content-Length:".Length).Trim());
            }
        }
        return 0;
    }

    /// <summary>
    /// Handshakes, asks for a response, and then never reads a byte of it - the peer that fills a
    /// server's send buffer and leaves its flush in flight. Stays connected until the server has
    /// reported, because closing would release the send and dissolve the state under test.
    /// </summary>
    private static void RequestAndStopReading(int port, Task settled)
    {
        using var client = new TcpClient();

        // A small receive window, set before the connect so it is what gets advertised: the server
        // then parks within a megabyte or so instead of after however much this box's autotuning
        // decides to buffer.
        client.ReceiveBufferSize = 4096;
        client.Connect("127.0.0.1", port);

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        ssl.Write(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n"));
        ssl.Flush();

        settled.Wait(TimeSpan.FromSeconds(60));
    }
}
