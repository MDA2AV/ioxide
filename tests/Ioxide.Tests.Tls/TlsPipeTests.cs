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
            // returns without reading the rest - a rejected upload, an early 401. Disposal has to
            // return with the body still unread: nothing may be left waiting on it.
            //
            // The assertion has to be on the SERVER side. An earlier version of this test uploaded
            // a body and checked that a SECOND request was answered, which passes either way - the
            // response is written before the handler wedges, and the reactor keeps accepting while
            // one handler task sits abandoned. No client-visible signal separates the two cases. So
            // the handler reports the moment DisposeAsync RETURNS, which is the actual claim.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            var disposed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(HeadersOnlyHandler(disposed), r => TlsService.Start(r, options));

            Assert.True(PostBody(port, kilobytes: 32).Contains("headers-only"),
                "the upload was not answered");

            // Generous on purpose: the failure this catches is a disposal that never returns, which
            // does not complete at ANY deadline.
            Assert.True(disposed.Task.Wait(TimeSpan.FromSeconds(60)), "DisposeAsync never returned");
        });

        runner.Test("tls pipe: nothing is decrypted until the handler reads", () =>
        {
            // The body lands while the handler reads nothing, so it waits as ciphertext and the
            // connection has no read armed for it - a background pump would have decrypted it into
            // the pipe as it arrived. Then the handler reads, and gets all of it.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            const int bodyKilobytes = 96;
            var report = new TaskCompletionSource<(long Held, long Body)>(TaskCreationOptions.RunContinuationsAsynchronously);
            int port = TestServer.Start(OnDemandHandler(report, bodyKilobytes * 1024), r => TlsService.Start(r, options));

            Assert.True(UploadAfterContinue(port, bodyKilobytes).Contains("done"), "the upload was not answered");
            Assert.True(report.Task.Wait(TimeSpan.FromSeconds(30)), "the handler never reported");

            (long held, long body) = report.Task.Result;
            Assert.True(held == 0, $"{held} B of the body were decrypted before the handler read any of it");
            Assert.Equal((long)bodyKilobytes * 1024, body);
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
    /// Answers from the request headers and returns WITHOUT draining the body - an ordinary thing for
    /// a handler to do - and signals once <c>DisposeAsync</c> has RETURNED. A disposal that wedges
    /// never signals at all, which is what the test waits on.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> HeadersOnlyHandler(TaskCompletionSource disposed)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;

            // Set only on the connection that uploaded. The harness's liveness probe opens a raw TCP
            // connection and fails the handshake, so an unguarded signal would come from it.
            bool answered = false;

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

                        const string body = "headers-only";
                        pipe.Output.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}"));
                        await pipe.Output.FlushAsync();

                        answered = true;
                        return;   // the rest of the body stays unread on purpose
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

                if (answered)
                {
                    disposed.TrySetResult();
                }
            }
        };

    /// <summary>
    /// Sends a head plus a body in one go and returns whatever came back. The body stays small enough
    /// to sit in the server's recv queue, so the write does not block once the handler stops reading.
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

    /// <summary>
    /// Sends the head, waits for the server's 100 Continue, and only then the body - so the body can
    /// only arrive after the handler has taken the head. Returns the final response.
    /// </summary>
    private static string UploadAfterContinue(int port, int kilobytes)
    {
        using var sock = new System.Net.Sockets.TcpClient();
        sock.Connect("127.0.0.1", port);
        sock.SendTimeout = 10_000;
        sock.ReceiveTimeout = 10_000;

        using var ssl = new System.Net.Security.SslStream(sock.GetStream(), false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient("localhost");

        int length = kilobytes * 1024;
        ssl.Write(Encoding.ASCII.GetBytes(
            $"POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: {length}\r\nexpect: 100-continue\r\n\r\n"));
        ssl.Flush();

        var buf = new byte[256];
        int n = ssl.Read(buf, 0, buf.Length);
        if (n <= 0 || !Encoding.ASCII.GetString(buf, 0, n).Contains(" 100 "))
        {
            return "";
        }

        ssl.Write(new byte[length]);
        ssl.Flush();

        n = ssl.Read(buf, 0, buf.Length);
        return n > 0 ? Encoding.ASCII.GetString(buf, 0, n) : "";
    }

    /// <summary>
    /// Takes the head, answers 100 Continue, and reads nothing while the body lands. Reports how much
    /// of it had been decrypted by then, and how much it then read.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> OnDemandHandler(
        TaskCompletionSource<(long Held, long Body)> report, int bodyBytes)
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

                pipe.Output.Write("HTTP/1.1 100 Continue\r\n\r\n"u8);
                await pipe.Output.FlushAsync();

                // The client sends the whole body on the 100 Continue, on loopback: it is here within
                // milliseconds, and this is the backstop for that, not a measurement.
                await Task.Delay(500);

                long held = 0;
                if (pipe.Input.TryRead(out ReadResult waiting))
                {
                    held = waiting.Buffer.Length;
                    pipe.Input.AdvanceTo(waiting.Buffer.Start);
                }

                long body = 0;
                while (body < bodyBytes)
                {
                    ReadResult read = await pipe.Input.ReadAsync();
                    body += read.Buffer.Length;
                    pipe.Input.AdvanceTo(read.Buffer.End);

                    if (read.IsCompleted)
                    {
                        break;
                    }
                }

                const string done = "done";
                pipe.Output.Write(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Length: {done.Length}\r\n\r\n{done}"));
                await pipe.Output.FlushAsync();

                report.TrySetResult((held, body));
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
