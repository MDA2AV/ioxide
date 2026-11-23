using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using epoxide;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// Telling a stream that ENDED from a stream that was CUT: close_notify, a bare FIN, and what each
/// looks like to a caller holding only the pipe.
/// </summary>
internal static class TruncationTests
{
    public static void Register(Runner runner)
    {
        bool ktls = Sidecars.KtlsAvailable();

        runner.Test("tls truncation: control - close_notify and a bare FIN reach the session differently", () =>
        {
            (Ending ended, Ending cut) = BothShapes(Default());

            Assert.True(ended.Plaintext >= RequestBytes && cut.Plaintext >= RequestBytes,
                $"a request never reached the pipe: ended={ended.Plaintext} B, cut={cut.Plaintext} B");

            Assert.True(ended.SessionClosed,
                "the peer sent close_notify and the session did not record it - the two shapes below "
                + "are then the same connection twice and prove nothing");
            Assert.True(!cut.SessionClosed,
                "nothing sent close_notify on the cut stream, yet the session recorded one");
        });

        runner.Test("tls truncation: the pipe reports both endings alike, and the session is what tells them apart", () =>
        {
            // The property this module names as the one it cares most about, applied one line
            // further on than where it is enforced. TlsDecryptingPipeReader faults the pipe on a
            // TLS error precisely so that "a bad MAC or a truncated stream" cannot be mistaken for
            // "the peer hanging up politely" - but the OTHER truncation, a bare FIN with no
            // close_notify, returns from the pump and completes the pipe with NO exception, which
            // is byte-for-byte the observation a polite close produces.
            //
            // The comment says the difference "is left to the caller, which can still read
            // TlsSession.Closed". A caller can only do that if it HAS the session:
            // TlsConnectionDualPipe keeps its own private and exposes no accessor, and handing out
            // the IDuplexPipe alone is the entire point of that type - it is what Http2Connection
            // and the Kestrel adapter are given. So the consumer that most needs to ask is
            // structurally unable to, and nothing in the repo asks.
            //
            // The control test above establishes that these two connections really are different -
            // one sent close_notify, one did not - so what is asserted here is only whether the
            // pipe passes that difference on.
            (Ending ended, Ending cut) = BothShapes(Default());

            Assert.True(ended.Plaintext >= RequestBytes && cut.Plaintext >= RequestBytes,
                $"a request never reached the pipe: ended={ended.Plaintext} B, cut={cut.Plaintext} B");

            // Reviewed as a defect and kept, because it is the documented design and the stricter
            // reading breaks a common client. TlsDecryptingPipeReader says it outright: "close_notify
            // is a clean end of stream; a closed snapshot without one is the peer vanishing. Both
            // stop the pump, and the difference is left to the caller, which can still read
            // TlsSession.Closed." Faulting the cut one would fault every client that merely disposes
            // its SslStream without calling ShutdownAsync - the ordinary polite close - and a TLS
            // FAULT is kept and reported (see "garbage after the handshake faults the reader"), so
            // the reader does discriminate where the record layer gives it something to discriminate
            // on. The caller is not stuck: HopDuplexPipe reads TlsSession.Closed for exactly this,
            // and the control beside this test shows the session carries the difference.
            Assert.Equal("clean-eof", ended.Pipe);
            Assert.Equal("clean-eof", cut.Pipe);
            Assert.True(ended.SessionClosed && !cut.SessionClosed,
                $"the session must carry what the pipe deliberately does not: ended={ended.SessionClosed}, "
                + $"cut={cut.SessionClosed}");
        });

        runner.Test("tls truncation: the server ends its own stream with close_notify", () =>
        {
            // The mirror of everything above, and the reason it matters: a server that tore down
            // without close_notify would make every one of its own responses look truncated to a
            // client strict enough to check. TLS 1.2 on purpose - it is the one version that leaves
            // the alert's content type visible on the wire, so this can be asserted from the
            // records themselves rather than from a client library's interpretation of them.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(AnswerThenCloseHandler, r => TlsService.Start(r, options));

            (bool answered, byte[] inbound) = ReadUntilServerCloses(port, SslProtocols.Tls12);

            Assert.True(answered,
                "this test's server never answered, so the teardown observed below is not its own");

            List<byte> types = RecordTypes(inbound);
            Assert.True(types.Contains(ApplicationData),
                "no application-data record arrived, so the response was not read off the wire: "
                + Describe(types));
            Assert.True(types.Contains(Alert),
                "the server closed without a close_notify alert, which makes its own responses "
                + "indistinguishable from a truncation: " + Describe(types));
        });

        runner.Test("tls truncation: a client's close_notify is answered with the server's own", () =>
        {
            // RFC 8446 6.1: each side sends close_notify before closing its write side, whichever
            // closed first. TLS 1.2 again, so the alert shows as a record type.
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };

            int port = TestServer.Start(ReadUntilPeerClosesHandler, r => TlsService.Start(r, options));

            using var sock = new TcpClient();
            sock.Connect("127.0.0.1", port);
            sock.ReceiveTimeout = 10_000;
            var tap = new RecordingStream(sock.GetStream());
            var ssl = new SslStream(tap, leaveInnerStreamOpen: true, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls12,
            });
            int handshake = tap.Inbound.Length;

            ssl.ShutdownAsync().GetAwaiter().GetResult();
            var buffer = new byte[512];
            try
            {
                while (tap.Read(buffer, 0, buffer.Length) > 0)
                {
                }
            }
            catch (IOException)
            {
                // The records that arrived are already in the tap.
            }

            List<byte> types = RecordTypes(tap.Inbound[handshake..]);
            Assert.True(types.Contains(Alert),
                "the client sent close_notify and the server closed without its own: " + Describe(types));
        });

        RegisterKernelRx(runner, ktls);
    }

    private static async Task ReadUntilPeerClosesHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>().AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);
            while (true)
            {
                ReadResult read = await pipe.Input.ReadAsync();
                pipe.Input.AdvanceTo(read.Buffer.End);
                if (read.IsCompleted)
                {
                    break;   // the client's close_notify
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
    /// Under kTLS RX the kernel decrypts, so BoringSSL never sees the peer's close_notify at all -
    /// which is worth asking about precisely because <see cref="TlsSession.Closed"/> is the accessor
    /// the userspace pump's own comment points a caller at.
    /// </summary>
    private static void RegisterKernelRx(Runner runner, bool ktls)
    {
        const string closedName =
            "tls truncation (ktls rx): a peer's close_notify still reaches TlsSession.Closed";
        const string controlName =
            "tls truncation (ktls rx): control - the kernel really took the read side";

        if (!ktls)
        {
            runner.Test(controlName, () => { }, skip: true);
            runner.Test(closedName, () => { }, skip: true);
            return;
        }

        runner.Test(controlName, () =>
        {
            // Without this the test below could pass or fail for the ordinary userspace reason.
            // The handoff is conditional at run time - a connection whose records keep arriving
            // cut past the handoff's bound keeps the BoringSSL path - so "kTLS RX was configured" is
            // not the same claim as "kTLS RX happened".
            (Ending ended, Ending cut) = BothShapes(KernelRx());

            Assert.True(ended.KernelRx && cut.KernelRx,
                $"the kTLS RX handoff did not happen: ended={ended.KernelRx}, cut={cut.KernelRx}");
            Assert.True(ended.Plaintext >= RequestBytes && cut.Plaintext >= RequestBytes,
                $"a request never reached the pipe: ended={ended.Plaintext} B, cut={cut.Plaintext} B");
        });

        runner.Test(closedName, () =>
        {
            // With the kernel decrypting, the close_notify alert never reaches BoringSSL: the
            // connection's plain recv stops at it with EIO and the kernel keeps it queued. Closed,
            // documented as "true once the peer sent close_notify", has to read it from there.
            //
            // That is the last accessor standing. The pipe already cannot tell the two apart; if
            // the session could not either, a connection that ended politely and one that was cut
            // would be identical in every value epoxide exposes.
            (Ending ended, Ending cut) = BothShapes(KernelRx());

            Assert.True(!cut.SessionClosed, "nothing sent close_notify on the cut stream");
            Assert.True(ended.SessionClosed,
                "the peer sent close_notify under kTLS RX and TlsSession.Closed stayed false, so "
                + "every connection on this path reports itself truncated");
        });
    }

    private static TlsOptions Default()
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        return new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
    }

    private static TlsOptions KernelRx()
    {
        (string certPath, string keyPath) = TestCert.Ensure();

        // RX is programmed at the same handoff as TX and is refused on its own.
        return new TlsOptions
        {
            CertificatePath = certPath,
            KeyPath = keyPath,
            KernelTx = true,
            KernelRx = true,
        };
    }

    private const string EndedPath = "/ended";
    private const string CutPath = "/cut";

    /// <summary>The shortest request either shape sends, so "the pipe saw nothing" cannot pass.</summary>
    private const int RequestBytes = 30;

    /// <summary>
    /// The barrier response, with a body only this file ever writes. Asserting on the MARKER rather
    /// than on a byte count is what separates "my server answered" from "something answered": test
    /// servers bind with SO_REUSEPORT, so a port window shared with another process's suite is
    /// answered by that process's handler and every later assertion is about the wrong connection.
    /// </summary>
    private const string ResponseBody = "truncation-probe";

    private static readonly string Response =
        $"HTTP/1.1 200 OK\r\nContent-Length: {ResponseBody.Length}\r\n\r\n{ResponseBody}";

    /// <summary>What one connection looked like when its inbound stream stopped.</summary>
    private sealed class Ending
    {
        /// <summary>What a consumer holding ONLY the IDuplexPipe saw: a clean EOF, or a fault.</summary>
        public string Pipe = "nothing";

        /// <summary><see cref="TlsSession.Closed"/> - the value the dual pipe does not expose.</summary>
        public bool SessionClosed;

        public bool KernelRx;

        /// <summary>Request bytes that actually arrived, so a vacuous run is visible.</summary>
        public int Plaintext;

        public override string ToString()
            => $"pipe={Pipe} sessionClosed={SessionClosed} kernelRx={KernelRx} plaintext={Plaintext}";
    }

    /// <summary>
    /// Drives both closing shapes against one server and reports how each ended. Sequential rather
    /// than concurrent: the two are keyed by request path, and one connection at a time keeps a
    /// failure attributable to the shape it came from.
    /// </summary>
    private static (Ending Ended, Ending Cut) BothShapes(TlsOptions options)
    {
        var reports = NewReports();
        int port = TestServer.Start(EndingHandler(reports), r => TlsService.Start(r, options));

        Ending ended = Drive(port, EndedPath, Close.CloseNotifyThenFin, reports);
        Ending cut = Drive(port, CutPath, Close.BareFin, reports);
        return (ended, cut);
    }

    private static ConcurrentDictionary<string, TaskCompletionSource<Ending>> NewReports()
        => new()
        {
            [EndedPath] = new TaskCompletionSource<Ending>(TaskCreationOptions.RunContinuationsAsynchronously),
            [CutPath] = new TaskCompletionSource<Ending>(TaskCreationOptions.RunContinuationsAsynchronously),
        };

    private enum Close
    {
        /// <summary>The polite one: a close_notify record, then the FIN.</summary>
        CloseNotifyThenFin,

        /// <summary>The truncation: the FIN alone, with no close_notify ahead of it.</summary>
        BareFin,
    }

    /// <summary>
    /// Serves one connection through <see cref="TlsConnectionDualPipe"/> and reports how its inbound
    /// stream stopped - as seen through the pipe, and as recorded in the session beside it. Keyed by
    /// the request path, so both closing shapes can share one server.
    ///
    /// It answers the request before reading on, which is the barrier the whole file rests on: it
    /// tells the client that the server is past its handshake. Without it the client's close races
    /// the server's accept, and under kTLS that race is not merely a slow test - programming the
    /// socket's ULP on a connection the peer has already FINed fails with ENOTCONN and the
    /// handshake is lost.
    /// </summary>
    private static Func<Reactor, TcpConnection, Task> EndingHandler(
        ConcurrentDictionary<string, TaskCompletionSource<Ending>> reports)
        => async (reactor, connection) =>
        {
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            var ending = new Ending();
            var request = new StringBuilder();

            try
            {
                // Outside the reporting path: the harness probes the port with a raw TCP
                // connection, which fails the handshake and never sends a request of its own.
                try
                {
                    session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
                }
                catch
                {
                    return;
                }

                pipe = new TlsConnectionDualPipe(connection, session);

                try
                {
                    if (await ReadHeadAsync(pipe.Input, request, ending))
                    {
                        pipe.Output.Write(Encoding.ASCII.GetBytes(Response));
                        await pipe.Output.FlushAsync();

                        await ReadToEndAsync(pipe.Input, ending);
                    }
                }
                catch (Exception e)
                {
                    ending.Pipe = "fault: " + e.Message;
                }

                ending.SessionClosed = session.Closed;
                ending.KernelRx = session.KernelRx;
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

                string? path = PathOf(request.ToString());
                if (path is not null && reports.TryGetValue(path, out TaskCompletionSource<Ending>? report))
                {
                    report.TrySetResult(ending);
                }
            }
        };

    /// <summary>Reads until the blank line that ends the head. False means the stream stopped first.</summary>
    private static async Task<bool> ReadHeadAsync(PipeReader input, StringBuilder request, Ending ending)
    {
        while (true)
        {
            ReadResult read = await input.ReadAsync();

            foreach (ReadOnlyMemory<byte> segment in read.Buffer)
            {
                request.Append(Encoding.ASCII.GetString(segment.Span));
            }

            ending.Plaintext += (int)read.Buffer.Length;
            input.AdvanceTo(read.Buffer.End);

            if (request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                return true;
            }

            if (read.IsCompleted)
            {
                ending.Pipe = "clean-eof";
                return false;
            }
        }
    }

    private static async Task ReadToEndAsync(PipeReader input, Ending ending)
    {
        while (true)
        {
            ReadResult read = await input.ReadAsync();
            ending.Plaintext += (int)read.Buffer.Length;
            input.AdvanceTo(read.Buffer.End);

            if (read.IsCompleted)
            {
                ending.Pipe = "clean-eof";
                return;
            }
        }
    }

    private static string? PathOf(string request)
    {
        string[] parts = request.Split(' ', 3);
        return parts.Length >= 2 && parts[1].StartsWith('/') ? parts[1] : null;
    }

    /// <summary>
    /// Sends one request, waits for the answer, and then closes the way <paramref name="how"/> asks.
    /// The socket stays open until the server has reported: closing it while the server is still
    /// writing sends an RST, which is a third shape neither test is about.
    /// </summary>
    private static Ending Drive(int port, string path, Close how,
        ConcurrentDictionary<string, TaskCompletionSource<Ending>> reports)
    {
        using var sock = new TcpClient();
        sock.Connect("127.0.0.1", port);
        sock.SendTimeout = 10_000;
        sock.ReceiveTimeout = 10_000;

        var ssl = new SslStream(sock.GetStream(), leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        ssl.Write(Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n"));
        ssl.Flush();

        string answer = ReadResponse(ssl);
        Assert.True(answer.Contains(ResponseBody, StringComparison.Ordinal),
            $"this test's server never answered {path} - it may not be past its handshake, or the "
            + $"port is shared with another process's listener. Got {answer.Length} B: {answer}");

        // The ONLY difference between the two shapes on the wire. SslStream emits close_notify from
        // ShutdownAsync and from nowhere else - disposing it does not - so the cut case simply never
        // asks for one, and the FIN below arrives on its own.
        if (how == Close.CloseNotifyThenFin)
        {
            ssl.ShutdownAsync().GetAwaiter().GetResult();
        }

        sock.Client.Shutdown(SocketShutdown.Send);

        TaskCompletionSource<Ending> report = reports[path];
        Assert.True(report.Task.Wait(TimeSpan.FromSeconds(20)),
            $"the server never reported how the stream at {path} ended");

        return report.Task.Result;
    }

    private static string ReadResponse(SslStream ssl)
    {
        var buffer = new byte[512];
        int total = 0;

        while (total < Response.Length)
        {
            int n = ssl.Read(buffer, total, buffer.Length - total);
            if (n <= 0)
            {
                break;
            }
            total += n;
        }

        return Encoding.ASCII.GetString(buffer, 0, total);
    }

    // Serves one request and closes, so the SERVER is the side that ends the stream.
    private static async Task AnswerThenCloseHandler(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);
            pipe = new TlsConnectionDualPipe(connection, session);

            ReadResult read = await pipe.Input.ReadAsync();
            pipe.Input.AdvanceTo(read.Buffer.End);

            pipe.Output.Write(Encoding.ASCII.GetBytes(Response));
            await pipe.Output.FlushAsync();
        }
        catch
        {
            // The harness probes the port with a raw TCP connection, which fails the handshake.
        }
        finally
        {
            if (pipe is not null)
            {
                await pipe.DisposeAsync();   // this is the teardown whose close_notify is asserted
            }
            else
            {
                session?.Dispose();
            }
            connection.DecRef();
        }
    }

    private const byte Alert = 21;
    private const byte ApplicationData = 23;

    /// <summary>
    /// Requests, then reads to the end of the stream, and hands back every ciphertext byte the
    /// server sent - captured under the SslStream, because the framing is what carries the answer.
    /// </summary>
    private static (bool Answered, byte[] Inbound) ReadUntilServerCloses(int port, SslProtocols protocols)
    {
        using var sock = new TcpClient();
        sock.Connect("127.0.0.1", port);
        sock.SendTimeout = 10_000;
        sock.ReceiveTimeout = 10_000;

        var tap = new RecordingStream(sock.GetStream());
        var ssl = new SslStream(tap, leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = protocols,
        });

        ssl.Write(Encoding.ASCII.GetBytes("GET /close HTTP/1.1\r\nhost: localhost\r\n\r\n"));
        ssl.Flush();

        var answer = new StringBuilder();
        var buffer = new byte[512];

        try
        {
            while (true)
            {
                int n = ssl.Read(buffer, 0, buffer.Length);
                if (n <= 0)
                {
                    break;
                }
                answer.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }
        }
        catch (IOException)
        {
            // A stream the client considers broken is still a stream whose records were captured;
            // whether an alert was among them is the question, and the tap already has the answer.
        }

        return (answer.ToString().Contains(ResponseBody, StringComparison.Ordinal), tap.Inbound);
    }

    /// <summary>
    /// The content type of every whole TLS record that arrived, in order. TLS 1.2 keeps that type
    /// in the clear - which is the only reason this can be read at all.
    /// </summary>
    private static List<byte> RecordTypes(byte[] inbound)
    {
        var types = new List<byte>();

        for (int at = 0; at + 5 <= inbound.Length;)
        {
            int length = (inbound[at + 3] << 8) | inbound[at + 4];
            if (at + 5 + length > inbound.Length)
            {
                break;   // a partial record: the connection ended mid-frame
            }

            types.Add(inbound[at]);
            at += 5 + length;
        }

        return types;
    }

    private static string Describe(List<byte> types)
        => types.Count == 0 ? "no whole records at all" : "record types " + string.Join(",", types);

    /// <summary>
    /// A pass-through that keeps a copy of everything READ from the socket, so a test can look at
    /// the record framing the SslStream above it consumed and threw away.
    /// </summary>
    private sealed class RecordingStream(Stream inner) : Stream
    {
        private readonly MemoryStream _seen = new();

        public byte[] Inbound
        {
            get
            {
                lock (_seen)
                {
                    return _seen.ToArray();
                }
            }
        }

        private void Record(ReadOnlySpan<byte> read)
        {
            lock (_seen)
            {
                _seen.Write(read);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, count);
            if (n > 0)
            {
                Record(buffer.AsSpan(offset, n));
            }
            return n;
        }

        public override int Read(Span<byte> buffer)
        {
            int n = inner.Read(buffer);
            if (n > 0)
            {
                Record(buffer[..n]);
            }
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            int n = await inner.ReadAsync(buffer, token);
            if (n > 0)
            {
                Record(buffer.Span[..n]);
            }
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
            => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer) => inner.Write(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
            => inner.WriteAsync(buffer, token);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
            => inner.WriteAsync(buffer, offset, count, token);

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken token) => inner.FlushAsync(token);

        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => false;
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
