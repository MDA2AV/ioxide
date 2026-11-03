using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using ioxide;
using ioxide.tls;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TlsSession"/>'s lifetime: it is a public disposable a user holds, so what its entry
/// points do once <see cref="TlsSession.Dispose"/> has freed the native SSL* and both BIOs is part
/// of its contract - whether stated or not.
/// </summary>
/// <remarks>
/// Two findings, from probing a real session obtained through the handshake and then poked after
/// disposal (see the DIAG history in git if reproducing):
///
/// 1. Double disposal is SAFE and enforced: the <c>_disposed</c> flag short-circuits the second
///    call, so the SSL* is freed once. Pinned below as an ordinary <see cref="Runner.Test"/> - a
///    regression that dropped the guard would double-free. This is the control: the type DOES guard
///    one thing, which is why the absence of any guard on the rest is a choice, not an oversight.
///
/// 2. Use-after-dispose is NOT refused: <see cref="TlsSession.Write"/>,
///    <see cref="TlsSession.Decrypt"/> and the version getters dereference the freed handles with
///    no disposed-guard. A guarded type would answer with <see cref="ObjectDisposedException"/>;
///    this one runs SSL_write against freed memory. Not exercised: OpenSSL happened to return an
///    error there, BoringSSL segfaults, and neither is something a test can pin.
///
/// A third shape is pinned as well: a caller that releases the connection before disposing. Dispose
/// sends close_notify on a bare stored fd, which by then may be the next client's, so it first checks
/// the connection is still in the life the session was made for. Showing it needs no race: one reactor
/// and its LIFO pool hand the second client the first one's connection, and its fd, before the first
/// session is disposed.
/// </remarks>
internal static class SessionLifetimeTests
{
    // Written on the reactor thread inside the probe handler, read on the test thread.
    private static volatile bool _served;
    private static volatile bool _probeDone;
    private static volatile string? _secondDisposeError;       // exception type name, or "none"

    public static void Register(Runner runner)
    {
        // Use-after-dispose was reviewed as a defect here and deliberately left unguarded. Writing
        // after Dispose is a use-after-free rather than a wrong exception type, but no supported
        // sequence reaches it: every owner in this library disposes the session LAST, on purpose -
        // TlsConnectionDualPipe.DisposeAsync unwinds the pump first, and HopDuplexPipe says so in as
        // many words. A disposed check on Write and Decrypt would sit on the per-request path to
        // refuse a call only a caller violating IDisposable can make, so what is pinned is the part
        // that teardown paths legitimately reach twice.
        runner.Test("lifetime: disposing a session twice is a no-op", () =>
        {
            Drive();

            Assert.True(_served, "the session never served a request, so the probe never ran");
            Assert.True(_probeDone, "the disposal probe did not complete");
            Assert.Equal("none", _secondDisposeError);   // the _disposed guard makes the 2nd Dispose a no-op
        });

        runner.Test("lifetime: a session disposed after its connection was recycled sends the next client nothing", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
            var reuse = new Reuse();
            int port = TestServer.Start((r, conn) => ReuseHandler(r, conn, reuse), r => TlsService.Start(r, options));

            // The probe's descriptor must be free before the first accept: freed after it, the second accept would take it.
            Assert.True(reuse.ProbeGone.Wait(10_000), "the harness's readiness probe never reached the handler");

            // Made up front: a client socket made later could take the descriptor the first connection frees.
            using var first = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 10_000 };
            using var second = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveTimeout = 10_000 };

            first.Connect(IPAddress.Loopback, port);
            using var firstTls = new SslStream(new NetworkStream(first), leaveInnerStreamOpen: false, (_, _, _, _) => true);
            firstTls.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls12,   // a misdirected close_notify then arrives as an alert record
            });

            first.Shutdown(SocketShutdown.Send);   // the server releases the connection and keeps the session
            Assert.True(reuse.FirstReleased.Wait(10_000), "the server never released the first connection");

            second.Connect(IPAddress.Loopback, port);
            var tap = new FirstRecordType(new NetworkStream(second));
            using var secondTls = new SslStream(tap, leaveInnerStreamOpen: false, (_, _, _, _) => true);
            (int Status, string Body) answer = (0, "");
            string? failure = null;
            try
            {
                secondTls.AuthenticateAsClient(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    EnabledSslProtocols = SslProtocols.Tls13,
                });
                Client.Send(secondTls, "/");
                answer = Client.ReadResponse(secondTls);
            }
            catch (Exception e)
            {
                failure = e.Message;
            }

            Assert.True(reuse.Reused.Task.Wait(10_000), "the second client never reached the handler");
            (bool sameConnection, int firstFd, int secondFd) = reuse.Reused.Task.Result;
            Assert.True(sameConnection, "the second client was not handed the first one's pooled connection, so nothing was reused");
            Assert.True(secondFd == firstFd,
                $"the second client was accepted on fd {secondFd}, not the first one's {firstFd}, so a misdirected close_notify could not reach it");

            Assert.True(tap.Type == HandshakeRecord,
                $"the second client's first record was type {tap.Type}, not its ServerHello: the first session's close_notify reached it");
            Assert.True(failure is null, $"the second client's TLS session failed: {failure}");
            Assert.Equal(200, answer.Status);
            Assert.Equal("ok", answer.Body);
        });
    }

    /// <summary>Start a server, serve one TLS request, and wait for the post-dispose probe to run.</summary>
    private static void Drive()
    {
        _served = false;
        _probeDone = false;
        _secondDisposeError = null;

        (string certPath, string keyPath) = TestCert.Ensure();
        var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
        int port = TestServer.Start(ProbeHandler, r => TlsService.Start(r, options));

        // Serving the request proves the session was live - handshake, decrypt and encrypt all ran
        // on it - so the probe that follows is not passing against a session that never worked.
        (int status, string body) = Client.GetTls(port, "/");
        Assert.Equal(200, status);
        Assert.Equal("ok", body);

        // The probe runs on the reactor thread just after the response flushes; wait for it. Bounded
        // well under the runner's own watchdog so a genuine hang still surfaces as a test failure.
        for (int i = 0; i < 500 && !_probeDone; i++)
        {
            Thread.Sleep(10);
        }
    }

    private static async Task ProbeHandler(Reactor r, TcpConnection conn)
    {
        TlsSession? tls = null;
        var carry = new List<byte>();
        try
        {
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            // One request/response, so the session is known-good before we probe its afterlife.
            while (!_served)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        AppendPlaintext(tls, item, carry);
                        conn.ReturnBuffer(in item);
                    }
                }

                bool responded = false;
                int idx;
                while ((idx = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(carry).IndexOf("\r\n\r\n"u8)) >= 0)
                {
                    carry.RemoveRange(0, idx + 4);
                    responded = true;
                }

                if (responded)
                {
                    Wire.Write(conn, 200, "ok", tls);
                    await conn.FlushAsync();
                    _served = true;
                }

                if (snapshot.IsClosed)
                {
                    break;
                }
                conn.ResetRead();
            }

            if (_served)
            {
                Probe(tls);
                tls = null;   // Probe disposed it (twice); don't dispose again in finally
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[lifetime-probe] handler: {e.Message}");
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    }

    /// <summary>Dispose the live session, then exercise its entry points afterwards and record what they do.</summary>
    private static void Probe(TlsSession tls)
    {
        tls.Dispose();   // frees the SSL* and both BIOs

        // Double dispose: the _disposed guard should make this a no-op.
        try
        {
            tls.Dispose();
            _secondDisposeError = "none";
        }
        catch (Exception e)
        {
            _secondDisposeError = e.GetType().Name;
        }

        _probeDone = true;
    }

    private static unsafe void AppendPlaintext(TlsSession tls, in SpscRecvRing.Item item, List<byte> carry)
    {
        carry.AddRange(tls.Decrypt(item.Ptr, item.Len).ToArray());
    }

    private sealed class Reuse
    {
        public readonly ManualResetEventSlim ProbeGone = new();
        public readonly ManualResetEventSlim FirstReleased = new();
        public readonly TaskCompletionSource<(bool SameConnection, int FirstFd, int SecondFd)> Reused =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        // Reactor thread only.
        public TcpConnection? First;
        public int FirstFd;
        public TlsSession? Parked;
    }

    // Serves the readiness probe, then the first client, then the second; the test lets each in only after the last.
    private static async Task ReuseHandler(Reactor reactor, TcpConnection connection, Reuse reuse)
    {
        if (reuse.Parked is { } parked)
        {
            // Disposed only now, while its connection already serves the second client.
            reuse.Parked = null;
            reuse.Reused.TrySetResult((ReferenceEquals(connection, reuse.First), reuse.FirstFd, connection.ClientFd));
            parked.Dispose();
        }

        TlsSession session;
        try
        {
            session = await reactor.GetService<TlsService>().AcceptAsync(connection);
        }
        catch (IOException)
        {
            connection.DecRef();
            reuse.ProbeGone.Set();   // the harness's readiness probe never completes a handshake
            return;
        }

        if (reuse.First is null)
        {
            await AnswerOne(connection, session);   // the first client asks nothing and leaves
            reuse.First = connection;
            reuse.FirstFd = connection.ClientFd;
            reuse.Parked = session;
            connection.DecRef();
            reuse.FirstReleased.Set();
            return;
        }

        try
        {
            await AnswerOne(connection, session);
        }
        finally
        {
            session.Dispose();
            connection.DecRef();
        }
    }

    // Answers one request, or returns once the peer has gone.
    private static async Task AnswerOne(TcpConnection connection, TlsSession session)
    {
        var carry = new List<byte>();
        while (true)
        {
            RecvSnapshot snapshot = await connection.ReadAsync();
            while (connection.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    AppendPlaintext(session, item, carry);
                    connection.ReturnBuffer(in item);
                }
            }

            if (System.Runtime.InteropServices.CollectionsMarshal.AsSpan(carry).IndexOf("\r\n\r\n"u8) >= 0)
            {
                Wire.Write(connection, 200, "ok", session);
                await connection.FlushAsync();
                return;
            }

            if (snapshot.IsClosed)
            {
                return;
            }
            connection.ResetRead();
        }
    }

    private const byte HandshakeRecord = 22;

    /// <summary>Keeps the content type of the first record read off the socket, from under the SslStream.</summary>
    private sealed class FirstRecordType(Stream inner) : Stream
    {
        public int Type { get; private set; } = -1;

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, count);
            if (n > 0 && Type < 0)
            {
                Type = buffer[offset];
            }
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override void Flush() => inner.Flush();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
