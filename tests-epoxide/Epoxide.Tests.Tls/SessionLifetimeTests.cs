using epoxide;
using epoxide.tls;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// <see cref="TlsSession"/>'s lifetime: it is a public disposable a user holds, so what its entry
/// points do once <see cref="TlsSession.Dispose"/> has freed the native SSL* and both BIOs is part
/// of its contract - whether stated or not.
/// </summary>
/// <remarks>
/// From probing a real session obtained through the handshake and then poked after disposal:
///
/// 1. Double disposal is SAFE and enforced: the <c>_disposed</c> flag short-circuits the second
///    call, so the SSL* is freed once. Pinned below - a regression that dropped the guard would
///    double-free.
///
/// 2. Use-after-dispose is refused. In ioxide it is not, and cannot be tested there: the entry
///    points dereference the freed handles. In epoxide a session's reader and writer may be on
///    other threads when it is disposed, so every BoringSSL call checks the flag under the
///    session's lock, and a call that comes after the disposal fails with
///    <see cref="ObjectDisposedException"/> (the version getters answer 0) instead of reaching freed
///    memory. Pinned below too.
///
/// A THIRD shape is guarded but deliberately NOT tested here: Dispose sends a close_notify to the
/// stored fd, and a caller that released the connection (recycling the fd through the pool) before
/// disposing would write a TLS record into whatever inherited the number. Dispose checks the
/// connection's generation first, which closes that once the recycle has happened; a test would
/// have to win an fd-reuse race to observe anything, which is exactly the timing-dependent flake
/// tests/README.md forbids. Every in-repo caller disposes BEFORE DecRef.
/// </remarks>
internal static class SessionLifetimeTests
{
    // Written on the reactor thread inside the probe handler, read on the test thread.
    private static volatile bool _served;
    private static volatile bool _probeDone;
    private static volatile string? _secondDisposeError;       // exception type name, or "none"
    private static volatile string? _writeAfterDispose;        // exception type name, or "none"
    private static volatile string? _decryptAfterDispose;      // exception type name, or "none"
    private static volatile int _versionAfterDispose = -1;

    public static void Register(Runner runner)
    {
        // Teardown paths legitimately reach Dispose twice.
        runner.Test("lifetime: disposing a session twice is a no-op", () =>
        {
            Drive();

            Assert.True(_served, "the session never served a request, so the probe never ran");
            Assert.True(_probeDone, "the disposal probe did not complete");
            Assert.Equal("none", _secondDisposeError);   // the _disposed guard makes the 2nd Dispose a no-op
        });

        // epoxide's own: a disposal on one thread can meet a read or a write still running on
        // another, so the session checks for it under its lock, and a call made after it is refused.
        runner.Test("lifetime: a session used after disposal refuses, rather than reaching the freed SSL", () =>
        {
            Drive();

            Assert.True(_served, "the session never served a request, so the probe never ran");
            Assert.True(_probeDone, "the disposal probe did not complete");
            Assert.Equal(nameof(ObjectDisposedException), _writeAfterDispose);
            Assert.Equal(nameof(ObjectDisposedException), _decryptAfterDispose);
            Assert.Equal(0, _versionAfterDispose);
        });
    }

    /// <summary>Start a server, serve one TLS request, and wait for the post-dispose probe to run.</summary>
    private static void Drive()
    {
        _served = false;
        _probeDone = false;
        _secondDisposeError = null;
        _writeAfterDispose = null;
        _decryptAfterDispose = null;
        _versionAfterDispose = -1;

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
                    TlsWire.Write(conn, 200, "ok", tls);
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
                Probe(tls, conn);
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
    private static unsafe void Probe(TlsSession tls, TcpConnection conn)
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

        _writeAfterDispose = Outcome(() => tls.Write(conn, "after"u8));
        _decryptAfterDispose = Outcome(() =>
        {
            byte* record = stackalloc byte[8];
            tls.Decrypt(record, 8);
        });
        _versionAfterDispose = tls.NegotiatedProtocolVersion;

        _probeDone = true;
    }

    private static string Outcome(Action call)
    {
        try
        {
            call();
            return "none";
        }
        catch (Exception e)
        {
            return e.GetType().Name;
        }
    }

    private static unsafe void AppendPlaintext(TlsSession tls, in SpscRecvRing.Item item, List<byte> carry)
    {
        carry.AddRange(tls.Decrypt(item.Ptr, item.Len).ToArray());
    }
}
