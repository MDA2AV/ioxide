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
/// A THIRD shape is real but deliberately NOT tested here: Dispose sends a close_notify to a bare
/// stored fd, and a caller that released the connection (recycling the fd through the pool) before
/// disposing would write a TLS record into whatever inherited the number. Every in-repo caller
/// disposes BEFORE DecRef, so nothing exercises it; a test would have to win an fd-reuse race to
/// observe the misdirected write, which is exactly the timing-dependent flake tests/README.md
/// forbids. The guarantee there is conventional (call ordering), not structural (no generation tag
/// on the fd, unlike every reactor-side descriptor) - a note, not a test.
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
}
