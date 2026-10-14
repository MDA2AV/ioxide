using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// ALPN on the TCP side: whose preference decides, what happens with no overlap, and what a
/// malformed offer list does.
/// </summary>
/// <remarks>
/// Driven with SslStream offering real ALPN lists, and answered by a handler that echoes
/// <see cref="TlsSession.NegotiatedAlpn"/> in the body - so each case pins BOTH views of the
/// negotiation: what the client was told, and what a handler would branch on to pick an h2 loop
/// over an h1 one. The select loop is additionally pinned by reflection for the malformed offers
/// OpenSSL never forwards - that test says why end-to-end cannot deliver them.
/// </remarks>
internal static class AlpnNegotiationTests
{
    // OpenSSL's tlsext callback results, restated because the binding class is internal to the
    // module. The values are ABI, not convention - they cannot drift.
    private const int TlsExtErrOk = 0;      // SSL_TLSEXT_ERR_OK
    private const int TlsExtErrNoAck = 3;   // SSL_TLSEXT_ERR_NOACK

    public static void Register(Runner runner)
    {
        runner.Test("alpn: the server's preference order decides, not the client's", () =>
        {
            // The one configuration in which server preference and client preference are
            // distinguishable: the SAME two-protocol offer, to two servers that differ only in
            // list order. The pair has to answer differently, which no order-independent
            // selection - client preference, hardcoded h2, first-offered - can do.
            string[] offer = ["http/1.1", "h2"];

            int h2First = StartEcho(["h2", "http/1.1"]);
            (_, string a, _, string bodyA) = Client.GetTlsSni(h2First, "/", null, alpn: offer);
            Assert.Equal("h2", a);
            Assert.True(bodyA.Contains("alpn=h2"),
                $"the handler must see the same choice the client was told; body: {bodyA}");

            int h1First = StartEcho(["http/1.1", "h2"]);
            (_, string b, _, string bodyB) = Client.GetTlsSni(h1First, "/", null, alpn: offer);
            Assert.Equal("http/1.1", b);
            Assert.True(bodyB.Contains("alpn=http/1.1"),
                $"the handler must see the same choice the client was told; body: {bodyB}");
        });

        runner.Test("alpn: a protocol the client did not offer is skipped, not imposed", () =>
        {
            // The walk has to CONTINUE past our favourite when the client lacks it, rather than
            // selecting it anyway - a client told a protocol it never offered aborts.
            int port = StartEcho(["h2", "http/1.1"]);

            (_, string alpn, int status, string body) = Client.GetTlsSni(port, "/", null, alpn: ["http/1.1"]);

            Assert.Equal("http/1.1", alpn);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alpn=http/1.1"), $"the handler must see http/1.1; body: {body}");
        });

        runner.Test("alpn: no shared protocol continues without alpn rather than alerting", () =>
        {
            // RFC 7301 3.2 says a server supporting none of the client's protocols SHALL alert
            // no_application_protocol. The callback deliberately deviates - NOACK continues the
            // handshake without the extension, on the theory that the client may still speak
            // HTTP/1.1. Pinned so a posture change to the RFC's alert is a conscious edit here,
            // not a silent one.
            int port = StartEcho(["h2"]);

            (_, string alpn, int status, string body) = Client.GetTlsSni(port, "/", null, alpn: ["spdy/3"]);

            Assert.Equal("", alpn);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alpn=none"),
                $"with nothing in common the handler must see no protocol, not a guess; body: {body}");
        });

        runner.Test("alpn: a client offering no alpn at all is served, and the server records none", () =>
        {
            // No extension in the ClientHello means the select callback never runs at all - the
            // curl-without-alpn case. The handshake must complete, and the handler's view must be
            // null rather than a stale or defaulted protocol.
            int port = StartEcho(["h2", "http/1.1"]);

            (_, string alpn, int status, string body) = Client.GetTlsSni(port, "/", null, alpn: null);

            Assert.Equal("", alpn);
            Assert.Equal(200, status);
            Assert.True(body.Contains("alpn=none"),
                $"a client that offered nothing must not be recorded as having negotiated; body: {body}");
        });

        runner.Test("alpn: the handler's NegotiatedAlpn matches what the client was told", () =>
        {
            // TlsSession.NegotiatedAlpn is what a handler serving h2 and h1 on one port branches
            // on. Nothing else in the suite reads it, so a CaptureAlpn that captured nothing - or
            // the wrong thing - was invisible until here.
            int port = StartEcho(["h2", "http/1.1"]);

            (_, string alpn, _, string body) = Client.GetTlsSni(port, "/", null, alpn: ["h2"]);

            Assert.Equal("h2", alpn);
            Assert.True(body.Contains("alpn=h2"),
                $"the session must record the protocol the client was told; body: {body}");
        });

        runner.Test("alpn: a 255-byte protocol name negotiates at the length limit", () =>
        {
            // 255 is the largest length the wire's one-byte prefix can carry, and the largest
            // BuildAlpnWire accepts - the boundary where an off-by-one in either shows up.
            string big = new string('a', 255);
            int port = StartEcho([big]);

            (_, string alpn, int status, string body) = Client.GetTlsSni(port, "/", null, alpn: [big]);

            Assert.Equal(big, alpn);
            Assert.Equal(200, status);
            Assert.True(body.Contains($"alpn={big}"), "the handler must see the full 255-byte name");
        });

        runner.Test("alpn: an unusable protocol list is refused at start", () =>
        {
            // The wire cannot express these - an empty list negotiates nothing forever, a
            // zero-length name is banned by RFC 7301, and 256 does not fit a one-byte length -
            // so each must be refused loudly at start, not built and left to fail per handshake.
            // The control for all three is every other test in this file starting successfully.
            Assert.True(StartFails([], "At least one ALPN protocol"),
                "an empty protocol list must be refused at start");
            Assert.True(StartFails([""], "must be 1..255"),
                "a zero-length protocol name must be refused at start");
            Assert.True(StartFails([new string('a', 256)], "must be 1..255"),
                "a 256-byte protocol name must be refused at start");
        });

        RegisterSelectLoopBounds(runner);

        runner.Test("alpn: a non-ascii protocol name must not negotiate as a different protocol", () =>
        {
            // BuildAlpnWire writes (byte)protocol[i] - the LOW BYTE of each UTF-16 unit. U+0168
            // has low byte 0x68, which is 'h', so a server configured to speak only "\u0168" + "2"
            // put the exact bytes "h2" on the wire and ACKed any client offering h2. Two distinct
            // protocol identifiers compared equal, the client was told h2, and CaptureAlpn recorded
            // h2 - a protocol the operator never listed. (The same cast is why the SAME non-ASCII
            // string configured on both sides failed to match: SslApplicationProtocol sends UTF-8.)
            // BuildAlpnWire now refuses a non-ASCII name, so the start below is refused.
            string exotic = "\u0168" + "2";   // two chars whose low bytes are 'h','2'

            (string cert, string key) = TestCert.Ensure();
            int port;
            try
            {
                port = TestServer.Start(EchoAlpn, r => TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = cert,
                    KeyPath = key,
                    Alpn = [exotic],
                }));
            }
            catch (Exception e) when (e.Message.Contains("ALPN") || e.Message.Contains('\u0168'))
            {
                // Refusing the configuration loudly is the other acceptable resolution. Narrow on
                // purpose: an unrelated failure to start must stay a failure, not a quiet pass.
                return;
            }

            // Control first: the server is alive and serves a client that negotiates nothing, so
            // the probe below cannot "pass" against a dead port.
            (_, _, int status, _) = Client.GetTlsSni(port, "/", null);
            Assert.Equal(200, status);

            string negotiated;
            try
            {
                (_, negotiated, _, _) = Client.GetTlsSni(port, "/", null, alpn: ["h2"]);
            }
            catch (AuthenticationException)
            {
                negotiated = "";   // declining to speak h2 satisfies the claim too
            }

            Assert.True(negotiated != "h2",
                "a server configured to speak only 'U+0168 2' ACKed h2 - the char-to-byte cast in "
                + "BuildAlpnWire makes two distinct protocol identifiers compare equal");
        });
    }

    /// <summary>
    /// The select loop's own bounds, driven by reflection with offer lists a real handshake can
    /// never deliver: OpenSSL validates the ClientHello's ALPN list while parsing it (empty or
    /// truncated entries are a decode_error alert) and hands the callback only the validated
    /// copy, so the loop's malformed-input handling is defence in depth that end-to-end tests
    /// structurally cannot reach. Unreachable is not unpinnable: if the bound is "simplified"
    /// away, this is the only test that notices.
    /// </summary>
    private static void RegisterSelectLoopBounds(Runner runner)
    {
        runner.Test("alpn: a truncated or empty offer entry is declined, never matched or overread", () =>
        {
            MethodInfo? core = typeof(TlsService).GetMethod(
                "AlpnSelectCore", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.True(core is not null,
                "AlpnSelectCore not found - the select loop moved; move this pin with it");

            byte[] wire = [2, (byte)'h', (byte)'2'];   // the server speaks h2 - built by hand, as BuildAlpnWire would
            GCHandle wireHandle = GCHandle.Alloc(wire);
            nint outSlot = Marshal.AllocHGlobal(IntPtr.Size);
            nint outLen = Marshal.AllocHGlobal(1);
            nint offer = Marshal.AllocHGlobal(64);

            try
            {
                int Run(byte[] bytes)
                {
                    Marshal.WriteIntPtr(outSlot, (nint)(-1));   // sentinels: a decline must leave both untouched
                    Marshal.WriteByte(outLen, 0xEE);
                    Marshal.Copy(bytes, 0, offer, bytes.Length);
                    return (int)core!.Invoke(null, [outSlot, outLen, offer, (uint)bytes.Length, GCHandle.ToIntPtr(wireHandle)])!;
                }

                // Control: a well-formed offer with h2 second matches, and *out points at the
                // NAME, not its length byte - the pointer arithmetic under test.
                int ok = Run([3, (byte)'f', (byte)'o', (byte)'o', 2, (byte)'h', (byte)'2']);
                Assert.Equal(TlsExtErrOk, ok);
                Assert.True(Marshal.ReadIntPtr(outSlot) == offer + 5,
                    "the selection must point at the protocol name inside the client's buffer");
                Assert.Equal((byte)2, Marshal.ReadByte(outLen));

                // An entry claiming more bytes than the list holds: declined, nothing written.
                int truncated = Run([5, (byte)'h', (byte)'2']);
                Assert.Equal(TlsExtErrNoAck, truncated);
                Assert.True(Marshal.ReadIntPtr(outSlot) == (nint)(-1),
                    "a declined offer must not have written a selection");
                Assert.Equal((byte)0xEE, Marshal.ReadByte(outLen));

                // Truncation AFTER a valid non-matching entry: the scan stops at the bound.
                Assert.Equal(TlsExtErrNoAck, Run([3, (byte)'f', (byte)'o', (byte)'o', 9, (byte)'h']));

                // Zero-length entries only: skipped without wedging (returning at all is the
                // no-infinite-loop assertion; the runner's watchdog backs it), and nothing selected.
                Assert.Equal(TlsExtErrNoAck, Run([0, 0, 0]));

                // A zero-length entry AHEAD of a real one does not derail the scan.
                int skipped = Run([0, 2, (byte)'h', (byte)'2']);
                Assert.Equal(TlsExtErrOk, skipped);
                Assert.True(Marshal.ReadIntPtr(outSlot) == offer + 2,
                    "the match after an empty entry must still point at its name");

                // An empty list, the degenerate bound.
                Assert.Equal(TlsExtErrNoAck, Run([]));
            }
            finally
            {
                wireHandle.Free();
                Marshal.FreeHGlobal(outSlot);
                Marshal.FreeHGlobal(outLen);
                Marshal.FreeHGlobal(offer);
            }
        });
    }

    /// <summary>Echo server: the body reports the ALPN the SESSION captured, so every test pins
    /// the server's view of the negotiation and not only the client's.</summary>
    private static int StartEcho(string[] alpn)
    {
        (string cert, string key) = TestCert.Ensure();

        return TestServer.Start(EchoAlpn, r => TlsService.Start(r, new TlsOptions
        {
            CertificatePath = cert,
            KeyPath = key,
            Alpn = alpn,
        }));
    }

    /// <summary>Whether starting with this ALPN list is refused for the stated reason.</summary>
    private static bool StartFails(string[] alpn, string because)
    {
        (string cert, string key) = TestCert.Ensure();

        try
        {
            TestServer.Start(EchoAlpn, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                Alpn = alpn,
            }));
            return false;
        }
        catch (Exception e)
        {
            return e.Message.Contains(because);
        }
    }

    /// <summary>
    /// The send-first TLS loop (see Handlers.TlsSendFirst for why answering precedes the first
    /// park), with one difference: the response body is "alpn=&lt;negotiated&gt;", read off
    /// <see cref="TlsSession.NegotiatedAlpn"/> the way a real handler would branch on it.
    /// </summary>
    private static async Task EchoAlpn(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;

        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);

            string view = session.NegotiatedAlpn ?? "none";
            byte[] response = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\ncontent-length: {5 + view.Length}\r\n\r\nalpn={view}");

            if (!session.DrainPlaintext().IsEmpty)
            {
                session.Write(connection, response);
                await connection.FlushAsync();
            }

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                session.Write(connection, response);
                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            session?.Dispose();
            connection.DecRef();
        }
    }
}
