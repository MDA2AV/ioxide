using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using epoxide;
using epoxide.tls;

namespace Epoxide.Tests;

/// <summary>
/// TLS 1.3 session resumption: that a returning client is served at all, what its ticket carries,
/// and what a certificate rotation does to one.
/// </summary>
/// <remarks>
/// Nothing else in this suite resumes anything - every other connection is a fresh full handshake -
/// so every property below was unpinned until now, including one the server explicitly configures
/// for (<c>SSL_CTX_set_session_id_context</c>) and one it states as an invariant in a comment and
/// does not have (a ticket outliving a rotation).
///
/// Resumption is driven with SslStream because it caches sessions per process and offers them for
/// the same target host, which is enough to get a ticket back on the wire without hand-rolling a
/// client. Every test uses a target host of its own: the cache is keyed by that name, so sharing
/// one would let a ticket from a neighbouring test - or from a server this one has already stopped
/// - be the thing offered, and each of these tests asserts on WHICH handshake happened.
///
/// What "resumed" means here is read off the wire rather than inferred, since neither side reports
/// it: the ClientHello carrying a pre_shared_key extension is the client offering its ticket, and
/// the ServerHello carrying one back is the server having accepted it (RFC 8446 4.2.11). Both
/// hellos are plaintext, so a tap on the inner stream can see them. Timing is never consulted.
/// </remarks>
internal static class SessionResumptionTests
{
    public static void Register(Runner runner)
    {
        // Why an mTLS port rather than a plain one: this is the case that breaks. An OpenSSL server
        // with SSL_VERIFY_PEER and no session id context does not merely decline the ticket - it
        // fails the whole handshake with "session id context uninitialized" and an internal_error
        // alert, so the second connection of every caching client dies. Verified against this box's
        // OpenSSL (3.0.13) in a standalone server whose only variable was that call, on TLS 1.3 and
        // TLS 1.2 alike; TlsService.SessionIdContext is what keeps it out of this suite's way.
        runner.Test("resume: an mTLS port serves a client that returns with a ticket, still as itself", () =>
        {
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey, _, _)
                = TestCert.EnsureMutualTls();

            int port = TestServer.Start(TlsHandlers.TlsIdentity, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = serverCert,
                KeyPath = serverKey,
                ClientCaPath = ca,
                RequireClientCertificate = true,
            }));

            Handshake first = Connect(port, "resume-mtls.test", clientCert, clientKey);
            Assert.True(first.Result == Outcome.Served, $"the first connection was not served: {first.Detail}");
            Assert.True(!first.AcceptedPsk, "the first connection must be a full handshake - a ticket "
                + "was already in the cache for this host, so nothing below distinguishes anything");
            Assert.True(first.Body.Contains("alice"), $"the handler should have seen CN=alice, got: {first.Body}");

            Handshake second = Connect(port, "resume-mtls.test", clientCert, clientKey);

            // Without this the test passes on a client that quietly stopped caching, which is the
            // only way it could be green while the server refuses every resumption there is.
            Assert.True(second.OfferedPsk,
                "the client did not offer the ticket it was issued, so no resumption was attempted at all");
            Assert.True(second.Result == Outcome.Served,
                $"a client returning with a ticket must still be served: {second.Detail}");
            Assert.True(second.AcceptedPsk,
                "the server refused the ticket and handshook in full, so this port issues tickets it "
                + "will not honour");
            Assert.True(second.Body.Contains("alice"),
                $"the identity verified during the full handshake must survive the resumption, got: {second.Body}");
        });

        // The control for the two rotation tests below, and the canary for the Pending: same server
        // shape, same client, no rotation. If this one goes red, resumption stopped happening for a
        // reason that has nothing to do with rotating anything, and the Pending is reporting on
        // machinery rather than on the defect it names.
        runner.Test("control: a second connection to a port that has not rotated resumes", () =>
        {
            (_, string cert, string key) = TestCert.EnsureNamedFromCa("resume-control.test");

            int port = TestServer.Start(TlsHandlers.TlsIdentity, r => TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
            }));

            Handshake first = Connect(port, "resume-control.test", null, null);
            Assert.True(first.Result == Outcome.Served, $"the first connection was not served: {first.Detail}");
            Assert.True(!first.AcceptedPsk, "the first connection must be a full handshake");

            Handshake second = Connect(port, "resume-control.test", null, null);
            Assert.True(second.OfferedPsk, "the client did not offer the ticket it was issued");
            Assert.True(second.AcceptedPsk,
                $"the server refused a ticket it issued a moment earlier: {second.Detail}");
        });

        runner.Test("resume: a ticket issued before a rotation is refused after it, and the client is still served", () =>
        {
            (_, string first, string firstKey) = TestCert.EnsureNamedFromCa("resume-rotate.test");
            (_, string renewed, string renewedKey) = TestCert.EnsureRenewedFromCa("resume-rotate.test");

            TlsService? service = null;
            int port = TestServer.Start(TlsHandlers.TlsIdentity, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = first,
                KeyPath = firstKey,
            }));

            Handshake full = Connect(port, "resume-rotate.test", null, null);
            Assert.True(full.Result == Outcome.Served, $"the first connection was not served: {full.Detail}");

            // Resumption has to be working BEFORE the rotation, or what follows says nothing about
            // rotating. The control above is the same claim as a test of its own, so a failure here
            // is not silently absorbed into the PEND.
            Handshake resumed = Connect(port, "resume-rotate.test", null, null);
            Assert.True(resumed.AcceptedPsk, $"resumption was not working before the rotation: {resumed.Detail}");

            service!.ReplaceCertificates(new TlsCertificate
            {
                CertificatePath = renewed,
                KeyPath = renewedKey,
            });

            Handshake after = Connect(port, "resume-rotate.test", null, null);

            // Reviewed as a defect and kept as the posture. Ticket KEYS are per SSL_CTX and
            // ReplaceCertificates builds new contexts, so a rotation retires them - which is what
            // nginx, Apache and HAProxy also do unless an explicit ticket-key file says otherwise.
            // The cost is real (a full handshake per returning client at every renewal) and the
            // alternative is worse, for the reason spelled out below this test: anchors given as a
            // path are re-read on every rotation, and a ticket that outlived one would carry the
            // old verify verdict past the new anchors. What must hold is that the client is still
            // SERVED - a retired ticket is a slower handshake, never an outage.
            Assert.True(after.Result == Outcome.Served,
                $"the connection after the rotation was not served: {after.Detail}");
            Assert.True(after.OfferedPsk, "the client did not offer its ticket after the rotation");
            Assert.True(!after.AcceptedPsk,
                "a ticket issued before the rotation was accepted after it: the rebuild is supposed "
                + "to retire the keys, and the test below depends on it doing so");
        });

        // The other side of that coin, and the reason the Pending must not be fixed carelessly.
        // Anchors given as ClientCaPath are re-read on every rotation, which is how an issuer is
        // revoked - so a resumption that survived a rotation would have to answer for the client
        // whose issuer that rotation removed. On a resumption no certificate is exchanged at all
        // and BoringSSL restores the stored peer certificate and its verify result, so a ticket that
        // outlived a rotation would carry the old verdict past the new anchors.
        runner.Test("resume: a ticket does not outlive the removal of its issuer from the anchors", () =>
        {
            (string ca, string serverCert, string serverKey, string clientCert, string clientKey, _, _)
                = TestCert.EnsureMutualTls();

            string anchors = Path.Combine(Path.GetTempPath(),
                $"epoxide-resume-anchors-{Environment.ProcessId}-{Random.Shared.Next():x8}.pem");
            File.WriteAllText(anchors, File.ReadAllText(ca));

            try
            {
                TlsService? service = null;
                int port = TestServer.Start(TlsHandlers.TlsIdentity, r => service = TlsService.Start(r, new TlsOptions
                {
                    CertificatePath = serverCert,
                    KeyPath = serverKey,
                    ClientCaPath = anchors,
                    RequireClientCertificate = true,
                }));

                Handshake first = Connect(port, "resume-anchors.test", clientCert, clientKey);
                Assert.True(first.Result == Outcome.Served, $"the first connection was not served: {first.Detail}");

                // The control, and it is what makes the refusal below mean anything: the same
                // client over the same rotation, differing only in whether its issuer is still in
                // the bundle. Without it, "refused after a rotation" is equally well explained by a
                // rotation that refuses everybody.
                service!.ReplaceCertificates(new TlsCertificate { CertificatePath = serverCert, KeyPath = serverKey });

                Handshake kept = Connect(port, "resume-anchors.test", clientCert, clientKey);
                Assert.True(kept.Result == Outcome.Served,
                    $"a rotation that kept the anchors must keep serving this client: {kept.Detail}");
                Assert.True(kept.Body.Contains("alice"), $"the handler should still see CN=alice, got: {kept.Body}");

                // The issuer is gone; a stranger takes its place, so the file is still a usable set
                // of anchors and the only thing that changed is who may connect.
                File.WriteAllText(anchors, StrangerAnchorPem());
                service.ReplaceCertificates(new TlsCertificate { CertificatePath = serverCert, KeyPath = serverKey });

                Handshake revoked = Connect(port, "resume-anchors.test", clientCert, clientKey);

                // Vacuity guard: had the client come with nothing to offer, being turned away would
                // say nothing about tickets.
                Assert.True(revoked.OfferedPsk,
                    "the client held no ticket to offer, so this proves nothing about resumption");
                Assert.True(revoked.Result == Outcome.Refused,
                    "a client whose issuer was dropped at a rotation must be refused even holding a "
                    + $"ticket, or resumption outlives a revocation until that ticket expires: {revoked.Detail}");
            }
            finally
            {
                File.Delete(anchors);
            }
        });
    }

    /// <summary>A CA nobody has ever trusted, so the anchors can be replaced rather than emptied.</summary>
    private static string StrangerAnchorPem()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=stranger CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 ca = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        return ca.ExportCertificatePem();
    }

    // ----------------------------------------------------------------- driving one connection

    private enum Outcome
    {
        Served,
        Refused,
        TimedOut,
        Dropped,
    }

    /// <param name="OfferedPsk">The ClientHello carried a pre_shared_key: the client offered a ticket.</param>
    /// <param name="AcceptedPsk">The ServerHello carried one back: the server resumed from it.</param>
    /// <param name="Detail">What happened, for the failure message - the exception chain, or "served".</param>
    private readonly record struct Handshake(
        bool OfferedPsk, bool AcceptedPsk, Outcome Result, string Body, string Detail);

    /// <summary>
    /// One TLS connection, one request, and what the handshake was: full or resumed.
    /// </summary>
    /// <remarks>
    /// The request is not incidental. Two things need it: a TLS 1.3 server sends its session
    /// tickets after the handshake, so a client that never reads is never issued one and can never
    /// resume; and a server that refuses a resumption does so after the client believes it has
    /// finished, so the alert only surfaces on the next read. A helper that watched
    /// AuthenticateAsClient alone would report both as successes.
    /// </remarks>
    private static Handshake Connect(int port, string host, string? certPath, string? keyPath,
        int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        // Outside the try, because the ClientHello is the evidence that the client offered a ticket
        // and that is exactly what a REFUSED connection has to be able to prove.
        var wire = new Wiretap(client.GetStream());
        Outcome result;
        string body = "";
        string detail = "served";

        try
        {
            var certificates = new X509CertificateCollection();
            if (certPath is not null && keyPath is not null)
            {
                using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certPath, keyPath);

                // SslStream on Linux needs the key associated through a PFX round-trip, as the rest
                // of this suite's client-certificate paths do.
                certificates.Add(X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null));
            }

            using var ssl = new SslStream(wire, leaveInnerStreamOpen: false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = certificates,
            });

            ssl.Write(Encoding.ASCII.GetBytes($"GET /who HTTP/1.1\r\nHost: {host}\r\n\r\n"));
            ssl.Flush();

            (int status, body) = ReadResponse(ssl);
            result = status > 0 ? Outcome.Served : Outcome.Dropped;
            if (result == Outcome.Dropped)
            {
                detail = "the connection ended before a response";
            }
        }
        catch (Exception e)
        {
            // Classified rather than swallowed. A refusal is the peer saying no - an alert, or the
            // handshake failing - and NOT a timeout: a server that hangs has refused nothing.
            var chain = new List<string>();
            bool alert = false;
            bool timedOut = false;

            for (Exception? at = e; at is not null; at = at.InnerException)
            {
                chain.Add($"{at.GetType().Name}: {at.Message}");
                alert |= at is AuthenticationException
                    || at.Message.Contains("alert", StringComparison.OrdinalIgnoreCase);
                timedOut |= at is SocketException { SocketErrorCode: SocketError.TimedOut };
            }

            result = timedOut ? Outcome.TimedOut : alert ? Outcome.Refused : Outcome.Dropped;
            detail = string.Join(" <- ", chain);
        }

        return new Handshake(
            OfferedPsk: HasPreSharedKey(wire.Sent, clientHello: true),
            AcceptedPsk: HasPreSharedKey(wire.Received, clientHello: false),
            Result: result,
            Body: body,
            Detail: detail);
    }

    private static (int Status, string Body) ReadResponse(Stream stream)
    {
        var buffer = new byte[8192];
        int total = 0;

        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read <= 0)
            {
                break;
            }

            total += read;
            string text = Encoding.ASCII.GetString(buffer, 0, total);
            int head = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (head < 0)
            {
                continue;
            }

            int length = 0;
            foreach (string line in text[..head].Split("\r\n"))
            {
                if (line.StartsWith("content-length:", StringComparison.OrdinalIgnoreCase))
                {
                    length = int.Parse(line["content-length:".Length..].Trim());
                }
            }

            if (total >= head + 4 + length)
            {
                return (int.Parse(text.Split(' ')[1]), text.Substring(head + 4, length));
            }
        }

        return (0, "");
    }

    /// <summary>Keeps a copy of the handshake bytes in both directions, so they can be read after.</summary>
    private sealed class Wiretap(Stream inner) : Stream
    {
        // The hellos are the first thing on the wire in either direction; everything past them is
        // encrypted records nothing here can read anyway.
        private const int Cap = 32 * 1024;

        private readonly MemoryStream _sent = new();
        private readonly MemoryStream _received = new();

        public byte[] Sent => _sent.ToArray();
        public byte[] Received => _received.ToArray();

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = inner.Read(buffer, offset, count);
            if (read > 0 && _received.Length < Cap)
            {
                _received.Write(buffer, offset, read);
            }

            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_sent.Length < Cap)
            {
                _sent.Write(buffer, offset, count);
            }

            inner.Write(buffer, offset, count);
        }

        public override void Flush() => inner.Flush();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) => inner.Dispose();
    }

    // ----------------------------------------------------------------- reading the hellos

    private const int PreSharedKeyExtension = 41;   // RFC 8446 4.2.11
    private const byte HandshakeRecord = 0x16;
    private const byte ClientHelloMessage = 1;
    private const byte ServerHelloMessage = 2;

    /// <summary>
    /// Walks the plaintext record layer for a hello carrying pre_shared_key. On the client's side
    /// that is a ticket being offered; on the server's, the same ticket being used.
    /// </summary>
    /// <remarks>
    /// Records after the ServerHello are encrypted and are skipped by type, so this reads only what
    /// is genuinely in the clear. A HelloRetryRequest is a ServerHello too and never carries the
    /// extension, so scanning every one of them cannot invent an acceptance.
    /// </remarks>
    private static bool HasPreSharedKey(ReadOnlySpan<byte> bytes, bool clientHello)
    {
        byte wanted = clientHello ? ClientHelloMessage : ServerHelloMessage;
        int at = 0;

        while (at + 5 <= bytes.Length)
        {
            byte type = bytes[at];
            int recordLength = (bytes[at + 3] << 8) | bytes[at + 4];
            if (at + 5 + recordLength > bytes.Length)
            {
                break;   // only part of it was captured
            }

            ReadOnlySpan<byte> record = bytes.Slice(at + 5, recordLength);
            at += 5 + recordLength;

            if (type != HandshakeRecord)
            {
                continue;   // change_cipher_spec, or an encrypted record
            }

            int p = 0;
            while (p + 4 <= record.Length)
            {
                byte message = record[p];
                int messageLength = (record[p + 1] << 16) | (record[p + 2] << 8) | record[p + 3];
                if (p + 4 + messageLength > record.Length)
                {
                    break;
                }

                if (message == wanted && HelloOffersPsk(record.Slice(p + 4, messageLength), clientHello))
                {
                    return true;
                }

                p += 4 + messageLength;
            }
        }

        return false;
    }

    /// <summary>The extension list of one hello, walked to its end looking for pre_shared_key.</summary>
    private static bool HelloOffersPsk(ReadOnlySpan<byte> hello, bool clientHello)
    {
        int at = 2 + 32;   // legacy_version, random
        if (at >= hello.Length)
        {
            return false;
        }

        at += 1 + hello[at];   // legacy_session_id, echoed by the server

        if (clientHello)
        {
            if (at + 2 > hello.Length)
            {
                return false;
            }

            at += 2 + ((hello[at] << 8) | hello[at + 1]);   // cipher_suites
            if (at >= hello.Length)
            {
                return false;
            }

            at += 1 + hello[at];   // legacy_compression_methods
        }
        else
        {
            at += 2 + 1;   // the one cipher suite chosen, and legacy_compression_method
        }

        if (at + 2 > hello.Length)
        {
            return false;
        }

        int end = Math.Min(hello.Length, at + 2 + ((hello[at] << 8) | hello[at + 1]));
        at += 2;

        while (at + 4 <= end)
        {
            int extension = (hello[at] << 8) | hello[at + 1];
            if (extension == PreSharedKeyExtension)
            {
                return true;
            }

            at += 4 + ((hello[at + 2] << 8) | hello[at + 3]);
        }

        return false;
    }
}
