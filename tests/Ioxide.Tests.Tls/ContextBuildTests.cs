using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// Building an SSL_CTX: what is checked, what is silently accepted, and what leaks when a build
/// fails partway.
/// </summary>
/// <remarks>
/// The shape every entry here has in common is the one this module treats as the worst kind: a
/// configuration ACCEPTED when the service starts, which then does not do what it says. An empty
/// ciphersuite list, a typo'd suite name and a certificate whose key is of another algorithm were
/// each that, and each is now refused at startup with the offender named. These are the ones still
/// accepted, and each is written the way the fix should leave it - refused for a stated reason, or
/// actually working - so it turns green whichever of the two the fix chooses.
///
/// Driven with SslStream as the client, because what is worth asserting is that a real peer is or
/// is not served, not that ioxide called a setter.
/// </remarks>
internal static class ContextBuildTests
{
    /// <summary>
    /// A TLS 1.2 suite under the IANA name for it. OpenSSL KNOWS this name, which is the whole
    /// problem: <c>SSL_CTX_set_ciphersuites</c> looks names up by their IANA std name over the
    /// WHOLE cipher table, not over the TLS 1.3 suites, so it accepts this one and files it in a
    /// list only a 1.3 handshake ever reads - where a 1.2 cipher is then filtered back out.
    /// </summary>
    /// <remarks>
    /// Reachable by an ordinary route rather than an exotic one. RFC 8446 names the 1.3 suites in
    /// exactly this style (<c>TLS_AES_128_GCM_SHA256</c>), and every compliance list, IANA table,
    /// Wireshark capture and Java <c>SSLParameters</c> config spells the 1.2 ones the same way, so
    /// "the suites we are allowed to offer" copied from any of them looks like a valid list.
    /// OpenSSL's own short names (<c>ECDHE-RSA-AES128-GCM-SHA256</c>) are the ones that do not.
    /// </remarks>
    private const string Tls12SuiteName = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

    public static void Register(Runner runner)
    {
        runner.Pending("ctx: a CipherSuites name that is not a TLS 1.3 suite is refused, not accepted into a port that serves nobody", () =>
        {
            (string cert, string key) = TestCert.Ensure();

            // Nothing else is set: no floor, no kTLS. The default posture serves TLS 1.2 and 1.3,
            // and this is the whole of the operator's stated policy.
            Built alone = Build(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CipherSuites = Tls12SuiteName,
            });

            if (alone.Refusal is { } refusal)
            {
                Assert.True(refusal.Contains(Tls12SuiteName),
                    $"startup was refused, but not for the suite named: {refusal}");
            }
            else
            {
                // It started. Then it has to be able to serve SOMEONE. The per-name validation
                // loop passed every name here, the full list applied, and the context came out of
                // it with no usable suite at either version - which is the end state an EMPTY
                // CipherSuites is already refused for, reached through a name OpenSSL accepts.
                Assert.True(Handshakes(alone.Port, SslProtocols.Tls12 | SslProtocols.Tls13),
                    $"CipherSuites = '{Tls12SuiteName}' was accepted at startup and the port then "
                    + "refused every client at both versions (no ciphers available): a TLS 1.2 suite "
                    + "named the IANA way is accepted into the TLS 1.3 list and leaves it empty");
            }

            // The other spelling of the same mistake, and the one that does not announce itself:
            // a real 1.3 suite beside it. That port handshakes perfectly and offers ONE suite, not
            // the two configured - the silent narrowing that the typo'd-name refusal exists to
            // stop, arrived at through a name that passes the same check.
            Built beside = Build(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CipherSuites = $"TLS_AES_256_GCM_SHA384:{Tls12SuiteName}",
            });

            Assert.True(beside.Refusal is not null && beside.Refusal.Contains(Tls12SuiteName),
                $"'{Tls12SuiteName}' beside a real 1.3 suite was accepted and then silently dropped "
                + "from the list, which is what a one-character typo in a suite name is refused for");
        }, "found by review: SSL_CTX_set_ciphersuites resolves IANA std names over the whole cipher "
         + "table, so a TLS 1.2 suite name passes every check this module makes and disables the "
         + "TLS 1.3 list it lands in");

        runner.Test("ctx: control: a list of real TLS 1.3 suite names starts and the port serves it", () =>
        {
            // The guard on the refusal above: it must turn away a name that cannot be offered over
            // TLS 1.3, and nothing else. A check that refused every list, or one that read the
            // shape of the name rather than what OpenSSL does with it, would satisfy the Pending
            // above and break every server that states a suite list at all.
            (string cert, string key) = TestCert.Ensure();

            Built built = Build(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CipherSuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
            });

            Assert.True(built.Refusal is null, $"a list of real TLS 1.3 suites was refused: {built.Refusal}");
            Assert.True(Handshakes(built.Port, SslProtocols.Tls13), "the port did not serve a TLS 1.3 client");
        });

        runner.Test("ctx: a MinProtocolVersion outside the enum is refused, not read as the weaker floor", () =>
        {
            // No cast is needed to get here. Enum.Parse and the options binders accept ANY integer
            // for an enum - Enum.Parse<TlsProtocolVersion>("3") succeeds - so a config that carries
            // the floor as a number, or one written against a build where the enum has since grown
            // a member, arrives with a value the ternary in Configure has never heard of. It maps
            // everything that is not Tls13 to the TLS 1.2 floor, so the unknown value is resolved
            // to the WEAKEST posture the setting can express, silently.
            (string cert, string key) = TestCert.Ensure();

            Built built = Build(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                MinProtocolVersion = (TlsProtocolVersion)3,
            });

            if (built.Refusal is { } refusal)
            {
                Assert.True(refusal.Contains("MinProtocolVersion"),
                    $"startup was refused, but not for the version floor: {refusal}");
                return;
            }

            // It started. Whatever the caller meant by the value, they did not name Tls12 - and
            // whether TLS 1.2 is on offer is the one thing this setting decides.
            Assert.True(!Handshakes(built.Port, SslProtocols.Tls12),
                "a MinProtocolVersion that is not one of the enum's members was accepted and the "
                + "port then served a TLS 1.2 client: an unrecognised floor is resolved to the "
                + "weaker of the two rather than refused");
        });

        runner.Test("ctx: a negative HandshakeTimeoutMs is refused, not read as no sweep at all", () =>
        {
            // TlsOptions documents ONE value as disabling the sweep, and it is zero. Both guards
            // that read the setting test "> 0", so every negative value disables it too - the
            // ticker is never registered and no handshake is ever enqueued. What is lost is the
            // only bound on a peer that connects and then says nothing, which is the one part of a
            // TLS server reachable before anything has been authenticated.
            (string cert, string key) = TestCert.Ensure();

            Built built = Build(new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                HandshakeTimeoutMs = -1,
            });

            if (built.Refusal is { } refusal)
            {
                Assert.True(refusal.Contains("HandshakeTimeoutMs"),
                    $"startup was refused, but not for the timeout: {refusal}");
                return;
            }

            // It started, so the sweep it configured has to run. A deadline already in the past
            // means the first tick after the connection arrives is the one that closes it, so a
            // budget of seconds is a backstop and not a stopwatch.
            Assert.True(SilentPeerDropped(built.Port, 4_000),
                "HandshakeTimeoutMs = -1 was accepted and a peer that sent nothing was still held "
                + "4 s later: a negative value silently disables the sweep, which TlsOptions says "
                + "only zero does");
        });
    }

    /// <summary>What became of a configuration: the port it built, or why it was refused.</summary>
    /// <remarks>
    /// Both outcomes are legitimate answers here, which is why they are one value rather than a
    /// helper that asserts on either. The refusal carries its message so that a test asserting one
    /// can assert on the REASON - a port already held, or a reactor that died on the way up, would
    /// otherwise read as the refusal being asked for.
    /// </remarks>
    private readonly record struct Built(int Port, string? Refusal);

    private static Built Build(TlsOptions options)
    {
        try
        {
            return new Built(TestServer.Start(Handlers.Tls, r => TlsService.Start(r, options)), null);
        }
        catch (Exception e)
        {
            return new Built(0, e.Message);
        }
    }

    /// <summary>
    /// Whether the handshake completed. A refusal is false; a server that HANGS throws, so a test
    /// asserting a client was turned away cannot be satisfied by one that answers nobody at all.
    /// </summary>
    private static bool Handshakes(int port, SslProtocols protocols)
    {
        using var sock = new TcpClient();
        sock.Connect("127.0.0.1", port);
        sock.ReceiveTimeout = 6_000;
        sock.SendTimeout = 6_000;

        using var ssl = new SslStream(sock.GetStream(), false, (_, _, _, _) => true);

        try
        {
            ssl.AuthenticateAsClient("localhost", null, protocols, false);
            return true;
        }
        catch (AuthenticationException)
        {
            return false;   // an alert: declined, which is what these tests mean by refused
        }
        catch (IOException e) when (TimedOut(e))
        {
            throw new Exception(
                $"the server on :{port} neither completed nor refused a handshake within 6 s - a "
                + "hang is not a refusal, and this assertion would have read it as one.", e);
        }
        catch (IOException)
        {
            return false;   // closed without an alert: rude, but still declined
        }
    }

    /// <summary>
    /// Whether the server gave up on a peer that connects and sends nothing, inside
    /// <paramref name="budgetMs"/>. False means the connection was still open at the end of it.
    /// </summary>
    private static bool SilentPeerDropped(int port, int budgetMs)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = budgetMs;

        // Not one byte of ClientHello ever goes out.
        try
        {
            return client.GetStream().Read(new byte[16], 0, 16) == 0;   // FIN: the server let go
        }
        catch (IOException e) when (TimedOut(e))
        {
            return false;   // the CLIENT gave up first, so the server is still holding it
        }
        catch (IOException)
        {
            return true;    // a reset rather than an orderly close - still the server giving up
        }
    }

    private static bool TimedOut(Exception e)
    {
        for (Exception? at = e; at is not null; at = at.InnerException)
        {
            if (at is SocketException { SocketErrorCode: SocketError.TimedOut })
            {
                return true;
            }
        }

        return false;
    }
}
