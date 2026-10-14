using ioxide;
using ioxide.ngtcp2;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// One option, both stacks. Where TCP and QUIC are documented as equivalent and are not.
/// </summary>
/// <remarks>
/// The two TLS terminations are deliberately separate - BoringSSL under <c>ioxide.tls</c>, picotls
/// under <c>ioxide.ngtcp2</c> - and there is a standing rule against a shared base class, so
/// nothing here argues for unifying them. What it looks for is narrower and worse: an option
/// spelled the same on both, described the same on both, that a deployment can set once and get
/// two different behaviours from. That is what makes a configuration reviewed on one port and
/// unsafe on the other.
///
/// This suite references both stacks, which is why the comparison lives here rather than in
/// <c>Ioxide.Tests.Tls</c> (TCP only) or <c>Ioxide.Tests.E2E</c> (QUIC only). Each stack's own
/// behaviour is covered in its own suite; these tests only ever assert that the two AGREE.
/// </remarks>
internal static class CrossStackParityTests
{
    public static void Register(Runner runner)
    {
        runner.Test("rotate/parity: omitting the host table is refused on QUIC and applied on TCP - a known divergence",
        () =>
        {
            // Both stacks expose the same operation under the same name, with the same shape, for
            // the same reason - an ACME client rewrote the PEM and restarting would be an outage:
            //
            //     TlsService.ReplaceCertificates(TlsCertificate,  IReadOnlyDictionary<..>? = null)
            //     QuicEngine .ReplaceCertificates(QuicCertificate, IReadOnlyDictionary<..>? = null)
            //
            // The renewal hook anyone writes passes the first argument and stops there, because the
            // certificate is what expired. On QUIC that call is refused. On TCP it is applied, and
            // applying it REPLACES THE WHOLE TABLE with nothing: every registered name is answered
            // by the default certificate from the next handshake on, with no exception and no log
            // line. The two stacks give the argument's DEFAULT VALUE opposite meanings.
            (string cert, string key) = TestCert.Ensure();
            (string alpha, string alphaKey) = TestCert.EnsureNamed("alpha.test");

            // ---- QUIC, the stack that already decided this. Also the guard against a vacuous run:
            // if the native engine could not load, or the fixtures were wrong, neither of these two
            // would behave as stated and the failure below would mean nothing.
            using (var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]))
            {
                engine.AddHost("named.test", alpha, alphaKey);

                Assert.Throws<ArgumentNullException>(
                    () => engine.ReplaceCertificates(new QuicCertificate(cert, key)),
                    "named host");

                // And the refusal is about the OMISSION, not about rotating a named engine at all:
                // saying "no names" out loud is accepted. Without this the assertion above would
                // also be satisfied by an engine that refused every rotation it was given.
                engine.ReplaceCertificates(new QuicCertificate(cert, key),
                    new Dictionary<string, QuicCertificate>());
            }

            // ---- TCP, driven through a real server so the table under test is one that is
            // actually being served rather than one that was merely built.
            TlsService? service = null;
            int port = TestServer.Start(Handlers.TlsSendFirst, r => service = TlsService.Start(r, new TlsOptions
            {
                CertificatePath = cert,
                KeyPath = key,
                CertificatesByHost = new Dictionary<string, TlsCertificate>
                {
                    ["named.test"] = new() { CertificatePath = alpha, KeyPath = alphaKey },
                },
            }));

            // The name has to be live before the rotation, or "the rotation dropped it" is a claim
            // about a table that never answered for anything.
            Assert.True(Client.ServerCertificateSubject(port, "named.test").Contains("alpha.test"),
                "the name should start on its own certificate");
            Assert.True(service!.ServerNames.Count == 1, "and should start being reported");

            // The divergence, pinned rather than asserted away. Same method name, same omission,
            // same default argument - and the two stacks answer differently. QUIC refuses (above);
            // TCP APPLIES it, and from here 'named.test' is served CN=localhost.
            //
            // Neither side is a bug on its own. TCP's behaviour is documented on the parameter ("or
            // null for none") and pinned by a passing test - RotationTests, "a name can be dropped
            // from a running service" - so the two cannot both be satisfied: raising TCP to QUIC's
            // contract is a deliberate breaking change that deletes that test, and it is a decision
            // rather than a fix. What this records is that the divergence EXISTS, so that whichever
            // way it is resolved, this test has to be rewritten and nobody resolves it by accident.
            service.ReplaceCertificates(new TlsCertificate { CertificatePath = cert, KeyPath = key });

            Assert.True(Client.ServerCertificateSubject(port, "named.test").Contains("localhost"),
                "TCP applies an omitted table: the name should fall back to the default certificate");
            Assert.True(service.ServerNames.Count == 0,
                "and the name should no longer be reported as served");

            // And on TCP too, stating the empty table must remain the way to ask for the drop.
            service.ReplaceCertificates(
                new TlsCertificate { CertificatePath = cert, KeyPath = key },
                new Dictionary<string, TlsCertificate>());

            Assert.True(Client.ServerCertificateSubject(port, "named.test").Contains("localhost"),
                "with the table emptied on purpose, the name falls back to the default certificate");
        });
    }
}
