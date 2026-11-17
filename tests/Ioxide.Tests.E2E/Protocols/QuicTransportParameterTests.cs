namespace Ioxide.Tests;

/// <summary>
/// The quic_transport_parameters extension a ClientHello must carry (RFC 9001 8.2): a hello without
/// it, or with only the draft codepoint, is refused with missing_extension, and the server it was
/// sent to goes on serving.
/// </summary>
/// <remarks>
/// The hellos are built by hand (<see cref="RawInitial"/>, <see cref="QuicSniHostileTests.Hello"/>),
/// because no client in this tree can leave the extension out. ngtcp2's picotls glue accepts such a
/// hello, so before the shim refused it the handshake went on without the client's transport
/// parameters, the server never learned its negotiated version, and its first 1-RTT packet aborted
/// the process on ngtcp2's assert(conn->negotiated_version) - this test host included.
///
/// Each refusal is followed by a well-formed hello to the same server, so a server that is gone, or
/// that refuses everything, fails the test rather than passing it.
/// </remarks>
internal static class QuicTransportParameterTests
{
    public static void Register(Runner runner)
    {
        foreach ((string label, QuicSniHostileTests.TransportParameters carried) in new[]
                 {
                     ("without quic_transport_parameters", QuicSniHostileTests.TransportParameters.None),
                     ("with only the draft quic_transport_parameters (0xffa5)", QuicSniHostileTests.TransportParameters.DraftOnly),
                 })
        {
            QuicSniHostileTests.TransportParameters transportParameters = carried;
            runner.Test($"quic: a ClientHello {label} is refused, and the server goes on serving", () =>
            {
                int udpPort = QuicSniHostileTests.Serve(QuicSniHostileTests.NewEngine());

                RawInitial.Reply refused;
                using (var raw = new RawInitial(udpPort))
                {
                    refused = raw.Exchange(QuicSniHostileTests.Hello(raw, [("alpha.test", 0)],
                        transportParameters: transportParameters));
                }

                Assert.True(refused.Closed && !refused.SawServerHello
                            && refused.CloseError == QuicSniHostileTests.CryptoError(QuicSniHostileTests.Alert.MissingExtension),
                    $"a ClientHello {label} must be refused with missing_extension, CRYPTO_ERROR 0x16d (RFC 9001 8.2); " +
                    $"instead the server {QuicSniHostileTests.Describe(refused)}");

                using var control = new RawInitial(udpPort);
                RawInitial.Reply answered = control.Exchange(QuicSniHostileTests.Hello(control, [("alpha.test", 0)]));

                Assert.True(answered.SawServerHello && !answered.Closed,
                    $"after refusing a ClientHello {label}, the same server should still answer a " +
                    $"well-formed one with a ServerHello; it {QuicSniHostileTests.Describe(answered)}");
            });
        }

        runner.Test("quic: a ClientHello offering no ALPN the server serves is refused with no_application_protocol", () =>
        {
            // RFC 9001 8.1. The alert is the shim's own choice (iq_on_client_hello), and the close carries it.
            int udpPort = QuicSniHostileTests.Serve(QuicSniHostileTests.NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply refused = raw.Exchange(QuicSniHostileTests.Hello(raw, [("alpha.test", 0)], alpn: "h2"));

            Assert.True(refused.Closed && !refused.SawServerHello
                        && refused.CloseError == QuicSniHostileTests.CryptoError(QuicSniHostileTests.Alert.NoApplicationProtocol),
                $"a ClientHello offering only h2 to an h3 server must be refused with no_application_protocol, " +
                $"CRYPTO_ERROR 0x178; instead the server {QuicSniHostileTests.Describe(refused)}");
        });
    }
}
