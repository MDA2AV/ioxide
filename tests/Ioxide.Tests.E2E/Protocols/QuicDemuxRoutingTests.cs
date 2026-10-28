using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// What the demux will accept as a routable connection id, before any of QUIC exists.
///
/// The route table is keyed by the DCID the client puts in its long header, and a key that lands
/// there decides which connection every later packet carrying it is fed into. That makes the
/// question "which connection ids may install a route" a transport-safety question, not a parsing
/// one - it is answered in <c>Reactor.QuicDispatchDatagram</c>, above ngtcp2 and above both HTTP/3
/// stacks.
///
/// The apparatus is <see cref="RawInitial"/>, shared with <see cref="QuicSniHostileTests"/>: a real
/// encrypted Initial carrying a real ClientHello, so the server either answers it or does not, and
/// no instrumentation is needed to tell which.
/// </summary>
internal static class QuicDemuxRoutingTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic/demux: a zero-length connection id does not become a routable connection", () =>
        {
            // A zero-length DCID is legal on the wire - a peer that does not need to be addressed
            // by connection id sends one - but it can never legitimately address THIS server:
            // QuicEngine enforces cidLength 1..20, so ioxide never mints one, and nothing it issued
            // can be empty. The demux accepts it anyway (TryExtractDcid takes packet[5] == 0 and
            // returns an empty QuicCid, which is a perfectly good dictionary key), and installs it
            // as a route like any other.
            //
            // ngtcp2 does not stop it either. ngtcp2_accept refuses a short DCID only when the
            // packet carries NO token:
            //
            //     if (pktlen < NGTCP2_MAX_UDP_PAYLOAD_SIZE ||
            //         (p->tokenlen == 0 && p->dcid.datalen < NGTCP2_MIN_INITIAL_DCIDLEN))
            //
            // so one junk token byte - which this server never issued and never checks, because it
            // has no Retry path - is enough to walk a zero-length DCID straight through.
            //
            // What that costs: the empty CID is one key, so every later zero-DCID long header from
            // ANY peer routes to whichever connection claimed it first. Initial keys are derived
            // from the client's original DCID, and a second peer sending an empty one derives the
            // same keys - so this is not merely a misdelivery, it is two peers on one connection
            // state, with replies going to whichever address arrived first.
            int udpPort = Serve();

            using var raw = new RawInitial(udpPort, dcidLength: 0, tokenLength: 1);
            RawInitial.Reply reply = raw.Exchange(QuicSniHostileTests.Hello(raw, [("alpha.test", 0)]));

            Assert.True(!reply.SawServerHello,
                "an Initial addressed to a zero-length connection id was answered with a ServerHello, " +
                "so it installed a route: nothing ioxide issues can be empty, so no later packet " +
                $"carrying that id belongs to anyone. The server {QuicSniHostileTests.Describe(reply)}");
        });

        runner.Test("control: the same Initial with an ordinary connection id is answered", () =>
        {
            // Without this the test above is satisfied by a packet the server rejected for some
            // unrelated reason - a bad token, a malformed hello, a length it did not like. This is
            // byte-for-byte the same construction and the same junk token, differing only in the
            // length of the connection id, and it must be served.
            int udpPort = Serve();

            using var raw = new RawInitial(udpPort, dcidLength: 8, tokenLength: 1);
            RawInitial.Reply reply = raw.Exchange(QuicSniHostileTests.Hello(raw, [("alpha.test", 0)]));

            Assert.True(reply.SawServerHello,
                "the control Initial was not answered, so the zero-length case above proves nothing: " +
                $"the server {QuicSniHostileTests.Describe(reply)}");
        });
    }

    private static int Serve()
    {
        (string cert, string key) = TestCert.Ensure();
        (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");

        var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
        engine.AddHost("alpha.test", alphaCert, alphaKey);

        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static _ => new Nghttp3Response { Body = "ok"u8.ToArray() }));

        return udpPort;
    }
}
