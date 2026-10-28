using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ioxide;
using ioxide.nghttp3;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// SNI as a hostile client can shape it: repeated extensions, a second ClientHello after a
/// HelloRetryRequest, and names that are legal but odd.
/// </summary>
/// <remarks>
/// Every test here drives the server with a hand-built ClientHello rather than with the in-tree
/// client, because no client in this tree can send the shapes under test - and the shim's defence
/// against them (<c>iq_count_host_names</c>, a hand-written TLS parser walking attacker-controlled
/// bytes) was therefore never once executed by the suite.
///
/// <see cref="RawInitial"/> is what makes that possible: it encrypts one QUIC Initial packet with
/// keys derived from the destination connection ID, so the ClientHello inside it is whatever bytes
/// this file says it is, and it decrypts the server's Initial packets back - which is enough to see
/// a ServerHello, a HelloRetryRequest, or a CONNECTION_CLOSE. It deliberately stops there: reading
/// the certificate would need the handshake keys, and nothing here has to.
///
/// Each refusal is paired with a control that differs in ONE field, so "the server refused" cannot
/// be satisfied by a hello this file simply got wrong. That pairing is also what stands in for
/// breaking the thing under test: nothing here can edit the shim, so what makes the two-name
/// refusal mean something is that the same hello with one host_name - and the same hello whose
/// second list entry is of another name_type - are both served by the same server.
///
/// No test asserts WHICH alert was sent, because the shim cannot carry one: it closes with
/// ngtcp2_ccerr_set_liberr(NGTCP2_ERR_CRYPTO), which infers PROTOCOL_VIOLATION, so every TLS alert
/// this server raises reaches the peer as the same code. What is asserted is the branch taken -
/// closed, retried, or answered - which is the part the alert would only have annotated.
/// </remarks>
internal static class QuicSniHostileTests
{
    public static void Register(Runner runner)
    {
        RegisterServerNameList(runner);
        RegisterSecondHello(runner);
    }

    // ---- the ServerNameList a client can repeat -----------------------------------------------

    private static void RegisterServerNameList(Runner runner)
    {
        runner.Test("sni/quic: a ClientHello listing two host names is refused", () =>
        {
            // RFC 6066 3.1 allows at most one name of a given type, and picotls does not enforce it
            // - client_hello_decode_server_name loops the list and overwrites, so the LAST name
            // wins. Anything in front reading the FIRST (an SNI router, an ACL) would then have
            // been looking at a different host than the one this server answered for. The shim
            // counts the entries itself and refuses; this is the only thing that ever runs that
            // counter, and the parser behind it.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply reply = raw.Exchange(Hello(raw, [("alpha.test", 0), ("beta.test", 0)]));

            Assert.True(reply.Closed,
                "a ClientHello carrying two host_name entries must be refused, and the peer told so; " +
                $"instead the server {Describe(reply)}");
            Assert.True(!reply.SawServerHello,
                "a ClientHello carrying two host_name entries was answered with a ServerHello - the " +
                "server picked one of the two names and carried on");
        });

        runner.Test("control: the same ClientHello listing one host name is answered", () =>
        {
            // The control that makes the test above mean something. Byte-for-byte the same hello
            // apart from the second entry in the ServerNameList: same cipher suites, same groups,
            // same key share, same ALPN, same transport parameters. If this one is refused too then
            // the refusal above says nothing about the second name.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply reply = raw.Exchange(Hello(raw, [("alpha.test", 0)]));

            Assert.True(reply.SawServerHello,
                $"a well-formed hand-built ClientHello should be answered with a ServerHello; the server {Describe(reply)}");
            Assert.True(!reply.Closed, $"the control hello was refused: {Describe(reply)}");
        });

        runner.Test("sni/quic: a second entry of another name_type is not a second host name", () =>
        {
            // The other side of the counter: it counts host_name(0) entries, not list entries. An
            // entry of some other type sits in the list without being a name anybody could have
            // routed on, so the hello stays legal and must still be served. A counter written as
            // "more than one entry" instead of "more than one host_name" fails here.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply reply = raw.Exchange(Hello(raw, [("alpha.test", 0), ("beta.test", 7)]));

            Assert.True(reply.SawServerHello,
                $"one host_name plus one entry of another type is one host name; the server {Describe(reply)}");
        });

        runner.Test("sni/quic: a host name with an embedded NUL is refused", () =>
        {
            // "alpha.test\0evil.test" is one host_name as far as the counter is concerned, so the
            // shim lets it through - and everything downstream that treats a name as a C string
            // would read alpha.test. picotls rejects it before any of that (illegal_parameter).
            // Pinned here because the counter is what decides whether this ever reaches picotls.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply reply = raw.Exchange(Hello(raw, [("alpha.test\0evil.test", 0)]));

            Assert.True(reply.Closed && !reply.SawServerHello,
                $"a host name containing a NUL must not start a handshake; the server {Describe(reply)}");
        });

        runner.Test("sni/quic: an empty host name is refused", () =>
        {
            // A zero-length host_name is not a name. The counter counts it (name_type is 0), the
            // hello has exactly one, so the shim allows it and picotls is what refuses. Worth
            // pinning for the same reason as the NUL: it is a path THROUGH the counter.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply reply = raw.Exchange(Hello(raw, [("", 0)]));

            Assert.True(reply.Closed && !reply.SawServerHello,
                $"an empty host_name must not start a handshake; the server {Describe(reply)}");
        });

        runner.Test("sni/quic: a ClientHello with no server_name extension is served", () =>
        {
            // The counter returns 0 for an absent extension and the caller must change nothing:
            // a hello with no name is legal and gets the default certificate. This is the case a
            // counter that reported "cannot parse" as a violation would break, and it is also the
            // shape every non-SNI client sends.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);
            RawInitial.Reply reply = raw.Exchange(Hello(raw, []));

            Assert.True(reply.SawServerHello,
                $"a hello with no server_name extension must still be served; the server {Describe(reply)}");
        });
    }

    // ---- the ClientHello that comes after a HelloRetryRequest ---------------------------------

    private static void RegisterSecondHello(Runner runner)
    {
        runner.Test("sni/quic: a second ClientHello naming a different host is refused", () =>
        {
            // on_client_hello runs for the FIRST ClientHello only (picotls guards the call with
            // !is_second_flight), so the host selected there is the one whose certificate is
            // served. picotls has a guard for exactly this - it compares CH2's server_name with
            // CH1's and fails the handshake on a mismatch - but the comparison is gated on
            // tls->server_name, which only ptls_set_server_name sets, so it runs only because the
            // shim's callback saves the name.
            //
            // The client controls whether a second hello happens at all: offering an empty
            // key_share list forces a HelloRetryRequest, and the retry is the invitation to send
            // CH2. RFC 8446 4.1.2 lets a client change only a listed set of fields between the two
            // and requires the server to abort otherwise; server_name is not in that set.
            //
            // Asserted at the Initial level: under the defect the server answers CH2 with a real
            // ServerHello, under the guard it would answer with a CONNECTION_CLOSE. The certificate
            // itself rides in Handshake packets this file cannot read, but which one it is follows
            // from CH1 being the only hello the callback ever saw.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);

            RawInitial.Reply first = raw.Exchange(Hello(raw, [("alpha.test", 0)], withKeyShare: false));
            Assert.True(first.SawHelloRetryRequest,
                $"a hello offering no key share should draw a HelloRetryRequest; the server {Describe(first)}");

            RawInitial.Reply second = raw.Exchange(Hello(raw, [("beta.test", 0)]));

            Assert.True(second.Closed && !second.SawServerHello,
                "the second ClientHello asked for beta.test where the first asked for alpha.test, and " +
                "the certificate was already chosen from the first - the server should have refused " +
                $"the change instead of continuing; it {Describe(second)}");
        });

        runner.Test("control: a second ClientHello keeping the name continues the handshake", () =>
        {
            // The control for the test above, and the thing that stops it from passing for
            // the wrong reason. Same retry, same two flights, same everything - only CH2 keeps
            // alpha.test. A ServerHello here proves the retry rig is correct and that a mismatched
            // name is the ONLY difference between the two cases.
            int udpPort = Serve(NewEngine());

            using var raw = new RawInitial(udpPort);

            RawInitial.Reply first = raw.Exchange(Hello(raw, [("alpha.test", 0)], withKeyShare: false));
            Assert.True(first.SawHelloRetryRequest,
                $"a hello offering no key share should draw a HelloRetryRequest; the server {Describe(first)}");

            RawInitial.Reply second = raw.Exchange(Hello(raw, [("alpha.test", 0)]));

            Assert.True(second.SawServerHello,
                $"a second hello that changed nothing but the key share should be accepted; the server {Describe(second)}");
            Assert.True(!second.Closed, $"the control second hello was refused: {Describe(second)}");
        });
    }

    // ---- fixtures -----------------------------------------------------------------------------

    /// <summary>Default localhost certificate, plus alpha.test and beta.test by name - the same
    /// shape <see cref="QuicSniTests"/> uses, so a name here is one the engine really holds.</summary>
    private static QuicEngine NewEngine()
    {
        (string cert, string key) = TestCert.Ensure();
        (string alphaCert, string alphaKey) = TestCert.EnsureNamed("alpha.test");
        (string betaCert, string betaKey) = TestCert.EnsureNamed("beta.test");

        var engine = new QuicEngine(cert, key, cidLength: 8, alpn: ["h3"]);
        engine.AddHost("alpha.test", alphaCert, alphaKey);
        engine.AddHost("beta.test", betaCert, betaKey);
        return engine;
    }

    private static int Serve(QuicEngine engine)
    {
        // The engine outlives the test body only as far as the reactor does; Runner stops every
        // test server when the test ends, and nothing here ever completes a handshake anyway.
        (_, int udpPort) = TestServer.StartDatagram(
            onDatagram: null,
            quicFactory: engine.CreateFactory(),
            quicHandle: static (_, conn) => new Nghttp3Connection(conn).RunAsync(
                static _ => new Nghttp3Response { Body = "ok"u8.ToArray() }));

        return udpPort;
    }

    /// <summary>
    /// One ClientHello, differing from the next only in its ServerNameList. Everything else - the
    /// cipher suite, the groups, the signature algorithms, the ALPN, the QUIC transport parameters
    /// - is fixed, which is what lets a pair of these be a test and its control.
    /// </summary>
    /// <param name="names">(name, name_type) pairs for the server_name extension; empty omits it.</param>
    /// <param name="withKeyShare">false sends an EMPTY client_shares list, which is what forces the
    /// server to answer with a HelloRetryRequest instead of a ServerHello.</param>
    internal static byte[] Hello(RawInitial raw, (string Name, byte Type)[] names, bool withKeyShare = true)
    {
        var b = new Buf();
        b.U8(0x01);                                   // client_hello
        int msg = b.Mark(3);
        b.U16(0x0303);                                // legacy_version
        b.Raw(raw.ClientRandom);                      // the SAME random across a retry pair
        b.U8(0);                                      // legacy_session_id: empty (RFC 9001 8.4)
        b.U16(2).U16(0x1301);                         // TLS_AES_128_GCM_SHA256
        b.U8(1).U8(0);                                // legacy_compression_methods: null
        int exts = b.Mark(2);

        if (names.Length > 0)
        {
            b.U16(0x0000);                            // server_name
            int ext = b.Mark(2);
            int list = b.Mark(2);
            foreach ((string name, byte type) in names)
            {
                byte[] raw8 = Encoding.UTF8.GetBytes(name);
                b.U8(type).U16(raw8.Length).Raw(raw8);
            }
            b.Fill(list, 2);
            b.Fill(ext, 2);
        }

        b.U16(0x000a);                                // supported_groups
        int g = b.Mark(2);
        b.U16(2).U16(0x0017);                         // secp256r1 only, so a retry can only ask for it
        b.Fill(g, 2);

        b.U16(0x000d);                                // signature_algorithms
        int s = b.Mark(2);
        b.U16(8).U16(0x0804).U16(0x0403).U16(0x0805).U16(0x0401);
        b.Fill(s, 2);

        b.U16(0x0010);                                // application_layer_protocol_negotiation
        int a = b.Mark(2);
        int alist = b.Mark(2);
        b.U8(2).Raw("h3"u8);
        b.Fill(alist, 2);
        b.Fill(a, 2);

        b.U16(0x0033);                                // key_share
        int k = b.Mark(2);
        int shares = b.Mark(2);
        if (withKeyShare)
        {
            b.U16(0x0017).U16(raw.KeyShare.Length).Raw(raw.KeyShare);
        }
        b.Fill(shares, 2);
        b.Fill(k, 2);

        b.U16(0x002b);                                // supported_versions
        int v = b.Mark(2);
        b.U8(2).U16(0x0304);
        b.Fill(v, 2);

        b.U16(0x0039);                                // quic_transport_parameters (v1)
        int tp = b.Mark(2);
        b.U8(0x0f).U8(raw.Scid.Length).Raw(raw.Scid);            // initial_source_connection_id
        b.U8(0x04).U8(4).Raw([0x80, 0x10, 0x00, 0x00]);          // initial_max_data
        b.U8(0x05).U8(4).Raw([0x80, 0x01, 0x00, 0x00]);          // initial_max_stream_data_bidi_local
        b.U8(0x06).U8(4).Raw([0x80, 0x01, 0x00, 0x00]);          // ...bidi_remote
        b.U8(0x07).U8(4).Raw([0x80, 0x01, 0x00, 0x00]);          // ...uni
        b.U8(0x08).U8(1).U8(0x10);                               // initial_max_streams_bidi
        b.U8(0x09).U8(1).U8(0x10);                               // initial_max_streams_uni
        b.Fill(tp, 2);

        b.Fill(exts, 2);
        b.Fill(msg, 3);
        return b.ToArray();
    }

    /// <summary>What the server actually did, for a failure message that names it.</summary>
    internal static string Describe(RawInitial.Reply r)
    {
        if (r.Datagrams == 0)
        {
            return "said nothing at all";
        }
        var parts = new List<string>();
        if (r.SawHelloRetryRequest) parts.Add("sent a HelloRetryRequest");
        if (r.SawServerHello) parts.Add("sent a ServerHello");
        if (r.Closed) parts.Add($"closed with 0x{r.CloseError:x}" + (r.CloseReason.Length > 0 ? $" ({r.CloseReason})" : ""));
        if (parts.Count == 0) parts.Add($"answered {r.Datagrams} datagram(s) with nothing this reads");
        return string.Join(" and ", parts);
    }

    /// <summary>Length-prefixed byte builder: Mark reserves a length field, Fill backfills it.</summary>
    private sealed class Buf
    {
        private readonly List<byte> _b = [];

        public Buf U8(int v) { _b.Add((byte)v); return this; }
        public Buf U16(int v) { _b.Add((byte)(v >> 8)); _b.Add((byte)v); return this; }
        public Buf Raw(ReadOnlySpan<byte> s) { foreach (byte x in s) _b.Add(x); return this; }

        /// <summary>Reserve a big-endian length field of <paramref name="width"/> bytes.</summary>
        public int Mark(int width)
        {
            for (int i = 0; i < width; i++) _b.Add(0);
            return _b.Count;
        }

        /// <summary>Write the bytes written since <paramref name="mark"/> into its length field.</summary>
        public void Fill(int mark, int width)
        {
            int len = _b.Count - mark;
            for (int i = 0; i < width; i++)
            {
                _b[mark - width + i] = (byte)(len >> (8 * (width - 1 - i)));
            }
        }

        public byte[] ToArray() => [.. _b];
    }
}

/// <summary>
/// A QUIC client that only knows the Initial packet number space: it puts a caller-supplied
/// ClientHello into an Initial packet, protects it with the keys RFC 9001 derives from the
/// destination connection ID, and decrypts the Initial packets that come back.
/// </summary>
/// <remarks>
/// Everything above the Initial space is deliberately absent. That space is enough to see whether a
/// hello was accepted (ServerHello), retried (HelloRetryRequest) or refused (CONNECTION_CLOSE),
/// and reading further would mean running the whole key schedule to get the handshake keys.
///
/// It is a hostile client, not a correct one: it never completes a handshake, its packet numbers
/// only go up, and it acknowledges the server's Initial packets and nothing else.
/// </remarks>
internal sealed class RawInitial : IDisposable
{
    // RFC 9001 5.2, QUIC v1.
    private static readonly byte[] InitialSalt =
    [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    // RFC 8446 4.1.3: the fixed Random a HelloRetryRequest carries in place of a real one.
    private static readonly byte[] HelloRetryRandom =
    [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    ];

    private readonly Socket _sock;
    private readonly byte[] _odcid;      // the DCID of the first Initial: what the keys come from
    private readonly Keys _tx;
    private readonly Keys _rx;
    private readonly ECDiffieHellman _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    private byte[] _dcid;                // what goes in the header; the server renames it once
    private readonly byte[] _token;      // address-validation token, empty unless a test asks for one
    private uint _pn;
    private long _ackLargest = -1;
    private int _txCryptoOff;            // where the next hello sits in the client's CRYPTO stream

    // One stream for the whole connection, not one per exchange: after a HelloRetryRequest the
    // ServerHello continues the SAME Initial-space CRYPTO stream, at the offset where the retry
    // ended. Reassembling per exchange would leave that ServerHello sitting behind a hole and
    // report the second flight as unreadable - which is exactly how this file first read it.
    private readonly CryptoStream _crypto = new();

    /// <summary>The connection ID this client asks to be addressed by - also its
    /// initial_source_connection_id, which ngtcp2 checks against the packet header.</summary>
    public byte[] Scid { get; } = RandomNumberGenerator.GetBytes(8);

    /// <summary>The ClientHello Random. Constant for the life of this client: picotls requires
    /// CH2 to repeat CH1's random byte for byte.</summary>
    public byte[] ClientRandom { get; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>An uncompressed secp256r1 point, so the server's key exchange has something real to
    /// work with. Nothing here ever uses the shared secret.</summary>
    public byte[] KeyShare { get; }

    /// <param name="dcidLength">
    /// Bytes in the connection ID this client addresses the server by. 16 is what a real client
    /// sends. ZERO is legal on the wire and is what the demux tests use: the Initial keys are
    /// derived from this value, so an empty one derives keys any other peer can derive too.
    /// </param>
    /// <param name="tokenLength">
    /// Bytes of address-validation token to carry. A server that never issued one has nothing to
    /// check it against - but ngtcp2_accept skips its minimum-DCID guard whenever a token is
    /// present, so carrying one is how a short DCID gets past it.
    /// </param>
    public RawInitial(int serverPort, int dcidLength = 16, int tokenLength = 0)
    {
        ECParameters p = _ecdh.ExportParameters(false);
        KeyShare = [0x04, .. p.Q.X!, .. p.Q.Y!];

        _odcid = dcidLength == 0 ? [] : RandomNumberGenerator.GetBytes(dcidLength);
        _dcid = _odcid;
        _token = tokenLength == 0 ? [] : RandomNumberGenerator.GetBytes(tokenLength);

        byte[] initial = HKDF.Extract(HashAlgorithmName.SHA256, _odcid, InitialSalt);
        _tx = Keys.From(ExpandLabel(initial, "client in", 32));
        _rx = Keys.From(ExpandLabel(initial, "server in", 32));

        _sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _sock.Connect(new IPEndPoint(IPAddress.Loopback, serverPort));
        _sock.ReceiveTimeout = 250;
    }

    /// <summary>What the server said back, as far as the Initial packet number space shows it.</summary>
    internal sealed class Reply
    {
        public int Datagrams;
        public bool Closed;
        public ulong CloseError;
        public string CloseReason = "";
        public bool SawServerHello;
        public bool SawHelloRetryRequest;
    }

    /// <summary>
    /// Send one ClientHello and collect what comes back, stopping as soon as the answer is
    /// unambiguous. The deadline is a backstop, not a measurement: a slower box takes longer to
    /// answer and still answers the same thing.
    /// </summary>
    public Reply Exchange(byte[] clientHello, int timeoutMs = 5_000)
    {
        Send(clientHello);

        var reply = new Reply();
        long deadline = Environment.TickCount64 + timeoutMs;
        byte[] buf = new byte[2048];

        while (Environment.TickCount64 < deadline)
        {
            int n;
            try
            {
                n = _sock.Receive(buf);
            }
            catch (SocketException)
            {
                continue;   // no datagram within the socket's own timeout; the deadline decides
            }

            reply.Datagrams++;

            // A datagram can coalesce several packets; only the Initial ones are readable here.
            int off = 0;
            while (off < n && TryOpen(buf.AsSpan(off, n - off), out byte[] payload, out int consumed))
            {
                Ingest(payload, reply, _crypto);
                off += consumed;
            }

            foreach ((byte type, byte[] body) in _crypto.TakeNew())
            {
                if (type != 0x02 || body.Length < 34)
                {
                    continue;   // only ServerHello lives in the Initial space
                }
                if (body.AsSpan(2, 32).SequenceEqual(HelloRetryRandom))
                {
                    reply.SawHelloRetryRequest = true;
                }
                else
                {
                    reply.SawServerHello = true;
                }
            }

            if (reply.Closed || reply.SawServerHello || reply.SawHelloRetryRequest)
            {
                return reply;
            }
        }

        return reply;
    }

    private void Send(byte[] clientHello)
    {
        var frames = new List<byte>();

        // Acknowledge what the server sent in this space, so a retry pair is not fighting the
        // server's own retransmit while the second hello is in flight.
        if (_ackLargest >= 0)
        {
            frames.Add(0x02);
            frames.AddRange(Varint((ulong)_ackLargest));
            frames.Add(0x00);   // ack delay
            frames.Add(0x00);   // range count
            frames.AddRange(Varint((ulong)_ackLargest));   // first range: everything down to 0
        }

        // The second hello CONTINUES the client's Initial CRYPTO stream where the first ended.
        // Sending it at offset 0 again is a retransmission of bytes the server already consumed,
        // and it is discarded in silence - which reads exactly like a server that ignored it.
        frames.Add(0x06);                              // CRYPTO
        frames.AddRange(Varint((ulong)_txCryptoOff));
        frames.AddRange(Varint((ulong)clientHello.Length));
        frames.AddRange(clientHello);
        _txCryptoOff += clientHello.Length;

        _sock.Send(Protect([.. frames]));
    }

    // RFC 9000 14.1: a datagram carrying a client Initial is padded to at least 1200 bytes.
    private const int DatagramSize = 1252;

    private byte[] Protect(byte[] frames)
    {
        int header = 1 + 4 + 1 + _dcid.Length + 1 + Scid.Length + 1 + _token.Length + 2 + 4;
        int room = DatagramSize - header - 16;

        if (frames.Length > room)
        {
            throw new Exception($"the hello is {frames.Length} bytes and one Initial packet holds {room}");
        }

        byte[] plain = new byte[room];          // the tail stays zero: PADDING frames
        frames.CopyTo(plain, 0);

        uint pn = _pn++;
        byte[] pkt = new byte[DatagramSize];
        int o = 0;

        pkt[o++] = 0xc3;                         // long header, Initial, 4-byte packet number
        pkt[o++] = 0x00; pkt[o++] = 0x00; pkt[o++] = 0x00; pkt[o++] = 0x01;   // version 1
        pkt[o++] = (byte)_dcid.Length; _dcid.CopyTo(pkt, o); o += _dcid.Length;
        pkt[o++] = (byte)Scid.Length; Scid.CopyTo(pkt, o); o += Scid.Length;
        // Token length as a varint - one byte while it stays under 64, which every caller here does.
        pkt[o++] = (byte)_token.Length; _token.CopyTo(pkt, o); o += _token.Length;

        int length = 4 + plain.Length + 16;
        pkt[o++] = (byte)(0x40 | (length >> 8)); pkt[o++] = (byte)length;

        int pnOff = o;
        pkt[o++] = (byte)(pn >> 24); pkt[o++] = (byte)(pn >> 16); pkt[o++] = (byte)(pn >> 8); pkt[o++] = (byte)pn;

        using (var gcm = new AesGcm(_tx.Key, 16))
        {
            gcm.Encrypt(Nonce(_tx.Iv, pn), plain,
                pkt.AsSpan(o, plain.Length), pkt.AsSpan(o + plain.Length, 16), pkt.AsSpan(0, o));
        }

        Span<byte> mask = stackalloc byte[16];
        HeaderMask(_tx.Hp, pkt.AsSpan(pnOff + 4, 16), mask);
        pkt[0] ^= (byte)(mask[0] & 0x0f);
        for (int i = 0; i < 4; i++)
        {
            pkt[pnOff + i] ^= mask[1 + i];
        }

        return pkt;
    }

    /// <summary>
    /// Decrypt the leading packet of <paramref name="dg"/> when it is an Initial. Reports how many
    /// bytes it spanned either way, so a coalesced Handshake packet behind it can be stepped over
    /// rather than mistaken for garbage.
    /// </summary>
    private bool TryOpen(ReadOnlySpan<byte> dg, out byte[] plain, out int consumed)
    {
        plain = [];
        consumed = dg.Length;

        if (dg.Length < 7 || (dg[0] & 0x80) == 0)
        {
            return false;
        }
        if (dg[1] != 0 || dg[2] != 0 || dg[3] != 0 || dg[4] != 1)
        {
            return false;   // version negotiation, or a version this does not speak
        }

        int type = (dg[0] >> 4) & 0x03;
        int o = 5;
        int dcidLen = dg[o++];
        o += dcidLen;
        if (o >= dg.Length)
        {
            return false;
        }
        int scidLen = dg[o++];
        byte[] serverScid = dg.Slice(o, Math.Min(scidLen, dg.Length - o)).ToArray();
        o += scidLen;

        if (type == 3 || o >= dg.Length)
        {
            return false;   // Retry has no Length field; nothing here can continue past one
        }
        if (type == 0)
        {
            ulong tokenLen = ReadVarint(dg, ref o);
            o += (int)tokenLen;
        }
        if (o >= dg.Length)
        {
            return false;
        }

        ulong length = ReadVarint(dg, ref o);
        int pnOff = o;
        if (pnOff + (int)length > dg.Length || pnOff + 20 > dg.Length)
        {
            return false;
        }
        consumed = pnOff + (int)length;

        if (type != 0)
        {
            return false;   // a Handshake packet: skipped, its keys are not derivable here
        }

        // The server renames the connection the moment it answers; later packets go to its CID.
        if (serverScid.Length > 0 && !serverScid.AsSpan().SequenceEqual(_dcid))
        {
            _dcid = serverScid;
        }

        Span<byte> mask = stackalloc byte[16];
        HeaderMask(_rx.Hp, dg.Slice(pnOff + 4, 16), mask);

        byte[] header = dg[..(pnOff + 4)].ToArray();
        header[0] = (byte)(dg[0] ^ (mask[0] & 0x0f));
        int pnLen = (header[0] & 0x03) + 1;
        header = header[..(pnOff + pnLen)];

        uint pn = 0;
        for (int i = 0; i < pnLen; i++)
        {
            header[pnOff + i] = (byte)(dg[pnOff + i] ^ mask[1 + i]);
            pn = (pn << 8) | header[pnOff + i];
        }

        int bodyOff = pnOff + pnLen;
        int bodyLen = consumed - bodyOff - 16;
        if (bodyLen < 0)
        {
            return false;
        }

        plain = new byte[bodyLen];
        try
        {
            using var gcm = new AesGcm(_rx.Key, 16);
            gcm.Decrypt(Nonce(_rx.Iv, pn), dg.Slice(bodyOff, bodyLen), dg.Slice(bodyOff + bodyLen, 16), plain, header);
        }
        catch (CryptographicException)
        {
            plain = [];
            return false;
        }

        _ackLargest = Math.Max(_ackLargest, pn);
        return true;
    }

    /// <summary>Walk the frames of a decrypted Initial payload. Anything not legal in this space
    /// ends the walk rather than being guessed at.</summary>
    private static void Ingest(ReadOnlySpan<byte> payload, Reply reply, CryptoStream crypto)
    {
        int o = 0;
        while (o < payload.Length)
        {
            ulong frame = ReadVarint(payload, ref o);
            switch (frame)
            {
                case 0x00:   // PADDING
                case 0x01:   // PING
                    break;

                case 0x02:   // ACK
                case 0x03:   // ACK with ECN counts
                {
                    ReadVarint(payload, ref o);
                    ReadVarint(payload, ref o);
                    ulong ranges = ReadVarint(payload, ref o);
                    ReadVarint(payload, ref o);
                    for (ulong i = 0; i < ranges && o < payload.Length; i++)
                    {
                        ReadVarint(payload, ref o);
                        ReadVarint(payload, ref o);
                    }
                    if (frame == 0x03)
                    {
                        ReadVarint(payload, ref o);
                        ReadVarint(payload, ref o);
                        ReadVarint(payload, ref o);
                    }
                    break;
                }

                case 0x06:   // CRYPTO
                {
                    ulong offset = ReadVarint(payload, ref o);
                    ulong len = ReadVarint(payload, ref o);
                    if (o + (int)len > payload.Length)
                    {
                        return;
                    }
                    crypto.Write((int)offset, payload.Slice(o, (int)len));
                    o += (int)len;
                    break;
                }

                case 0x1c:   // CONNECTION_CLOSE (transport)
                {
                    reply.CloseError = ReadVarint(payload, ref o);
                    ReadVarint(payload, ref o);   // the frame type that caused it
                    ulong len = ReadVarint(payload, ref o);
                    if (o + (int)len <= payload.Length)
                    {
                        reply.CloseReason = Encoding.ASCII.GetString(payload.Slice(o, (int)len));
                    }
                    o += (int)len;
                    reply.Closed = true;
                    break;
                }

                case 0x1d:   // CONNECTION_CLOSE (application)
                {
                    reply.CloseError = ReadVarint(payload, ref o);
                    ulong len = ReadVarint(payload, ref o);
                    o += (int)len;
                    reply.Closed = true;
                    break;
                }

                default:
                    return;
            }
        }
    }

    /// <summary>The server's Initial-space CRYPTO stream, reassembled by offset - a
    /// HelloRetryRequest and the ServerHello that follows it share one stream.</summary>
    private sealed class CryptoStream
    {
        private readonly byte[] _b = new byte[8192];
        private int _len;
        private int _cursor;   // bytes of complete messages already reported

        public void Write(int offset, ReadOnlySpan<byte> data)
        {
            if (offset + data.Length > _b.Length)
            {
                return;   // further than anything this reads; the Initial space stays small
            }
            data.CopyTo(_b.AsSpan(offset));
            _len = Math.Max(_len, offset + data.Length);
        }

        /// <summary>Complete handshake messages that have not been reported before - so a
        /// retransmitted HelloRetryRequest is not read as a fresh one.</summary>
        public List<(byte Type, byte[] Body)> TakeNew()
        {
            var fresh = new List<(byte, byte[])>();
            while (_cursor + 4 <= _len)
            {
                int len = (_b[_cursor + 1] << 16) | (_b[_cursor + 2] << 8) | _b[_cursor + 3];
                if (_cursor + 4 + len > _len)
                {
                    break;
                }
                fresh.Add((_b[_cursor], _b[(_cursor + 4)..(_cursor + 4 + len)]));
                _cursor += 4 + len;
            }
            return fresh;
        }
    }

    // ---- RFC 9001 key derivation ---------------------------------------------------------------

    private readonly struct Keys(byte[] key, byte[] iv, byte[] hp)
    {
        public byte[] Key { get; } = key;
        public byte[] Iv { get; } = iv;
        public byte[] Hp { get; } = hp;

        public static Keys From(byte[] secret) => new(
            ExpandLabel(secret, "quic key", 16),
            ExpandLabel(secret, "quic iv", 12),
            ExpandLabel(secret, "quic hp", 16));
    }

    /// <summary>HKDF-Expand-Label (RFC 8446 7.1) with an empty context.</summary>
    private static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        byte[] full = Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = new byte[2 + 1 + full.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)full.Length;
        full.CopyTo(info, 3);
        info[^1] = 0;
        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }

    private static byte[] Nonce(byte[] iv, uint pn)
    {
        byte[] nonce = (byte[])iv.Clone();
        nonce[8]  ^= (byte)(pn >> 24);
        nonce[9]  ^= (byte)(pn >> 16);
        nonce[10] ^= (byte)(pn >> 8);
        nonce[11] ^= (byte)pn;
        return nonce;
    }

    private static void HeaderMask(byte[] hp, ReadOnlySpan<byte> sample, Span<byte> mask)
    {
        using Aes aes = Aes.Create();
        aes.Key = hp;
        aes.EncryptEcb(sample, mask, PaddingMode.None);
    }

    // ---- varints (RFC 9000 16) ------------------------------------------------------------------

    private static ulong ReadVarint(ReadOnlySpan<byte> b, ref int off)
    {
        if (off >= b.Length)
        {
            off = b.Length;
            return 0;
        }
        int len = 1 << (b[off] >> 6);
        if (off + len > b.Length)
        {
            off = b.Length;
            return 0;
        }
        ulong v = (ulong)(b[off] & 0x3f);
        for (int i = 1; i < len; i++)
        {
            v = (v << 8) | b[off + i];
        }
        off += len;
        return v;
    }

    private static byte[] Varint(ulong v) => v switch
    {
        < 1UL << 6  => [(byte)v],
        < 1UL << 14 => [(byte)(0x40 | (v >> 8)), (byte)v],
        _           => [(byte)(0x80 | (v >> 24)), (byte)(v >> 16), (byte)(v >> 8), (byte)v],
    };

    public void Dispose()
    {
        _ecdh.Dispose();
        _sock.Dispose();
    }
}
