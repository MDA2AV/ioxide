"""Generate the docs' example panes from the Playground sources, so the two cannot drift.

Same contract as gen-docs-proxy-panes.py: each pane is the sample's real Program.cs with the
Playground.Shared indirection inlined, so what the page shows is a self-contained program.
"""
import html
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

ROOT = pathlib.Path(__file__).resolve().parent.parent

# pane slug -> (sample, title, packages, run lines, trailing note)
PANES = {
    "tlssni": (
        "Tls/Sni", "SNI &middot; a certificate per host", "ioxide",
        ["curl -ks --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/",
         "curl -s --cacert alpha.test.pem --resolve alpha.test:8443:127.0.0.1 \\",
         "     https://alpha.test:8443/    # and this proves WHICH certificate came back"],
        "One port, several names, a certificate each - chosen inside the handshake, before a byte "
        "of your protocol exists. The certificate at the top stays the DEFAULT: a client that sends "
        "no name (anything connecting by IP) or asks for one that is not registered gets it rather "
        "than a dead connection. Each entry is one OpenSSL context built at startup, so choosing "
        "one per handshake is a lookup that allocates nothing - ten names cost what one does. "
        "The same feature on h2 is "
        "<label for=\"tab-h2sni\" class=\"ex-jump\">a cert per host &middot; h2</label>, and on QUIC "
        "<label for=\"tab-h3sni\" class=\"ex-jump\">h3</label>."),
    "h2sni": (
        "Http2/Sni", "h2 &middot; a certificate per host", "ioxide + ioxide.http2",
        ["curl -k --http2 --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/"],
        "<b>Two different names, at two different layers.</b> SNI in the handshake picks the "
        "CERTIFICATE; <code>:authority</code> on each request picks the SITE. Nothing makes them "
        "agree - HTTP/2 lets a client reuse one connection for any origin the certificate covers, "
        "so authorization belongs on <code>:authority</code>, which is per request, and never on "
        "the name that chose the certificate."),
    "h3sni": (
        "Http3/Sni", "h3 &middot; a certificate per host", "ioxide + ioxide.ngtcp2 + ioxide.http3",
        ["curl --http3-only -k --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/"],
        "The QUIC side, where TLS lives INSIDE the transport: no <code>TlsService</code>, one "
        "shared <code>QuicEngine</code>, and names registered before it starts serving - "
        "<code>AddHost</code> refuses afterwards, because the table is read during handshakes on "
        "every reactor at once. Client verification carries over to every host, so a name cannot "
        "be a way around the mutual TLS the engine was built with."),
    "h2rotate": (
        "Http2/Rotate", "h2 &middot; certificate renewal", "ioxide + ioxide.http2",
        ["kill -HUP <pid>            # what an ACME hook sends after rewriting the PEM",
         "curl -s --cacert alpha.test.pem --resolve alpha.test:8443:127.0.0.1 \\",
         "     https://alpha.test:8443/    # succeeds before the rotation, fails after"],
        "Replacing a certificate without dropping a connection. Three things decide whether an "
        "automated renewal is safe: it replaces the WHOLE set, so passing only the default leaves "
        "every name answered by the default certificate; a <code>TlsService</code> belongs to ONE "
        "reactor, so all of them have to be rotated and there is no instant at which they flip "
        "together; and it builds before it publishes, so a half-written PEM throws and <b>leaves "
        "the service serving what it was</b>. Live connections never notice - their certificate "
        "was chosen at handshake. Compare "
        "<label for=\"tab-h3rotate\" class=\"ex-jump\">renewal &middot; h3</label>, where one "
        "shared engine makes it a single call."),
    "h3rotate": (
        "Http3/Rotate", "h3 &middot; certificate renewal", "ioxide + ioxide.ngtcp2 + ioxide.http3",
        ["kill -HUP <pid>            # what an ACME hook sends after rewriting the PEM",
         "curl --http3-only -s --cacert alpha.test.pem \\",
         "     --resolve alpha.test:8443:127.0.0.1 https://alpha.test:8443/"],
        "The same operational need with a different shape under it: ONE engine shared by every "
        "reactor, so a rotation is a single call and a handshake sees either every old certificate "
        "or every new one - never a mixture. The engine also REFUSES to replace the default alone "
        "while it answers for names, because that hook (renew the default, forget the rest) "
        "silently published an empty table. What a rotation may never change on either stack: the "
        "client trust anchors, and whether a client certificate is required."),
    "tlsmtls": (
        "Tls/MtlsOpenSslPipes", "mutual TLS &middot; openssl &middot; pipes", "ioxide",
        ["curl -k --cert client.pem --key client.key https://127.0.0.1:8443/"],
        "The client proves who it is too, and the handler is told which peer it got. Everything "
        "below the identity check is the ordinary pipe server."),
    "tlsmtlsktls": (
        "Tls/MtlsKtlsPipes", "mutual TLS &middot; kernel tx &middot; pipes", "ioxide",
        ["sudo modprobe tls",
         "curl -k --cert client.pem --key client.key https://127.0.0.1:8443/"],
        "The same mutual TLS with the kernel encrypting outbound records. Verifying the peer and "
        "choosing who does the crypto are independent choices."),
    "aspnet": (
        "AspNet", "ASP.NET Core on the ioxide transport", "ioxide + ioxide.Kestrel",
        ["dotnet run                      # TRANSPORT=ioxide is the default",
         "TRANSPORT=sockets dotnet run    # the stock Kestrel transport, for comparison"],
        "Not an ioxide server: an ordinary ASP.NET Core app with ioxide underneath Kestrel as its "
        "transport. <code>UseIoxide</code> is the whole integration, and <code>TRANSPORT=</code> "
        "switches back to stock sockets so the same app can be measured both ways."),
    "tls": (
        "Tls/Ktls", "kTLS &middot; raw ring", "ioxide",
        ["sudo modprobe tls        # kTLS needs the Linux 'tls' module + OpenSSL 3",
         "curl -k https://127.0.0.1:8443/"],
        "<b>Opt-in - and FULL kTLS</b>: both directions in the kernel, set right on the options. "
        "Kernel RX is experimental, so <code>Tls/KtlsTx</code> in the repo is this server minus "
        "the <code>KernelRx</code> line - the half you would deploy today. The KernelTx line is what "
        "makes the <code>conn.Write</code> below legal: it puts PLAINTEXT into the slab and the "
        "kernel turns it into records. Without it the same call would put <b>cleartext on the "
        "wire</b>, which is why every other sample goes through <code>TlsSession.Write</code> - "
        "correct in either mode. Compare "
        "<label for=\"tab-tlsossl\" class=\"ex-jump\">openssl &middot; raw</label>."),
    "tlshybrid": (
        "Tls/KtlsTx", "hybrid &middot; raw ring", "ioxide",
        ["sudo modprobe tls        # the kernel half still needs the module",
         "curl -k https://127.0.0.1:8443/"],
        "The deployable kernel mode: <b>kernel TX, OpenSSL RX</b>. The handler still writes "
        "plaintext - the kernel makes the records on send, which is what keeps <code>sendfile</code> "
        "and NIC offload reachable - while receive takes the well-trodden userspace path instead of "
        "kernel RX's experimental one. "
        "<label for=\"tab-tls\" class=\"ex-jump\">ktls &middot; raw</label> is this plus kernel "
        "receive; <label for=\"tab-tlsossl\" class=\"ex-jump\">openssl &middot; raw</label> is the "
        "default, with the kernel in neither direction."),
    "tlsossl": (
        "Tls/OpenSsl", "OpenSSL &middot; raw ring", "ioxide",
        ["curl -k https://127.0.0.1:8443/        # no modprobe needed"],
        "<b>The default.</b> No TLS ULP is attached at all - OpenSSL encrypts and decrypts, and the "
        "response goes through <code>TlsSession.Write</code>, which is correct whichever backend the "
        "session ended up with. That drops every constraint kTLS imposes: no kernel module, TLS 1.2, any "
        "ciphersuite, session resumption back, no handshake-alignment problem. What it gives up is "
        "<code>sendfile</code> and NIC offload. "
        "<b>It costs nothing measurable here</b> - against the plaintext baseline, 4 reactors, "
        "<code>wrk -t4 -c64</code>: 0.79&times; for both at a 64-byte response, 0.35&times; kTLS vs "
        "0.44&times; OpenSSL at 64 KiB. Which backend you pick matters far less than the cost of TLS."),
    "tlspipe": (
        "Tls/KtlsPipes", "kTLS &middot; pipes", "ioxide",
        ["sudo modprobe tls", "curl -k https://127.0.0.1:8443/"],
        "The same full-kTLS server behind an <code>IDuplexPipe</code>, for the frameworks that serve from "
        "one. Now compare <label for=\"tab-tlsosslpipe\" class=\"ex-jump\">openssl &middot; pipes</label>: "
        "its serve loop is <b>byte-identical</b> to this one. Over a pipe the backend is invisible, "
        "because <code>TlsConnectionDualPipe</code> composes its halves from the session rather than "
        "from configuration."),
    "tlsosslpipe": (
        "Tls/OpenSslPipes", "OpenSSL &middot; pipes", "ioxide",
        ["curl -k https://127.0.0.1:8443/        # no modprobe needed"],
        "Diff this against <label for=\"tab-tlspipe\" class=\"ex-jump\">ktls &middot; pipes</label> and "
        "the only functional difference is <code>KernelTx</code>; the rest is the banner and the log "
        "tag. That is the point of the pipe seam - <code>TlsConnectionDualPipe</code> pairs "
        "<code>TcpConnectionPipeReader</code> or <code>TlsDecryptingPipeReader</code> with "
        "<code>TcpConnectionPipeWriter</code> or <code>TlsEncryptingPipeWriter</code>, chosen from the "
        "<em>session</em>. It has to be the session and not the config, because a handshake that left a "
        "partial record keeps the userspace reader whatever was asked for."),
    "tlsmulti": (
        "Tls/MultiPort", "plaintext + TLS &middot; one server", "ioxide",
        ["curl  http://127.0.0.1:8080/", "curl -ks https://127.0.0.1:8081/"],
        "One server, two doors: plaintext on <code>:8080</code>, TLS on <code>:8081</code>, and ONE "
        "serve loop for both. The branch on <code>ListenerPort</code> is the entire difference - "
        "the TLS door builds a <code>TlsConnectionDualPipe</code>, the plaintext door pairs the "
        "connection's own reader and writer, and the loop reads an <code>IDuplexPipe</code> without "
        "knowing which it got. Ports come from <a href=\"learn/multiport.html\">multi-port</a>; "
        "TLS is the default backend, OpenSSL both ways."),

    # ── transport ────────────────────────────────────────────────────────────────────────────
    "tlsbcl": (
        "Tls/SslStream", "TLS &middot; SslStream", "ioxide",
        ["curl -k https://127.0.0.1:8443/"],
        "The third TLS backend, and the portable one: the BCL's <code>SslStream</code> over "
        "<code>TcpConnectionStream</code>. Fully managed, full-featured, and the slowest of the "
        "three, because the bytes are copied through a <code>Stream</code> both ways. Reach for it "
        "for <b>client certificates</b> - the ring-native path does not do mTLS - or anything else "
        "OpenSSL-on-the-ring does not expose; for TLS 1.2 and resumption the default already has "
        "you covered: <label for=\"tab-tlsossl\" class=\"ex-jump\">openssl &middot; raw</label>."),
    "big": (
        "Tcp/Big", "TCP &middot; large responses", "ioxide",
        ["curl -s http://127.0.0.1:8080/ | wc -c"],
        "The write path under a payload that does not fit the slab, and the knobs that shape it: "
        "<code>WriteSlabSize</code>, <code>WriteOverflow</code> (<code>Grow</code> reallocates, "
        "<code>Segmented</code> chains slabs into one SENDMSG) and <code>ZeroCopySend</code>, which "
        "only pays off once the response is large enough for the pinning to be worth it."),
    "hop": (
        "Tcp/Hop", "TCP &middot; leaving the reactor", "ioxide",
        ["curl http://127.0.0.1:8080/"],
        "The same server as <label for=\"tab-shared\" class=\"ex-jump\">raw &middot; shared ring</label>, "
        "except every request deliberately bounces off the reactor thread and back. It is here as the "
        "counter-example: this is what ioxide spends its design avoiding, and having it runnable makes "
        "the cost measurable rather than asserted."),
    "taskrun": (
        "Tcp/TaskRun", "TCP &middot; ordinary async", "ioxide",
        ["curl http://127.0.0.1:8080/"],
        "Proof that normal .NET async works inside a handler - <code>Task.Run</code>, "
        "<code>Task.Delay</code>, the thread pool - and that you come back to your reactor "
        "afterwards. The per-reactor <code>SynchronizationContext</code> is what makes that true, so "
        "connection and pool state stay single-threaded without a lock even when a handler wanders."),

    # ── protocols ────────────────────────────────────────────────────────────────────────────
    "h2cstls": (
        "Http2/Tls", "HTTP/2 &middot; TLS &amp; ALPN", "ioxide + ioxide.http2",
        ["curl -k --http2 https://127.0.0.1:8443/"],
        "How a browser actually reaches h2: over TLS, with the protocol chosen during the "
        "handshake. <code>Alpn = [\"h2\", \"http/1.1\"]</code> is an ordered preference, not a "
        "weighting - the server takes the first entry the client also offered, and this sample "
        "then branches on what was agreed, so ONE port serves both. That is why the h2c samples "
        "are the exception rather than the rule. What <code>Http2Connection</code> is handed is a "
        "<code>TlsConnectionDualPipe</code>: it never learns TLS is involved, so the protocol code "
        "is byte-for-byte the h2c sample's. TLS is <b>OpenSSL both ways by default</b>; the "
        "<code>kernelTx</code>/<code>kernelRx</code> knobs at the top move either direction into "
        "the kernel, and cost the same <b>0.05&micro;s per request</b> either way."),
    "h2bcl": (
        "Http2/SslStream", "HTTP/2 &middot; over SslStream", "ioxide + ioxide.http2",
        ["curl -k --http2 https://127.0.0.1:8443/"],
        "HTTP/2 over the BCL's <code>SslStream</code>, and the point is the ten-line "
        "<code>Stream</code>-to-<code>IDuplexPipe</code> adapter at the bottom. "
        "<code>Nghttp2Connection</code> takes a pipe, so the same HTTP/2 code runs over the ring "
        "directly, over ioxide's TLS, or over <code>SslStream</code> - the transport is a "
        "constructor argument, not a branch inside the protocol."),
    "h3cs": (
        "Http3/ManagedBuffered", "HTTP/3 &middot; buffered", "ioxide + ioxide.ngtcp2 + ioxide.http3",
        ["curl --http3-only -k https://127.0.0.1:8443/"],
        "HTTP/3 with <b>no native library above the transport</b> - frames, QPACK and Huffman are "
        "all managed code, and only QUIC itself stays native. Drop-in for "
        "<label for=\"tab-h3\" class=\"ex-jump\">nghttp3</label>: the diff is the package and three "
        "type names. It is also <b>faster at every size measured</b> on this rig - 2 reactors, "
        "<code>h3x --connections 16 -m 8</code>: <b>1.54&times;</b> at a 13-byte body, 1.28&times; at "
        "50 KiB, 1.32&times; at 1 MiB, using less memory at the large end. The small-body lead came "
        "from sending the header frame and a short body in ONE call rather than two; the large-body "
        "lead is the native shim copying every response body at submit, which this never does."),
    "h3stream": (
        "Http3/Nghttp3Response", "HTTP/3 &middot; response streamed (nghttp3)", "ioxide + ioxide.ngtcp2 + ioxide.nghttp3",
        ["curl --http3-only -k https://127.0.0.1:8443/",
         "curl --http3-only -kN https://127.0.0.1:8443/feed   # never ends"],
        "The response body produced OVER TIME instead of handed over whole - each flush becomes a "
        "DATA frame. That is what <code>/feed</code> demonstrates: an endless response has no final "
        "byte, so a buffered API cannot express it at all. <code>Nghttp3ResponseWriter</code> is an "
        "<code>IBufferWriter&lt;byte&gt;</code>, so a serializer or a framework's response sink "
        "writes into it unchanged, and <code>FlushAsync</code> returning only once nghttp3 has taken "
        "the chunk is what stops a producer outrunning a peer that has stopped reading. nghttp3 "
        "PULLS body bytes rather than accepting pushes, which is why this carries a resume and a "
        "drain the pure-C# writer does not need."),
    "h3csstream": (
        "Http3/ManagedStreamedBoth", "HTTP/3 &middot; request + response streamed", "ioxide + ioxide.ngtcp2 + ioxide.http3",
        ["curl --http3-only -k https://127.0.0.1:8443/",
         "curl --http3-only -kN https://127.0.0.1:8443/feed        # never ends",
         "curl --http3-only -k --data-binary @big.bin https://127.0.0.1:8443/echo"],
        "Both directions streamed, in pure C#. The request body is PULLED a chunk at a time through "
        "<code>Http3Request.BodyReader</code>, so a large upload is never held whole; the response is "
        "PUSHED through <code>Http3ResponseWriter</code>, one DATA frame per flush, so a large "
        "download is never built whole. <code>/echo</code> runs both at once - read a chunk, write a "
        "chunk - which is what a proxy does. "
        "Owning the framing is what makes the push side simple: a chunk is just "
        "<code>[0x00][varint length][payload]</code> handed to the QUIC stream, with no data-reader "
        "callback to answer and nothing to defer. "
        "<label for=\"tab-h3stream\" class=\"ex-jump\">nghttp3 &middot; streamed</label> carries a "
        "resume and a drain because nghttp3 pulls instead; this measures <b>1.32&times;</b> its "
        "throughput on the same 8&times;1&nbsp;KiB response."),
    "h3ngboth": (
        "Http3/Nghttp3StreamedBoth", "HTTP/3 &middot; request + response streamed (nghttp3)",
        "ioxide + ioxide.ngtcp2 + ioxide.nghttp3",
        ["curl --http3-only -k https://127.0.0.1:8443/",
         "curl --http3-only -k --data-binary @big.bin https://127.0.0.1:8443/echo"],
        "The fourth corner the other three nghttp3 samples leave empty: the request pulled through "
        "<code>BodyReader</code> while the response is pushed through the writer, both in one "
        "handler. One call arranges it - <code>RunStreamedResponseAsync</code> dispatches at "
        "end-of-headers, so the handler is running while the upload is still on the wire. "
        "<code>/echo</code> is the shape a proxy needs: read a chunk, write a chunk, never hold "
        "more than one, and neither side can outrun the other because <code>ReadAsync</code> waits "
        "on the peer and <code>FlushAsync</code> waits on nghttp3. Measured here on a 64 MiB echo: "
        "byte-identical out, and the server's RSS moved 51&rarr;57 MB - flat, in the sense that "
        "matters. Diff it against "
        "<label for=\"tab-h3csstream\" class=\"ex-jump\">the pure-C# twin</label>: same routes, "
        "opposite mechanism underneath. nghttp3 owns the framing and <b>pulls</b> body bytes when "
        "it has room to emit DATA, so a flush here means <em>nghttp3 has taken the chunk</em>, "
        "where the managed writer stages a DATA frame the moment you flush. That twin also serves "
        "an endless <code>/feed</code>; this one deliberately does not, because on this stack an "
        "endless response never reaches the wire."),
    "h3buf": (
        "Http3/Nghttp3Buffered", "HTTP/3 &middot; buffered (nghttp3)", "ioxide + ioxide.ngtcp2 + ioxide.nghttp3",
        ["curl --http3-only -k https://127.0.0.1:8443/"],
        "The same server as <label for=\"tab-h3\" class=\"ex-jump\">nghttp3</label> with the other "
        "dispatch mode - one method call is the whole difference. <b>Buffered</b> waits for "
        "end-of-stream, so the body is already in <code>request.Body</code> when your handler runs; "
        "the trade is that memory holds the whole body, which suits normal requests and not hostile "
        "uploads. <b>Streamed</b> runs you while the body is still arriving and credits the peer's "
        "flow-control window as you read, so memory is bound by one window instead."),
    "h3mtls": (
        "Http3/MutualTls", "HTTP/3 &middot; mutual TLS", "ioxide + ioxide.ngtcp2 + ioxide.http3",
        ["PLAYGROUND_CLIENT_CA=ca.crt dotnet run -c Release --project Playground/Http3/MutualTls",
         "curl --http3 --cacert ca.crt --cert client.crt --key client.key https://localhost:8443/"],
        "The client proves who it is too. <code>clientCaPemPath</code> is what turns it on - the CA "
        "that client certificates are checked against - and the handler reads "
        "<code>PeerSubject</code> to find out WHICH client it got. That distinction is the point: a "
        "server that can only answer <em>some valid certificate</em> has a gate, where one that can "
        "name the peer has an identity to authorise against. "
        "Read it per REQUEST, not where the connection is accepted - that callback runs before the "
        "handshake finishes, so there is no identity yet. "
        "<b>QUIC settles client authentication during the handshake</b>, and RFC 9001 &sect;4.4 "
        "forbids doing it afterwards, so this is a property of the whole CONNECTION: there is no "
        "asking for a certificate later because a request reached a protected route. That needs a "
        "second port. <code>requireClientCertificate</code> decides whether a client offering none "
        "is refused during the handshake or arrives unauthenticated for the handler to judge."),
    "quicalpn": (
        "Quic/Alpn", "QUIC &middot; two protocols by ALPN", "ioxide + ioxide.ngtcp2 + ioxide.nghttp3",
        ["curl --http3-only -k https://127.0.0.1:8443/"],
        "One QUIC listener serving two protocols, chosen during the handshake: connections that "
        "negotiate <code>h3</code> get the HTTP/3 loop, anything else gets raw stream echo over the "
        "dual pipe. QUIC-only - <code>Tcp = null</code>, so the process opens no TCP listener at all."),
    "files": (
        "Clients/File", "Client &middot; static files", "ioxide + ioxide.file",
        ["curl http://127.0.0.1:8080/index.html",
         "PLAYGROUND_FILE_TLS=ktls    # then curl -k https://127.0.0.1:8443/index.html"],
        "Every file under the root is opened <b>once</b> and the descriptors shared across reactors, "
        "read positionally off the ring - nothing locked, nothing cached in memory. The knob worth "
        "reading is <code>tlsMode</code>, because it decides whether the fast path is even legal, and "
        "the whole question is <em>what is the write slab supposed to hold when it is sent?</em> "
        "Cleartext: the slab IS the wire. <b>kTLS</b>: the slab holds plaintext and the kernel makes "
        "the records - so <code>ReadFileAsync</code> can still read the file straight into it and the "
        "bytes are never copied. <b>OpenSSL</b>: the slab must hold ciphertext, so the body has to "
        "pass through <code>TlsSession.Write</code>, which needs a source buffer - and that buffer IS "
        "the copy. The sample refuses that combination rather than serving the file in the clear. "
        "Measured on one saturated reactor at 4 KiB, skipping the copy is worth <b>1.22&times;</b> "
        "cleartext and <b>1.21&times;</b> under kTLS; at 64 KiB the kernel's per-byte crypto "
        "overtakes it and OpenSSL wins outright."),

    # ── the last hand-written code panes, now generated too ──────────────────────────────────
    "pipe": (
        "Tcp/Pipe", "TCP &middot; pipes", "ioxide",
        ["curl http://127.0.0.1:8080/"],
        "The <code>IDuplexPipe</code> seam over a plain TCP connection - what "
        "<code>ioxide.Kestrel</code> and the HTTP/2 layers sit on. Compare "
        "<label for=\"tab-shared\" class=\"ex-jump\">raw &middot; shared ring</label>: same server, "
        "one abstraction lower."),
    "shared": (
        "Tcp/Raw", "TCP &middot; raw, shared recv ring", "ioxide",
        ["curl http://127.0.0.1:8080/"],
        "The bottom of the stack: no pipes, no protocol, just the ring. Buffers come from one "
        "shared provided-buffer ring per reactor - the default mode. "
        "<label for=\"tab-inc\" class=\"ex-jump\">incremental</label> hands them out per connection "
        "instead, and <label for=\"tab-vs\" class=\"ex-jump\">shared vs incremental</label> is the "
        "comparison."),
    "inc": (
        "Tcp/Incremental", "TCP &middot; raw, incremental ring", "ioxide",
        ["curl http://127.0.0.1:8080/"],
        "Per-connection recv buffer rings (kernel 6.12+) instead of one shared ring. The kernel "
        "appends across recvs into the same buffer, so a request split over several reads arrives "
        "contiguous. Costs memory per connection - see "
        "<label for=\"tab-vs\" class=\"ex-jump\">shared vs incremental</label>."),
    "h2cs": (
        "Http2/ManagedBuffered", "HTTP/2 &middot; buffered", "ioxide + ioxide.http2",
        ["curl --http2-prior-knowledge http://127.0.0.1:8080/"],
        "<b>h2c with prior knowledge</b>: the peer opens with the HTTP/2 connection preface and "
        "there is no upgrade dance. For h2 over TLS see "
        "<label for=\"tab-h2cstls\" class=\"ex-jump\">tls &amp; alpn</label> - the protocol code "
        "there is byte-for-byte this one, because <code>Http2Connection</code> takes an "
        "<code>IDuplexPipe</code> and never learns what is under it. "
        "BUFFERED is the dispatch mode: the handler runs once the request has fully arrived, so "
        "<code>request.Body</code> holds the whole body and the answer is one "
        "<code>Http2Response</code>. That is the right default, and the wrong one for a large "
        "upload or an endless response - the three tabs after it are those cases."),
    "h2sresp": (
        "Http2/ManagedStreamedResponse", "HTTP/2 &middot; response streamed", "ioxide + ioxide.http2",
        ["curl --http2-prior-knowledge http://127.0.0.1:8080/",
         "curl --http2-prior-knowledge -N http://127.0.0.1:8080/feed   # never ends"],
        "The RESPONSE body produced over time instead of returned whole - each flush becomes a "
        "DATA frame. <code>/feed</code> is why the mode exists: an endless response has no final "
        "byte, so a buffered API cannot express it at all. <code>Http2ResponseWriter</code> is an "
        "<code>IBufferWriter&lt;byte&gt;</code>, so a serializer or a framework's response sink "
        "writes into it unchanged. What HTTP/2 adds over "
        "<label for=\"tab-h3csstream\" class=\"ex-jump\">the h3 equivalent</label> is that credit "
        "is SHARED: every stream rides one TCP connection, so a flush waits on whichever of the "
        "stream and connection windows runs out first, and a WINDOW_UPDATE for either wakes it."),
    "h2sreq": (
        "Http2/ManagedStreamedRequest", "HTTP/2 &middot; request streamed", "ioxide + ioxide.http2",
        ["head -c 50000000 /dev/zero | curl --http2-prior-knowledge --data-binary @- \\",
         "  http://127.0.0.1:8080/upload"],
        "The other direction, and a different problem. <code>StreamRequestBodies</code> dispatches "
        "at the HEADERS and hands the handler an <code>Http2BodyReader</code>, so it runs while "
        "the upload is still arriving. What changes is what bounds memory: buffered holds the "
        "whole body, so <code>MaxRequestBytes</code> is all that stands between a hostile peer and "
        "the arena; streamed holds ONE flow-control window, because a chunk credits the peer's "
        "window only as the handler <em>reads</em> it. Fall behind and the peer runs out of credit "
        "and stops sending - backpressure the peer takes part in, rather than a buffer you hope is "
        "big enough."),
    "h2sboth": (
        "Http2/ManagedStreamedBoth", "HTTP/2 &middot; both directions streamed", "ioxide + ioxide.http2",
        ["curl --http2-prior-knowledge -N http://127.0.0.1:8080/feed",
         "head -c 50000000 /dev/zero | curl --http2-prior-knowledge --data-binary @- \\",
         "  http://127.0.0.1:8080/echo"],
        "Both at once, which is the shape a proxy needs: <code>/echo</code> reads a chunk and "
        "writes a chunk, so neither the upload nor the download is ever held whole. The two "
        "directions are separate switches - <code>StreamRequestBodies</code> for the read side, "
        "<code>RunAsync</code> with a writer for the write side - because they solve different "
        "problems and most servers want exactly one of them. Mirrors "
        "<label for=\"tab-h3csstream\" class=\"ex-jump\">h3 &middot; request + response "
        "streamed</label>; the difference is HTTP/2's shared connection window, which a handler "
        "that stops reading holds down for every other stream on the connection."),
    "h2ng": (
        "Http2/Nghttp2Buffered", "HTTP/2 &middot; nghttp2", "ioxide + ioxide.nghttp2",
        ["curl --http2-prior-knowledge http://127.0.0.1:8080/"],
        "The same h2c server on the <b>reference implementation</b>. Kept because being battle-tested "
        "is a property no amount of benchmarking substitutes for: nghttp2 is continuously fuzzed, "
        "patched by people whose job it is when the next HTTP/2 CVE lands, and has a decade of "
        "interop against every other stack. "
        "It streams both directions too now - see "
        "<label for=\"tab-h2ngs\" class=\"ex-jump\">response streamed (nghttp2)</label> and "
        "<label for=\"tab-h2ngreq\" class=\"ex-jump\">request streamed (nghttp2)</label>. "
        "Measured as a client on this rig, the managed "
        "stack runs <b>1.35&times;-1.39&times;</b> it. Take this one when you want the reference "
        "implementation's coverage; take "
        "<label for=\"tab-h2cs\" class=\"ex-jump\">buffered</label> for everything else."),
    "h2ngs": (
        "Http2/Nghttp2Response", "HTTP/2 &middot; nghttp2, response streamed", "ioxide + ioxide.nghttp2",
        ["curl --http2-prior-knowledge http://127.0.0.1:8080/",
         "curl --http2-prior-knowledge -N http://127.0.0.1:8080/feed   # never ends"],
        "The same streamed response as "
        "<label for=\"tab-h2sresp\" class=\"ex-jump\">the managed one</label>, and the sample code is "
        "nearly identical - but what happens underneath is the opposite. nghttp2 owns the framing, so "
        "it <b>PULLS</b>: it asks for body bytes when it is ready to emit DATA, and its read callback "
        "<em>defers</em> whenever nothing is buffered rather than ending the stream. Every write "
        "buffers a chunk natively and resumes the deferred stream. "
        "So a flush here means <em>handed over</em>, not <em>on the wire</em> - nghttp2 decides frame "
        "boundaries and timing - where the managed writer stages a DATA frame the moment you flush. "
        "That difference is the whole reason this needed new native entry points "
        "(<code>ih2_submit_response_stream</code>, <code>ih2_stream_write</code>, "
        "<code>ih2_stream_close</code>) rather than being a C# change."),
    "h2ngreq": (
        "Http2/Nghttp2StreamedRequest", "HTTP/2 &middot; nghttp2, request streamed", "ioxide + ioxide.nghttp2",
        ["head -c 50000000 /dev/zero | curl --http2-prior-knowledge --data-binary @- \\",
         "  http://127.0.0.1:8080/upload"],
        "The same streamed request body as "
        "<label for=\"tab-h2sreq\" class=\"ex-jump\">the managed one</label>, and nearly the same "
        "sample: <code>StreamRequestBodies</code> dispatches at the HEADERS and hands the handler an "
        "<code>Nghttp2BodyReader</code>. What makes it hold is underneath. nghttp2 "
        "credits DATA the moment it arrives unless told otherwise, which would put the bound back on "
        "the whole body, so a streaming session runs with its automatic WINDOW_UPDATE off and the "
        "reader hands credit back only as the handler <em>reads</em>. Every byte nghttp2 delivers is "
        "then credited exactly once - read, left unread by a handler that returned, or on a stream "
        "that was reset - because one that never is shrinks the connection window for every stream on "
        "it. That took one native entry point (<code>ih2_consume</code>) and a flag on "
        "<code>ih2_server_new</code>."),
    "h3": (
        "Http3/Nghttp3Request", "HTTP/3 &middot; request streamed (nghttp3)", "ioxide + ioxide.ngtcp2 + ioxide.nghttp3",
        ["curl --http3-only -k https://127.0.0.1:8443/"],
        "HTTP/3 over QUIC, dispatched as the body streams. Compare "
        "<label for=\"tab-h3buf\" class=\"ex-jump\">buffered</label>, which waits for end-of-stream "
        "instead - one method call is the whole difference."),
    "qpipe": (
        "Quic/Pipe", "QUIC &middot; pipes", "ioxide + ioxide.ngtcp2",
        ["dotnet run -c Release --project Playground/Quic/Pipe"],
        "QUIC behind an <code>IDuplexPipe</code>, the transport's twin of "
        "<label for=\"tab-pipe\" class=\"ex-jump\">tcp &middot; pipes</label>. A "
        "<code>PipeReader</code> is ONE byte stream, so this binds to a single QUIC stream - which "
        "is exactly why HTTP/3 cannot use it and takes "
        "<label for=\"tab-qraw\" class=\"ex-jump\">raw streams</label> instead. ngtcp2 + picotls "
        "ship as one native, so TLS 1.3 is inside the transport and the certificate IS the config."),
    "qraw": (
        "Quic/Raw", "QUIC &middot; raw streams", "ioxide + ioxide.ngtcp2",
        ["dotnet run -c Release --project Playground/Quic/Raw"],
        "Every stream on the connection, not just one: each delivery names its stream id, so a "
        "multi-stream protocol demuxes right here. This is the surface "
        "<code>ioxide.nghttp3</code> sits on."),
    "http": (
        "Clients/Http", "HTTP client &middot; alt-svc", "ioxide + ioxide.httpclient",
        ["dotnet run -c Release --project Playground/Http3/Nghttp3Request   # an origin advertising h3",
         "PLAYGROUND_UPSTREAM_PORT=8080 dotnet run -c Release --project Playground/Clients/Http"],
        "Both hops - the inbound connection and the outbound call - ride this reactor's ring and "
        "resume inline, so a request never leaves the thread it arrived on. The knob is "
        "<code>Policy</code>: <code>Negotiate</code> starts on HTTP/1.1 and moves to HTTP/3 once the "
        "origin advertises it via <b>Alt-Svc</b>, so the upgrade costs nothing at the call site. The "
        "nine <label for=\"tab-pxmatrix\" class=\"ex-jump\">proxy</label> samples pin a protocol "
        "instead."),
    "pg": (
        "Clients/Pg", "Postgres", "ioxide + ioxide.pg",
        ["curl http://127.0.0.1:8080/"],
        "One pool per reactor, opened on the reactor thread, so a query rides the same ring that "
        "accepted the request and resumes the handler inline. The host must be an IPv4 literal - a "
        "DNS lookup would block the reactor."),
    "timer": (
        "Clients/Timer", "Timers &middot; a deadline on the ring", "ioxide + ioxide.timer",
        ["curl http://127.0.0.1:8080/50"],
        "A wait is one <code>IORING_OP_TIMEOUT</code>: the kernel holds the deadline and the "
        "completion arrives on the reactor that took the request, with the connection's state "
        "still warm. Nothing is armed on the side, no syscall of its own is made to arrange it, "
        "and nothing is allocated per wait - a <code>RingTimer</code> holds ONE "
        "<code>RingOpSource</code>, so it carries one wait at a time and belongs to one "
        "connection. Which is the point at scale: 32,000 connections waiting is 32,000 deadlines "
        "the KERNEL holds, where a timerfd each would be 32,000 descriptors and a "
        "<code>timerfd_settime</code> per wait. Expiry arrives as <b>-ETIME</b>, io_uring's normal "
        "report for a timeout rather than a failure, which is why the check is "
        "<code>RingTimer.Expired</code> and not <code>result &gt;= 0</code>. The "
        "<code>useTaskDelay</code> knob swaps in <code>Task.Delay</code> - same server, same "
        "response - so the hop it costs is measurable rather than asserted; "
        "<label for=\"tab-hop\" class=\"ex-jump\">leaving the reactor</label> is that hop on its "
        "own."),
    "redis": (
        "Clients/Redis", "Redis", "ioxide + ioxide.redis",
        ["curl http://127.0.0.1:8080/"],
        "RESP2 with pipelining, one pool per reactor. Same shape as "
        "<label for=\"tab-pg\" class=\"ex-jump\">postgres</label> - the client is ring-native, so "
        "the round trip never leaves the core the request landed on."),
    "qclient": (
        "Clients/Quic", "QUIC &middot; client", "ioxide + ioxide.ngtcp2",
        ["dotnet run -c Release --project Playground/Quic/Raw   # something to talk to",
         "dotnet run -c Release --project Playground/Clients/Quic"],
        "The client half of QUIC, and the other side of "
        "<label for=\"tab-qraw\" class=\"ex-jump\">quic &middot; raw streams</label> - everything "
        "else here is a server. <code>QuicClientEngine.Connect</code> needs no listener at all: it "
        "asks the reactor for an outbound transport on an ephemeral port, which is why "
        "<code>Tcp</code>, <code>Udp</code> and <code>Quic</code> are all null below. The handshake, "
        "the stream and the reads ride that reactor's ring and resume inline on it, exactly as they "
        "do server-side. It doubles as the <b>load driver</b> for the echo servers - they speak no "
        "HTTP, so wrk and h2load cannot touch them - which is what makes them benchmarkable."),
    "https": (
        "Clients/Https", "Client &middot; https origins", "ioxide + ioxide.httpclient",
        ["curl http://127.0.0.1:8080/get"],
        "TLS in the other direction: not terminating it for inbound connections but speaking it "
        "outbound, so a handler can reach an <code>https://</code> origin on the same ring that "
        "accepted the request. One <code>TlsClientContext</code> per reactor, shared by that "
        "reactor's pool. Verification is on by default - turning it off leaves the hop encrypted but "
        "<em>unauthenticated</em>, and a private CA belongs in <code>CaFile</code> instead."),
}

from paneinline import BANNER, ENV_DEFAULTS, inline, inline_env

def build(slug: str) -> str:
    sample, title, packages, run, note = PANES[slug]
    body = inline((ROOT / f"Playground/{sample}/Program.cs").read_text())

    # One real command per package. This used to be a single line with the packages joined by
    # " + ", which read fine when every pane was TLS (one package) and became a command nobody
    # can paste as soon as the generator grew panes that need three.
    header = "\n".join(f"// dotnet add package {p.strip()}" for p in packages.split("+"))
    header += "\n" + "\n".join(f"//   {line}" for line in run)
    code = html.escape(f"{header}\n\n{body}", quote=False).replace("'", "&#x27;").replace('"', "&quot;")

    return (f'  <div class="pane pane-{slug}">\n'
            f'    <div class="pane-head">\n'
            f'      <h3>{title}</h3>\n'
            f'      <span class="pane-pkg">{packages}</span>\n'
            f'    </div>\n'
            f'<pre><code class="language-csharp">{code}</code></pre>\n'
            f'    <p class="ex-foot">{note}</p>\n'
            f'  </div>\n')


if __name__ == "__main__":
    index = ROOT / "docs/index.html"
    page = index.read_text()
    changed = 0

    for slug in PANES:
        marker = f'  <div class="pane pane-{slug}">'
        if marker not in page:
            raise SystemExit(f"pane-{slug} is not in docs/index.html - add its tab first")

        start = page.index(marker)
        end = page.index("  </div>\n", page.index("</code></pre>", start)) + len("  </div>\n")
        fresh = build(slug)
        if page[start:end] != fresh:
            page = page[:start] + fresh + page[end:]
            changed += 1

    if changed:
        index.write_text(page)
        print(f"rewrote {changed} of {len(PANES)} panes in docs/index.html")
    else:
        print("docs/index.html is already up to date")

    for slug, (sample, *_rest) in PANES.items():
        print(f"  pane-{slug:12} <- Playground/{sample}/Program.cs")
