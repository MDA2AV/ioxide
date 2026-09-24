namespace ioxide.tls;

public sealed class TlsOptions
{
    /// <summary>PEM certificate chain file. Exactly one of this and <see cref="CertificatePem"/>
    /// must be set - <see cref="TlsService.Start"/> refuses anything else.</summary>
    public string? CertificatePath { get; init; }

    /// <summary>PEM private key file. Exactly one of this and <see cref="KeyPem"/> must be set.</summary>
    public string? KeyPath { get; init; }

    /// <summary>
    /// The certificate chain as PEM text, leaf first - the in-memory alternative to
    /// <see cref="CertificatePath"/>, for hosts that carry certificates as data (an
    /// <c>X509Certificate2</c> export, a secrets store) rather than as files on disk.
    /// </summary>
    public string? CertificatePem { get; init; }

    /// <summary>The private key as PEM text - the in-memory alternative to <see cref="KeyPath"/>.</summary>
    public string? KeyPem { get; init; }

    /// <summary>
    /// Further certificates, chosen by the name the client asked for - Server Name Indication
    /// (RFC 6066 3.1), which is what lets one address serve several hosts over TLS.
    /// </summary>
    /// <remarks>
    /// The certificate above remains the DEFAULT, and answers a client that sent no name or asked
    /// for one this table does not hold. Refusing an unknown name is not done here: a server that
    /// aborts the handshake on it cannot serve a bare IP or an alias, and the client would see a
    /// connection failure rather than a certificate it can reason about.
    ///
    /// Names are matched case-insensitively and exactly - a wildcard certificate covers its names
    /// through the certificate itself, not through this table. Keys are hostnames only: SNI carries
    /// no port, and a literal IP address is not a legal SNI value (RFC 6066 3.1).
    ///
    /// Keys must be ASCII, which is what SNI carries: an international name belongs here in its
    /// A-label form (<c>xn--</c>...), the form a client actually sends. A non-ASCII key is matched
    /// byte for byte and so would simply never be asked for. Two keys differing only in case are
    /// refused, since only the first could ever be served.
    ///
    /// Each entry costs one OpenSSL context. Selection at handshake time is a short linear scan
    /// over the names as UTF-8 bytes, on the reactor thread, with no managed allocation - a
    /// dictionary would mean decoding the name into a string first, which is the allocation the
    /// shape exists to avoid. Contexts are rebuilt whenever the certificates are replaced.
    /// </remarks>
    public IReadOnlyDictionary<string, TlsCertificate>? CertificatesByHost { get; init; }

    /// <summary>
    /// Protocols this port serves, MOST PREFERRED FIRST. The client sends what it supports and the
    /// server picks; listing <c>["h2", "http/1.1"]</c> means a browser offering both gets HTTP/2.
    ///
    /// Order is the only preference ALPN has - RFC 7301 carries a plain ordered list with no
    /// quality values, so there is nothing weight-like to express. Server preference wins here
    /// (this list is walked, and the first entry the client also offered is chosen), which is what
    /// nginx and Kestrel do: the server knows which protocol it serves better.
    ///
    /// A client offering nothing we list gets no ALPN extension back and continues without one,
    /// rather than being rejected - it may still speak HTTP/1.1 perfectly well.
    /// </summary>
    public string[] Alpn { get; init; } = ["http/1.1"];

    /// <summary>
    /// How long a connection may take to finish its TLS handshake before the server gives up on
    /// it, in milliseconds. 0 disables the sweep.
    ///
    /// The default exists because the handshake read has no deadline of its own: a peer that opens
    /// a connection and then sends nothing, or dribbles a ClientHello a byte at a time, otherwise
    /// holds a connection, its SSL object and its BIOs for as long as it cares to. That is cheap
    /// to do and not cheap to absorb, and it is the one part of a TLS server reachable before any
    /// authentication has happened.
    ///
    /// Enforced on the reactor's timer, so the granularity is the tick (~250 ms) and a connection
    /// is closed at the first tick after its deadline rather than exactly on it.
    /// </summary>
    public int HandshakeTimeoutMs { get; init; } = 10_000;

    /// <summary>
    /// Lowest TLS version this server will negotiate.
    ///
    /// <see cref="TlsProtocolVersion.Default"/> keeps OpenSSL's own floor, which on a current
    /// build is TLS 1.2. <see cref="TlsProtocolVersion.Tls13"/> turns the server into 1.3-only,
    /// which is what a deployment that has to state a posture usually wants: it removes every
    /// TLS 1.2 ciphersuite, renegotiation, and static-RSA key exchange in one setting rather than
    /// leaving them to be excluded one at a time through <see cref="CipherList"/>.
    ///
    /// <see cref="KernelTx"/> already pins 1.3, so setting this to
    /// <see cref="TlsProtocolVersion.Tls12"/> alongside it is a contradiction and is refused at
    /// <see cref="TlsService.Start"/> rather than silently losing to whichever runs last.
    /// </summary>
    public TlsProtocolVersion MinProtocolVersion { get; init; } = TlsProtocolVersion.Default;

    /// <summary>
    /// TLS 1.3 ciphersuites to offer, in preference order and in OpenSSL's naming, e.g.
    /// <c>"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"</c>. Null keeps OpenSSL's defaults.
    ///
    /// Separate from <see cref="CipherList"/> because OpenSSL keeps the two lists separate: a 1.3
    /// suite named here does not restrict a 1.2 handshake and vice versa, so a server that means
    /// to constrain both has to say both - or set <see cref="MinProtocolVersion"/> to
    /// <see cref="TlsProtocolVersion.Tls13"/> and be done.
    ///
    /// Refused together with <see cref="KernelTx"/>, which requires exactly
    /// <c>TLS_AES_128_GCM_SHA256</c> to derive kernel keys.
    /// </summary>
    public string? CipherSuites { get; init; }

    /// <summary>
    /// Ciphers for TLS 1.2 and below, in OpenSSL's cipher-list syntax. Null keeps OpenSSL's
    /// defaults. Has no effect on a 1.3 handshake - see <see cref="CipherSuites"/>.
    /// </summary>
    public string? CipherList { get; init; }

    /// <summary>
    /// PEM bundle of trust anchors that CLIENT certificates are validated against - mutual TLS.
    /// Null (the default) means no client certificate is ever requested and the handshake is
    /// exactly what it was.
    ///
    /// Setting this asks every client for a certificate and rejects one whose chain does not
    /// validate. Whether a client offering NOTHING is also rejected is
    /// <see cref="RequireClientCertificate"/>.
    ///
    /// The subject names are also sent in the CertificateRequest, so a client holding several
    /// certificates can pick the one this server accepts rather than guessing.
    /// <see cref="ClientCaPem"/> sends the same hint.
    ///
    /// What validation covers: the chain builds to one of these anchors, the signatures verify,
    /// and the certificate is inside its validity window. What it does NOT cover is REVOCATION -
    /// no CRL is fetched and no OCSP request is made, so a certificate revoked by its issuer keeps
    /// being accepted until it expires. A deployment that needs revocation has to bound it some
    /// other way: short-lived certificates, or an application check against its own source of
    /// truth keyed on <see cref="TlsSession.PeerCommonName"/>.
    /// </summary>
    public string? ClientCaPath { get; init; }

    /// <summary>
    /// Client trust anchors as PEM text - the in-memory alternative to <see cref="ClientCaPath"/>,
    /// matching how the server's own certificate can come from either. Set at most one of the two.
    ///
    /// Neither source checks revocation. The one difference to design around is lifetime: a path is
    /// re-read whenever a context is built, so replacing the file changes who is trusted at the next
    /// rotation, whereas PEM text is a value and does not move.
    ///
    /// The two are NOT byte-for-byte interchangeable, and a bundle that loads from a path can be
    /// refused as text. This route parses the PEM itself rather than handing the bytes to OpenSSL's
    /// file loader, so today it reads only <c>CERTIFICATE</c> blocks - a <c>TRUSTED CERTIFICATE</c>
    /// block, which is what an OpenSSL trust store or <c>x509 -trustout</c> emits, is skipped - it
    /// converts as ASCII, so a byte-order mark makes the first block unreadable, and it sends one
    /// issuer hint per certificate where the file loader de-duplicates by subject. A malformed
    /// block is refused outright rather than silently ending the bundle, which the file route also
    /// does. If a bundle is rejected here and works as a path, that list is where to look.
    /// </summary>
    public string? ClientCaPem { get; init; }

    /// <summary>
    /// With client anchors configured, whether a client that presents NO certificate is refused
    /// during the handshake.
    ///
    /// False - the default - lets it connect unauthenticated and leaves the decision to the
    /// application, which reads <see cref="TlsSession.PeerCommonName"/> and can serve a public
    /// route while refusing a protected one. True refuses at the handshake, before a single byte
    /// of request has been read.
    ///
    /// Ignored when no anchors are set: there would be nothing to validate against.
    /// </summary>
    public bool RequireClientCertificate { get; init; }

    /// <summary>
    /// Let the kernel decrypt inbound records too. Off by default, experimental, and it requires
    /// <see cref="KernelTx"/>: RX is programmed at the same handoff as TX and shares the TCP_ULP
    /// that EnableTx installs, so asking for RX alone is refused at
    /// <see cref="TlsService.Start"/>.
    ///
    /// With both on, an ordinary recv returns PLAINTEXT and <see cref="TlsSession.Decrypt"/> is a
    /// no-op - plaintext then lands directly in ring memory, so the zero-copy reader works on TLS
    /// connections exactly as it does on cleartext ones.
    ///
    /// Two reasons it is opt-in even where <see cref="KernelTx"/> is.
    ///
    /// The handoff must land on a record boundary. Whatever the handshake already pulled off the
    /// socket is invisible to the kernel, so the record sequence it starts at has to account for
    /// it - and if the handshake left a PARTIAL record behind, those bytes are gone and no sequence
    /// number can recover them. That connection silently stays on the userspace path.
    ///
    /// And a recv can then fail with EIO. With kTLS RX a non-application-data record - a TLS 1.3
    /// KeyUpdate, or an alert - is only retrievable through recvmsg with a TLS_GET_RECORD_TYPE
    /// control message. The reactor's TCP hot path uses IORING_OP_RECV, which carries no control
    /// data, so the kernel refuses the read instead. Clients that never send one are unaffected;
    /// one that does loses the connection.
    /// </summary>
    public bool KernelRx { get; init; }

    /// <summary>
    /// Let the kernel encrypt outbound records. <b>Off by default</b> - TLS is OpenSSL in both
    /// directions unless you turn this on.
    ///
    /// It used to default on, which made ioxide's TLS asymmetric: the kernel encrypted, OpenSSL
    /// decrypted. That asymmetry is now something you opt into rather than something you inherit,
    /// because it is not free and it was not faster. Measured on loopback, HTTP/1.1, 4 reactors:
    /// kTLS trails OpenSSL by roughly 20-25% on large single writes and costs about 20% more CPU
    /// per request, while a small response shows no difference either way. What it constrains is
    /// the part that matters: the Linux <c>tls</c> module has to be present, TLS 1.3 only, one
    /// ciphersuite, and session resumption is disabled because a ticket would consume a record
    /// sequence number and desynchronise the handoff.
    ///
    /// Turn it on for what it is actually for - <c>sendfile</c> and NICs that offload TLS - neither
    /// of which those measurements exercise.
    ///
    /// <b>It changes what a handler must write.</b> With kTLS the kernel produces the records, so
    /// a handler writes plaintext straight to the connection; without it OpenSSL has to encrypt
    /// first. <see cref="TlsSession.Write"/> is correct either way and is what samples use - a bare
    /// <c>connection.Write</c> on a session with this off puts CLEARTEXT on the wire.
    /// </summary>
    public bool KernelTx { get; init; }
}
