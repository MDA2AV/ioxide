package ioxide.tls

/** Lowest TLS version a server negotiates. See [TlsOptions.minProtocolVersion]. */
enum class TlsProtocolVersion {
    /** BoringSSL's own floor: TLS 1.2 on a current build. */
    DEFAULT,

    /** TLS 1.2 and above. */
    TLS12,

    /** TLS 1.3 only. */
    TLS13,
}

/**
 * One TLS port's settings; [TlsService.start] takes them per reactor and refuses the combinations that cannot hold.
 *
 * @property certificatePath PEM certificate chain file, leaf first. Exactly one of this and [certificatePem].
 * @property keyPath PEM private key file. Exactly one of this and [keyPem].
 * @property certificatePem the chain as PEM text.
 * @property keyPem the key as PEM text.
 * @property alpn protocols this port serves, most preferred first: the first one the client also offered wins. A
 *   client offering none of them continues without ALPN rather than being refused.
 * @property handshakeTimeoutMs how long a handshake may take before the connection is closed, checked every
 *   reactor tick (~250 ms); 0 disables it. The handshake read has no deadline of its own, and it is reachable
 *   before any authentication.
 * @property minProtocolVersion the floor. [kernelTx] already pins TLS 1.3, so TLS12 alongside it is refused.
 * @property cipherSuites TLS 1.3 suites in preference order, in BoringSSL's names
 *   (`"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"`); null keeps BoringSSL's. With [kernelTx], only
 *   TLS_AES_128_GCM_SHA256 is accepted.
 * @property cipherList TLS 1.2 ciphers in BoringSSL's cipher-list syntax; null keeps BoringSSL's.
 * @property kernelTx the kernel encrypts outbound records (kTLS TX): handlers write plaintext and the ring's sends
 *   carry it. Off by default. Needs the `tls` kernel module, and pins TLS 1.3, one suite and no session tickets
 *   (a ticket would consume a record sequence number before the handoff). [TlsSession.write] is right either way.
 * @property kernelRx the kernel decrypts inbound records too (kTLS RX), so a recv returns plaintext. Experimental,
 *   and requires [kernelTx], whose ULP it rides. The handoff waits for a record boundary - a connection whose
 *   records keep arriving cut past 1 MiB stays on BoringSSL - and a non-data record (a KeyUpdate, an alert) then
 *   fails the recv with EIO, which ends the read side; a close_notify still reaches [TlsSession.closed].
 */
class TlsOptions(
    val certificatePath: String? = null,
    val keyPath: String? = null,
    val certificatePem: String? = null,
    val keyPem: String? = null,
    val alpn: List<String> = listOf("http/1.1"),
    val handshakeTimeoutMs: Int = 10_000,
    val minProtocolVersion: TlsProtocolVersion = TlsProtocolVersion.DEFAULT,
    val cipherSuites: String? = null,
    val cipherList: String? = null,
    val kernelTx: Boolean = false,
    val kernelRx: Boolean = false,
)
