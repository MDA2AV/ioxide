namespace ioxide.httpclient;

/// <summary>
/// How a client should negotiate TLS with an origin. The defaults are the safe ones: verify the
/// peer against the system trust store, and require its certificate to match the name we asked for.
/// </summary>
public sealed record TlsClientOptions
{
    /// <summary>
    /// The name sent as SNI and checked against the certificate the origin presents. Null: the name the
    /// connection is opened to (<see cref="HttpClientOptions.Host"/>, or the URL's host), so one context
    /// serves any number of origins. Set it to connect by address, which on its own has nothing to verify.
    /// </summary>
    public string? ServerName { get; init; }

    /// <summary>
    /// ALPN protocols to offer, most preferred first, e.g. <c>["h2", "http/1.1"]</c>. Empty offers
    /// none, which leaves the origin to assume a protocol - fine for HTTP/1.1, never for h2.
    /// </summary>
    public string[] AlpnProtocols { get; init; } = [];

    /// <summary>
    /// Verify the origin's certificate chain and that it matches <see cref="ServerName"/>. Turning
    /// this off accepts any certificate from anyone, so the connection is encrypted but not
    /// authenticated - a machine in the path can read and rewrite everything on it. Only for
    /// self-signed certificates in tests.
    /// </summary>
    public bool VerifyCertificate { get; init; } = true;

    /// <summary>
    /// PEM bundle of trust anchors. Null uses the system store, which is what a public origin
    /// wants; a private CA sets this instead of turning verification off.
    /// </summary>
    public string? CaFile { get; init; }

    /// <summary>
    /// PEM certificate to present when the origin asks for one - mutual TLS. Null (the default)
    /// means no client certificate, and an origin that requires one refuses the handshake.
    ///
    /// Include any intermediates in the file, leaf first: the origin validates the chain we send,
    /// and a leaf-only file works against a store that happens to hold the intermediates while
    /// failing against every other one.
    /// </summary>
    public string? CertificateFile { get; init; }

    /// <summary>
    /// PEM private key for <see cref="CertificateFile"/>. Set both or neither - a certificate is
    /// public, so it is the key that proves the identity is ours.
    /// </summary>
    public string? PrivateKeyFile { get; init; }

    /// <summary>
    /// Lowest TLS version accepted. 1.2 by default because plenty of origins still stop there;
    /// raise it to <c>0x0304</c> for TLS 1.3 only.
    /// </summary>
    public int MinimumVersion { get; init; } = OpenSslVersions.Tls12;

    /// <summary>How long the handshake may take before the connect fails.</summary>
    public int HandshakeTimeoutMs { get; init; } = 10_000;
}

/// <summary>TLS protocol version numbers, so callers need not know the OpenSSL constants.</summary>
public static class OpenSslVersions
{
    public const int Tls12 = 0x0303;
    public const int Tls13 = 0x0304;
}
