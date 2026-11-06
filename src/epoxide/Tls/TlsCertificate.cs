namespace epoxide.tls;

/// <summary>
/// One certificate and its key, in whichever form the caller holds them - the entry
/// <see cref="TlsOptions.CertificatesByHost"/> is made of.
/// </summary>
/// <remarks>
/// The same either-or as <see cref="TlsOptions"/> itself: exactly one source for the certificate
/// and exactly one for the key, checked when the service starts rather than at the handshake, where
/// a misconfiguration would show up as a failed connection.
/// </remarks>
public sealed class TlsCertificate
{
    /// <summary>PEM certificate chain file. Exactly one of this and <see cref="CertificatePem"/>.</summary>
    public string? CertificatePath { get; init; }

    /// <summary>PEM private key file. Exactly one of this and <see cref="KeyPem"/>.</summary>
    public string? KeyPath { get; init; }

    /// <summary>The certificate chain as PEM text, leaf first.</summary>
    public string? CertificatePem { get; init; }

    /// <summary>The private key as PEM text.</summary>
    public string? KeyPem { get; init; }
}
