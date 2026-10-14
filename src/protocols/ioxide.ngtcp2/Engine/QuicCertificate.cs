namespace ioxide.ngtcp2;

/// <summary>
/// One certificate chain and its key, as paths to PEM files - what a host in
/// <see cref="QuicEngine.ReplaceCertificates"/> is made of.
/// </summary>
/// <remarks>
/// Paths and nothing else, for the same reason the constructor takes them: ngtcp2 loads PEM by
/// path. The TCP side accepts either paths or PEM text because BoringSSL takes the certificate as
/// data; here there is only the one form.
/// </remarks>
/// <param name="CertificatePath">
/// The certificate, leaf first. Any intermediates in the same file are sent with it, which is how a
/// client reaches a root it trusts - a file holding the leaf alone serves only clients that already
/// have the rest.
/// </param>
/// <param name="KeyPath">The private key, PEM, matching the certificate.</param>
public sealed record QuicCertificate(string CertificatePath, string KeyPath);
