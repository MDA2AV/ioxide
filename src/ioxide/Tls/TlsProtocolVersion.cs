namespace ioxide.tls;

/// <summary>Lowest TLS version a server will negotiate. See <see cref="TlsOptions.MinProtocolVersion"/>.</summary>
public enum TlsProtocolVersion
{
    /// <summary>Whatever BoringSSL's own floor is - TLS 1.2 on a current build.</summary>
    Default = 0,

    /// <summary>Accept TLS 1.2 and above.</summary>
    Tls12 = 1,

    /// <summary>TLS 1.3 only.</summary>
    Tls13 = 2,
}
