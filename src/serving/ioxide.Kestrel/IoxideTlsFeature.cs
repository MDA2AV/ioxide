using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using ioxide.tls;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;

namespace ioxide.Kestrel;

/// <summary>
/// The TLS connection features Kestrel reads when a connection is already TLS-terminated by the transport
/// (kTLS via ioxide.tls) instead of by <c>UseHttps()</c>/SslStream. Setting these on the
/// <see cref="IoxideConnectionContext"/> makes Kestrel treat the connection as HTTPS (scheme, IsHttps) and
/// pick the application protocol from ALPN.
///
/// These values are READ from the session rather than assumed. Pinned constants (TLS 1.3,
/// AES-128-GCM-SHA256, no client certificate) held only while kTLS-TX was the default; once it became
/// opt-in, a TLS 1.2 or ChaCha20 connection was policy-checked as TLS 1.3 AES-128, and a permanently
/// null ClientCertificate made certificate authentication deny every verified peer.
/// </summary>
internal sealed class IoxideTlsFeature : ITlsConnectionFeature, ITlsHandshakeFeature, ITlsApplicationProtocolFeature
{
    private readonly TlsSession? _session;
    private X509Certificate2? _clientCertificate;
    private bool _clientCertificateRead;

    public IoxideTlsFeature(ReadOnlyMemory<byte> applicationProtocol, TlsSession? session = null)
    {
        ApplicationProtocol = applicationProtocol;
        _session = session;
    }

    // ITlsApplicationProtocolFeature - the negotiated ALPN.
    public ReadOnlyMemory<byte> ApplicationProtocol { get; }

    /// <summary>
    /// The verified client certificate, or null when the peer presented none. Materialised on first
    /// read: a server not doing mutual TLS never parses one, and a server that is pays for it once.
    /// </summary>
    public X509Certificate2? ClientCertificate
    {
        get
        {
            if (_clientCertificateRead)
            {
                return _clientCertificate;
            }

            _clientCertificateRead = true;
            byte[]? der = _session?.PeerCertificateDer;
            if (der is not null)
            {
                _clientCertificate = X509CertificateLoader.LoadCertificate(der);
            }

            return _clientCertificate;
        }
        set
        {
            _clientCertificateRead = true;
            _clientCertificate = value;
        }
    }

    public Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken)
        => Task.FromResult(ClientCertificate);

    // ITlsHandshakeFeature. NegotiatedCipherSuite is the modern accessor; the legacy
    // CipherAlgorithm/HashAlgorithm/KeyExchangeAlgorithm (+ *Strength) properties are obsolete
    // (SYSLIB0058) but still required interface members, so implement and suppress the warning.
    public SslProtocols Protocol => _session?.NegotiatedProtocolVersion switch
    {
        0x0304 => SslProtocols.Tls13,
        0x0303 => SslProtocols.Tls12,
        _ => SslProtocols.None,
    };

    // OpenSSL reports the suite by its IANA id, which is exactly how TlsCipherSuite is numbered.
    public TlsCipherSuite NegotiatedCipherSuite => (TlsCipherSuite)(_session?.NegotiatedCipherSuiteId ?? 0);
    public string HostName => string.Empty;
#pragma warning disable SYSLIB0058 // legacy ITlsHandshakeFeature cipher properties are obsolete but required
    public CipherAlgorithmType CipherAlgorithm => CipherAlgorithmType.Aes128;
    public int CipherStrength => 128;
    public HashAlgorithmType HashAlgorithm => HashAlgorithmType.Sha256;
    public int HashStrength => 256;
    public ExchangeAlgorithmType KeyExchangeAlgorithm => ExchangeAlgorithmType.None;
    public int KeyExchangeStrength => 0;
#pragma warning restore SYSLIB0058
}
