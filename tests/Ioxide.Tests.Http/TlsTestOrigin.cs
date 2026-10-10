using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Ioxide.Tests;

/// <summary>
/// A TLS origin for the client tests: a plain TcpListener wrapped in the BCL's SslStream, speaking
/// just enough HTTP/1.1 to answer a request.
///
/// Deliberately not one of our own servers. ioxide's TLS termination hands transmit to the kernel
/// via kTLS, so it cannot run without the 'tls' module - and testing our client against our own
/// handshake would only prove the two agree with each other. SslStream is an independent
/// implementation, in-process, with no sidecar to install.
/// </summary>
internal sealed class TlsTestOrigin : IDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2 _certificate;
    private readonly List<SslApplicationProtocol> _alpn;
    private readonly CancellationTokenSource _stopping = new();
    private X509Certificate2? _clientCa { get; init; }

    /// <summary>The port it accepted on.</summary>
    public int Port { get; }

    /// <summary>ALPN protocol selected on the most recent handshake, for assertions.</summary>
    public string? LastAlpn { get; private set; }

    /// <summary>When true, a client that presents no certificate is refused at the handshake.</summary>
    public bool RequireClientCertificate { get; init; }

    /// <summary>
    /// Subject of the client certificate on the most recent handshake, or null if none was
    /// presented. Proves the identity actually crossed the wire rather than the handshake merely
    /// succeeding.
    /// </summary>
    public string? LastClientSubject { get; private set; }

    /// <summary>
    /// When true, each connection ends after its first response - close_notify, then the FIN - the
    /// way a keep-alive timeout ends a connection the client still holds.
    /// </summary>
    public bool CloseAfterResponse { get; set; }

    /// <summary>The client's port on the most recent connection, which names its socket.</summary>
    public int LastClientPort { get; private set; }

    private TlsTestOrigin(TcpListener listener, X509Certificate2 certificate, string[] alpn)
    {
        _listener = listener;
        _certificate = certificate;
        _alpn = [.. alpn.Select(p => new SslApplicationProtocol(p))];
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// Start an origin that demands a client certificate, signed by <paramref name="clientCaPath"/>.
    /// </summary>
    public static TlsTestOrigin StartMutual(string clientCaPath, params string[] alpn)
        => StartCore(alpn, clientCaPath);

    /// <summary>Start an origin offering <paramref name="alpn"/>, most preferred first.</summary>
    public static TlsTestOrigin Start(params string[] alpn) => StartCore(alpn, clientCaPath: null);

    private static TlsTestOrigin StartCore(string[] alpn, string? clientCaPath)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        X509Certificate2 certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);

        // SslStream on Linux needs the private key associated through a PFX round-trip; a PEM-built
        // certificate carries the key in a form AuthenticateAsServerAsync will not use directly.
        certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var origin = new TlsTestOrigin(listener, certificate, alpn)
        {
            RequireClientCertificate = clientCaPath is not null,
            // CreateFromPemFile wants the private key alongside; a CA certificate is public and
            // has none, so parse the certificate on its own.
            _clientCa = clientCaPath is null
                ? null
                : X509Certificate2.CreateFromPem(File.ReadAllText(clientCaPath)),
        };

        _ = origin.AcceptLoopAsync();
        return origin;
    }

    /// <summary>
    /// Accept only certificates that chain to the CA this origin was started with. Built fresh per
    /// handshake so the trust decision is exactly "signed by that CA" and nothing else.
    /// </summary>
    private bool ValidateClientCertificate(
        object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null || _clientCa is null)
        {
            return false;
        }

        using var built = new X509Chain();
        built.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        built.ChainPolicy.CustomTrustStore.Add(_clientCa);
        built.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        return built.Build(new X509Certificate2(certificate));
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stopping.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stopping.Token);
            }
            catch
            {
                return;   // stopped
            }

            _ = ServeAsync(client);
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            LastClientPort = ((IPEndPoint)client.Client.RemoteEndPoint!).Port;

            SslStream? tls = null;
            try
            {
                tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    ApplicationProtocols = _alpn,
                    ClientCertificateRequired = RequireClientCertificate,

                    // Only consult the CA we were given: the machine store must not be able to
                    // make an unrelated certificate acceptable, or the test proves nothing.
                    RemoteCertificateValidationCallback = RequireClientCertificate
                        ? ValidateClientCertificate
                        : null,
                });

                LastAlpn = tls.NegotiatedApplicationProtocol.Protocol.Length == 0
                    ? null
                    : tls.NegotiatedApplicationProtocol.ToString();

                LastClientSubject = tls.RemoteCertificate is { } peer
                    ? new X509Certificate2(peer).Subject
                    : null;

                var request = new byte[8192];
                while (true)
                {
                    int n = await tls.ReadAsync(request, _stopping.Token);
                    if (n == 0)
                    {
                        return;   // peer closed
                    }

                    string body = $"hello over {LastAlpn ?? "tls"}";
                    byte[] response = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\n" +
                        $"content-length: {body.Length}\r\n" +
                        "content-type: text/plain\r\n\r\n" +
                        body);

                    await tls.WriteAsync(response, _stopping.Token);

                    if (CloseAfterResponse)
                    {
                        await tls.ShutdownAsync();
                        return;
                    }
                }
            }
            catch
            {
                // A rejected certificate or a client that walked away mid-handshake is the POINT of
                // several tests, so a failure here is data rather than an error to report.
            }
            finally
            {
                tls?.Dispose();
            }
        }
    }

    public void Dispose()
    {
        _stopping.Cancel();
        _listener.Stop();
        _certificate.Dispose();
        _stopping.Dispose();
    }
}
