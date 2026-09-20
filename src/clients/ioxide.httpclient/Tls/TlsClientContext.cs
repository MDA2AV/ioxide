using System.Runtime.InteropServices;

namespace ioxide.httpclient;

/// <summary>
/// A configured client SSL_CTX: trust anchors, protocol floor and the ALPN list to offer. One per
/// origin is plenty - it holds no per-connection state, and every <see cref="TlsClientStream"/>
/// opened from it gets its own SSL.
///
/// <code>
/// using var tls = TlsClientContext.Create(new TlsClientOptions
/// {
///     ServerName = "api.example.com",
///     AlpnProtocols = ["h2", "http/1.1"],
/// });
/// </code>
/// </summary>
/// <remarks>
/// This is the client mirror of <see cref="TlsService"/>. It deliberately does NOT use kTLS: the
/// offload there is a server-side trick tied to capturing the traffic secret from the keylog
/// callback and handing transmit to the kernel, which pays off for big responses. A client sends
/// small requests and reads whatever it is given, so both directions stay in userspace.
/// </remarks>
public sealed unsafe class TlsClientContext : IDisposable
{
    private readonly nint _ctx;
    private bool _disposed;

    internal nint Handle => _ctx;

    internal TlsClientOptions Options { get; }

    private TlsClientContext(nint ctx, TlsClientOptions options)
    {
        _ctx = ctx;
        Options = options;
    }

    /// <summary>Build the context. Throws if OpenSSL rejects any of the configuration.</summary>
    public static TlsClientContext Create(TlsClientOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ServerName))
        {
            throw new ArgumentException(
                "ServerName is required: it is both the SNI sent and the name the certificate is checked against.",
                nameof(options));
        }

        nint ctx = OpenSsl.SSL_CTX_new(OpenSsl.TLS_client_method());
        if (ctx == 0)
        {
            throw new IOException($"SSL_CTX_new: {OpenSsl.LastError()}");
        }

        try
        {
            // Checked, because ssl3_ctx_ctrl returns 0 for a version it will not accept and applies
            // NOTHING - silently, with no error queued. A caller pinning a floor got OpenSSL's
            // default instead and no way to find out.
            if (OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_SET_MIN_PROTO_VERSION, options.MinimumVersion, 0) != 1)
            {
                throw new IOException(
                    $"set_min_proto_version({options.MinimumVersion:X}): OpenSSL refused the version.");
            }

            ConfigureVerification(ctx, options);
            ConfigureClientCertificate(ctx, options);
            ConfigureAlpn(ctx, options);

            return new TlsClientContext(ctx, options);
        }
        catch
        {
            OpenSsl.SSL_CTX_free(ctx);
            throw;
        }
    }

    private static void ConfigureVerification(nint ctx, TlsClientOptions options)
    {
        if (!options.VerifyCertificate)
        {
            // Encrypted but unauthenticated: anything in the path can present its own certificate
            // and read or rewrite the whole connection. TlsClientOptions documents the one case
            // this is for.
            OpenSsl.SSL_CTX_set_verify(ctx, OpenSsl.SSL_VERIFY_NONE, 0);
            return;
        }

        // SSL_VERIFY_PEER with no callback makes a failed chain fail the handshake outright, which
        // is what we want - there is no prompt to fall back to.
        OpenSsl.SSL_CTX_set_verify(ctx, OpenSsl.SSL_VERIFY_PEER, 0);

        int loaded = options.CaFile is { } caFile
            ? OpenSsl.SSL_CTX_load_verify_locations(ctx, caFile, null)
            : OpenSsl.SSL_CTX_set_default_verify_paths(ctx);

        if (loaded != 1)
        {
            string source = options.CaFile ?? "the system trust store";
            throw new IOException($"could not load trust anchors from {source}: {OpenSsl.LastError()}");
        }
    }

    /// <summary>
    /// Load the certificate this client presents when an origin asks for one.
    /// </summary>
    /// <remarks>
    /// Nothing here arms anything: TLS client authentication is driven by the SERVER sending a
    /// CertificateRequest. Loading a certificate only means we have an answer ready, so configuring
    /// this against an origin that never asks costs a file read and changes no handshake.
    /// </remarks>
    private static void ConfigureClientCertificate(nint ctx, TlsClientOptions options)
    {
        if (options.CertificateFile is null && options.PrivateKeyFile is null)
        {
            return;
        }

        if (options.CertificateFile is null || options.PrivateKeyFile is null)
        {
            throw new ArgumentException(
                "set both CertificateFile and PrivateKeyFile, or neither: a certificate without its key "
                + "proves nothing, and a key without its certificate has nothing to present.",
                nameof(options));
        }

        if (OpenSsl.SSL_CTX_use_certificate_chain_file(ctx, options.CertificateFile) != 1)
        {
            throw new IOException(
                $"could not load client certificate '{options.CertificateFile}': {OpenSsl.LastError()}");
        }

        if (OpenSsl.SSL_CTX_use_PrivateKey_file(ctx, options.PrivateKeyFile, OpenSsl.SSL_FILETYPE_PEM) != 1)
        {
            throw new IOException(
                $"could not load client private key '{options.PrivateKeyFile}': {OpenSsl.LastError()}");
        }

        // Catch a mismatched pair here rather than during a handshake, where it surfaces as an
        // opaque failure against a specific origin.
        if (OpenSsl.SSL_CTX_check_private_key(ctx) != 1)
        {
            throw new IOException(
                $"client private key '{options.PrivateKeyFile}' does not match certificate "
                + $"'{options.CertificateFile}': {OpenSsl.LastError()}");
        }
    }

    private static void ConfigureAlpn(nint ctx, TlsClientOptions options)
    {
        if (options.AlpnProtocols.Length == 0)
        {
            return;
        }

        byte[] wire = BuildAlpnWire(options.AlpnProtocols);
        int result;
        fixed (byte* p = wire)
        {
            result = OpenSsl.SSL_CTX_set_alpn_protos(ctx, p, (uint)wire.Length);
        }

        // Inverted against every other function here: this one returns 0 for success.
        if (result != 0)
        {
            throw new IOException($"SSL_CTX_set_alpn_protos: {OpenSsl.LastError()}");
        }
    }

    /// <summary>Protocols as ALPN wants them: each one a length byte followed by its ASCII name.</summary>
    internal static byte[] BuildAlpnWire(string[] protocols)
    {
        int total = 0;
        foreach (string protocol in protocols)
        {
            if (protocol.Length is 0 or > 255)
            {
                throw new ArgumentException($"ALPN protocol '{protocol}' must be 1..255 bytes.", nameof(protocols));
            }
            total += 1 + protocol.Length;
        }

        var wire = new byte[total];
        int cursor = 0;
        foreach (string protocol in protocols)
        {
            wire[cursor++] = (byte)protocol.Length;
            for (int i = 0; i < protocol.Length; i++)
            {
                wire[cursor++] = (byte)protocol[i];
            }
        }
        return wire;
    }

    /// <summary>
    /// Open a TLS connection over an already-connected ring socket. The stream takes ownership of
    /// the socket and closes it on dispose.
    /// </summary>
    public ValueTask<TlsClientStream> ConnectAsync(RingSocket socket)
        => TlsClientStream.HandshakeAsync(socket, this);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        OpenSsl.SSL_CTX_free(_ctx);
    }
}
