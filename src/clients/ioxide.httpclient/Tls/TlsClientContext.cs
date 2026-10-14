using System.Runtime.InteropServices;

namespace ioxide.httpclient;

/// <summary>
/// A configured client SSL_CTX: trust anchors, protocol floor and the ALPN list to offer. One is
/// plenty for any number of origins - it holds no per-connection state, every <see cref="TlsClientStream"/>
/// opened from it gets its own SSL, and the name to verify comes per connection unless
/// <see cref="TlsClientOptions.ServerName"/> pins it.
///
/// <code>
/// using var tls = TlsClientContext.Create(new TlsClientOptions
/// {
///     AlpnProtocols = ["h2", "http/1.1"],
/// });
/// </code>
/// </summary>
/// <remarks>
/// This is the client mirror of <see cref="ioxide.tls.TlsService"/>. It deliberately does NOT use kTLS: the
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

    /// <summary>Build the context. Throws if BoringSSL rejects any of the configuration.</summary>
    public static TlsClientContext Create(TlsClientOptions options)
    {
        if (options.ServerName is { } name && string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException(
                "ServerName is blank: it is both the SNI sent and the name the certificate is checked against.",
                nameof(options));
        }

        nint ctx = BoringSsl.SSL_CTX_new(BoringSsl.TLS_client_method());
        if (ctx == 0)
        {
            throw new IOException($"SSL_CTX_new: {BoringSsl.LastError()}");
        }

        try
        {
            // Checked, because a version the library will not accept leaves its default floor in
            // place, and a caller pinning one would have no way to find out. The range check comes
            // first: the int would otherwise wrap into a ushort that happens to be a version.
            if (options.MinimumVersion is < 0 or > ushort.MaxValue ||
                BoringSsl.SSL_CTX_set_min_proto_version(ctx, (ushort)options.MinimumVersion) != 1)
            {
                throw new IOException(
                    $"set_min_proto_version({options.MinimumVersion:X}): BoringSSL refused the version.");
            }

            ConfigureVerification(ctx, options);
            ConfigureClientCertificate(ctx, options);
            ConfigureAlpn(ctx, options);

            return new TlsClientContext(ctx, options);
        }
        catch
        {
            BoringSsl.SSL_CTX_free(ctx);
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
            BoringSsl.SSL_CTX_set_verify(ctx, BoringSsl.SSL_VERIFY_NONE, 0);
            return;
        }

        // SSL_VERIFY_PEER with no callback makes a failed chain fail the handshake outright, which
        // is what we want - there is no prompt to fall back to.
        BoringSsl.SSL_CTX_set_verify(ctx, BoringSsl.SSL_VERIFY_PEER, 0);

        int loaded = options.CaFile is { } caFile
            ? BoringSsl.SSL_CTX_load_verify_locations(ctx, caFile, null)
            : BoringSsl.SSL_CTX_set_default_verify_paths(ctx);

        if (loaded != 1)
        {
            string source = options.CaFile ?? "the system trust store";
            throw new IOException($"could not load trust anchors from {source}: {BoringSsl.LastError()}");
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

        if (BoringSsl.SSL_CTX_use_certificate_chain_file(ctx, options.CertificateFile) != 1)
        {
            throw new IOException(
                $"could not load client certificate '{options.CertificateFile}': {BoringSsl.LastError()}");
        }

        if (BoringSsl.SSL_CTX_use_PrivateKey_file(ctx, options.PrivateKeyFile, BoringSsl.SSL_FILETYPE_PEM) != 1)
        {
            throw new IOException(
                $"could not load client private key '{options.PrivateKeyFile}': {BoringSsl.LastError()}");
        }

        // Catch a mismatched pair here rather than during a handshake, where it surfaces as an
        // opaque failure against a specific origin.
        if (BoringSsl.SSL_CTX_check_private_key(ctx) != 1)
        {
            throw new IOException(
                $"client private key '{options.PrivateKeyFile}' does not match certificate "
                + $"'{options.CertificateFile}': {BoringSsl.LastError()}");
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
            result = BoringSsl.SSL_CTX_set_alpn_protos(ctx, p, (nuint)wire.Length);
        }

        // Inverted against every other function here: this one returns 0 for success.
        if (result != 0)
        {
            throw new IOException($"SSL_CTX_set_alpn_protos: {BoringSsl.LastError()}");
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
            // Each char goes out as one byte, so any other name would be offered as a different protocol.
            if (!System.Text.Ascii.IsValid(protocol))
            {
                throw new ArgumentException($"ALPN protocol '{protocol}' must be ASCII.", nameof(protocols));
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
        => ConnectAsync(socket, Options.ServerName ?? throw new InvalidOperationException(
            "no ServerName to verify the origin against: set TlsClientOptions.ServerName, or pass the name"));

    /// <summary>As <see cref="ConnectAsync(RingSocket)"/>, verifying the origin as
    /// <paramref name="serverName"/>.</summary>
    public ValueTask<TlsClientStream> ConnectAsync(RingSocket socket, string serverName)
        => TlsClientStream.HandshakeAsync(socket, this, serverName);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        BoringSsl.SSL_CTX_free(_ctx);
    }
}
