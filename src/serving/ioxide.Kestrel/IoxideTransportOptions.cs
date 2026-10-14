using ioxide;

namespace ioxide.Kestrel;

/// <summary>Options for the ioxide Kestrel transport.</summary>
public sealed class IoxideTransportOptions
{
    /// <summary>
    /// Number of ioxide reactors (one io_uring ring + one dedicated thread each), load-balanced by
    /// SO_REUSEPORT. Defaults to the processor count.
    /// </summary>
    public int ReactorCount { get; set; } = Environment.ProcessorCount;

    /// <summary>
    /// Optional hook to customize the ioxide <see cref="ServerConfig"/> (ring depth, recv buffer ring,
    /// write slab, zero-copy send, incremental mode, ...). The listen port and reactor count are always
    /// overridden afterwards by the bound endpoint and <see cref="ReactorCount"/>.
    /// </summary>
    public Func<ServerConfig, ServerConfig>? ConfigureServer { get; set; }

    /// <summary>
    /// Per-reactor startup hook, run on each reactor's own thread before its loop starts - open ring-native
    /// clients here (e.g. <c>PgPool.Start(r, pgOptions)</c>, <c>AssetReader.CreatePool(r, ...)</c>) so DB and
    /// file I/O ride that reactor's ring. Endpoints resolve them via <c>IoxideReactor.Current.GetService&lt;T&gt;()</c>.
    /// </summary>
    public Action<Reactor>? OnReactorStart { get; set; }

    /// <summary>
    /// TLS termination, done in the transport on the listed ports. When set, the reactor runs the
    /// handshake on accept - BoringSSL carries the records both ways unless
    /// <see cref="IoxideTlsOptions.KernelTx"/> opts transmit into the kernel - and hands Kestrel a
    /// plaintext connection with the TLS connection features set, so the endpoint must NOT use
    /// <c>UseHttps()</c>. Null = no TLS (every port is plaintext). See
    /// <see cref="IoxideTlsOptions.Alpn"/> for which protocols a TLS port advertises.
    /// </summary>
    public IoxideTlsOptions? Tls { get; set; }

    /// <summary>
    /// Convenience over assigning <see cref="Tls"/>: terminate TLS on <paramref name="ports"/> with one
    /// certificate/key. Example: <c>o.UseTls("/certs/server.crt", "/certs/server.key", new[] { 8081 });</c>.
    /// </summary>
    public void UseTls(string certificatePath, string keyPath, IEnumerable<int> ports, params string[] alpn)
    {
        var tls = new IoxideTlsOptions
        {
            CertificatePath = certificatePath,
            KeyPath = keyPath,
            Alpn = alpn.Length == 0 ? ["http/1.1"] : alpn,
        };
        foreach (var p in ports)
        {
            tls.Ports.Add(p);
        }
        Tls = tls;
    }
}

/// <summary>TLS termination settings for the ioxide Kestrel transport.</summary>
public sealed class IoxideTlsOptions
{
    /// <summary>PEM certificate chain file.</summary>
    public required string CertificatePath { get; set; }

    /// <summary>PEM private key file.</summary>
    public required string KeyPath { get; set; }

    /// <summary>
    /// Opt into kernel TLS transmit offload. Off by default: BoringSSL encrypts responses in the
    /// send pump, which needs no 'tls' kernel module. See <c>ioxide.tls.TlsOptions.KernelTx</c>
    /// for what the kernel path buys and what it constrains.
    /// </summary>
    public bool KernelTx { get; set; }

    /// <summary>
    /// Protocols to advertise, MOST PREFERRED FIRST. The server walks this list and picks the first
    /// entry the client also offered, so order is the policy - ALPN itself carries no weights.
    /// </summary>
    public string[] Alpn { get; set; } = ["http/1.1"];

    /// <summary>Listen ports that terminate TLS in the transport. Connections on other ports stay plaintext.</summary>
    public HashSet<int> Ports { get; set; } = new();
}
