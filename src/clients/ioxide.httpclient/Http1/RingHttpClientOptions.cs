namespace ioxide.httpclient;

/// <summary>How a <see cref="RingHttpClient"/> reaches the origins its URLs name.</summary>
public sealed record RingHttpClientOptions
{
    /// <summary>
    /// The pool each origin gets, opened on first use. <see cref="HttpClientOptions.Host"/>,
    /// <see cref="HttpClientOptions.Port"/> and <see cref="HttpClientOptions.Tls"/> come from the URL;
    /// the rest applies to every origin. Connections open as requests need them, up to
    /// <see cref="HttpClientOptions.PoolSize"/> per origin, so a high ceiling costs nothing until used.
    /// </summary>
    public HttpClientOptions Pool { get; init; } = new() { PoolSize = 64 };

    /// <summary>
    /// TLS for https origins: one context for all of them, each connection verified against its URL's
    /// host, so <see cref="TlsClientOptions.ServerName"/> is ignored. Null verifies against the system
    /// trust store and offers http/1.1.
    /// </summary>
    public TlsClientOptions? Tls { get; init; }

    /// <summary>Redirects followed before the last one is returned as the response; 0 follows none.
    /// .NET's HttpClient follows 50.</summary>
    public int MaxRedirects { get; init; } = 50;
}
