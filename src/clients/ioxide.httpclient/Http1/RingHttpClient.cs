using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace ioxide.httpclient;

/// <summary>
/// HTTP/1.1 to any origin by URL - the shape of .NET's HttpClient, on one reactor's ring. Each origin
/// (scheme, host, port) gets an <see cref="HttpClientPool"/> of its own on first use, whose connections
/// open as requests need them and close once idle; names are resolved, https checks the URL's host,
/// and redirects are followed. One per reactor, from <c>Reactor.OnStart</c>:
///
/// <code>
/// reactor.OnStart = r => RingHttpClient.Start(r);
/// ...
/// var http = reactor.GetService&lt;RingHttpClient&gt;();
/// using HttpClientResponse response = await http.GetAsync("https://www.example.com/");
/// </code>
/// </summary>
/// <remarks>
/// For one upstream on a hot path - a reverse proxy - start an <see cref="HttpClientPool"/> instead:
/// its connections are opened up front and kept, and a request parses no URL. Reactor thread only,
/// like the pool.
/// </remarks>
public sealed class RingHttpClient : IDisposable
{
    private readonly IRingHost _host;
    private readonly RingHttpClientOptions _options;
    private readonly Dictionary<string, HttpClientPool> _origins = new(StringComparer.Ordinal);
    private TlsClientContext? _tls;   // one for every https origin, made for the first
    private bool _disposed;

    private RingHttpClient(IRingHost host, RingHttpClientOptions options)
    {
        _host = host;
        _options = options;
    }

    /// <summary>Create the client and register it as a reactor service.</summary>
    public static RingHttpClient Start(Reactor reactor, RingHttpClientOptions? options = null)
    {
        var client = new RingHttpClient(reactor, options ?? new RingHttpClientOptions());
        reactor.AddService(client);
        reactor.AddTicker(client.Sweep);
        return client;
    }

    /// <summary>Origins with a pool right now (for diagnostics).</summary>
    public int OriginCount => _origins.Count;

    public ValueTask<HttpClientResponse> GetAsync(string url) => SendAsync(url, new HttpClientRequest(HttpMethods.Get, "/"));

    public ValueTask<HttpClientResponse> PostAsync(string url, ReadOnlyMemory<byte> body)
        => SendAsync(url, new HttpClientRequest(HttpMethods.Post, "/") { Body = body });

    /// <summary>
    /// Send <paramref name="request"/> to an absolute http or https URL, which replaces its path, and
    /// follow redirects up to <see cref="RingHttpClientOptions.MaxRedirects"/>. The response owns its
    /// bytes - dispose it.
    /// </summary>
    public async ValueTask<HttpClientResponse> SendAsync(string url, HttpClientRequest request)
    {
        Uri target = Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed) && parsed.Scheme is "http" or "https"
            ? parsed
            : throw new ArgumentException($"'{url}' is not an absolute http or https URL", nameof(url));

        ReadOnlyMemory<byte> method = request.Method;
        ReadOnlyMemory<byte> body = request.Body;
        bool sameOrigin = true;

        for (int redirects = 0; ; redirects++)
        {
            var hop = new HttpClientRequest(method, target.PathAndQuery) { Body = body };
            foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in request.Headers.AsSpan())
            {
                // Credentials stay with the origin they were given for.
                if (sameOrigin || !(field.Key.Span.SequenceEqual("authorization"u8) || field.Key.Span.SequenceEqual("cookie"u8)))
                {
                    hop.Headers.Add(field.Key, field.Value);
                }
            }

            HttpClientResponse response = await PoolFor(target).SendAsync(hop);

            int status = response.Status;
            if (redirects >= _options.MaxRedirects || status is not (301 or 302 or 303 or 307 or 308)
                || !TryGetLocation(response, target, out Uri? next)
                || (target.Scheme == "https" && next.Scheme == "http"))   // never down to cleartext, as .NET
            {
                return response;
            }

            response.Dispose();

            // 303 turns anything but HEAD into a GET; 301 and 302 turn a POST into one, as browsers and
            // .NET do. 307 and 308 keep the method and the body.
            if ((status == 303 && !method.Span.SequenceEqual(HttpMethods.Head))
                || (status is 301 or 302 && method.Span.SequenceEqual(HttpMethods.Post)))
            {
                method = HttpMethods.Get;
                body = default;
            }

            sameOrigin &= Uri.Compare(target, next, UriComponents.SchemeAndServer, UriFormat.Unescaped,
                StringComparison.OrdinalIgnoreCase) == 0;
            target = next;
        }
    }

    // A Location, absolute or relative to the URL that answered.
    private static bool TryGetLocation(HttpClientResponse response, Uri current, [NotNullWhen(true)] out Uri? next)
    {
        next = null;
        return response.TryGetHeader("location"u8, out ReadOnlyMemory<byte> value)
               && Uri.TryCreate(current, Encoding.Latin1.GetString(value.Span).Trim(), out next)
               && next.Scheme is "http" or "https";
    }

    private HttpClientPool PoolFor(Uri url)
    {
        if (_disposed)
        {
            throw new HttpClientException("client is disposed");
        }

        // An IPv6 address goes to the pool bare; a name in its DNS form.
        string host = url.HostNameType == UriHostNameType.IPv6 ? url.DnsSafeHost : url.IdnHost;
        string key = $"{url.Scheme}://{host}:{url.Port}";
        if (!_origins.TryGetValue(key, out HttpClientPool? pool))
        {
            TlsClientContext? tls = url.Scheme == "https"
                ? _tls ??= TlsClientContext.Create((_options.Tls ?? new TlsClientOptions { AlpnProtocols = ["http/1.1"] })
                    with { ServerName = null })
                : null;

            pool = HttpClientPool.CreateOnDemand(_host, _options.Pool with { Host = host, Port = (ushort)url.Port, Tls = tls });
            _origins.Add(key, pool);
        }
        return pool;
    }

    // Each origin's sweep. An origin left with nothing open, opening or waiting is dropped, so the
    // client does not keep a pool for every origin it ever spoke to.
    private void Sweep()
    {
        if (_disposed)
        {
            return;   // AddTicker has no removal API
        }

        foreach ((string key, HttpClientPool pool) in _origins)
        {
            pool.Sweep();
            if (pool.IsUnused)
            {
                _origins.Remove(key);
                pool.Dispose();
            }
        }
    }

    /// <summary>Close every origin's idle connections; requests in flight finish first, as with the pool.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        foreach (HttpClientPool pool in _origins.Values)
        {
            pool.Dispose();
        }
        _origins.Clear();
        _tls?.Dispose();
    }
}
