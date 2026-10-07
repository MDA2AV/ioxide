namespace ioxide.httpclient;

/// <summary>Method tokens as wire bytes, so a request costs no string encoding.</summary>
public static class HttpMethods
{
    public static readonly byte[] Get    = "GET"u8.ToArray();
    public static readonly byte[] Head   = "HEAD"u8.ToArray();
    public static readonly byte[] Post   = "POST"u8.ToArray();
    public static readonly byte[] Put    = "PUT"u8.ToArray();
    public static readonly byte[] Patch  = "PATCH"u8.ToArray();
    public static readonly byte[] Delete = "DELETE"u8.ToArray();
}

/// <summary>
/// One outgoing HTTP/1.1 request - bytes throughout, mirroring the server-side surface. Reusable:
/// build one per route and send it repeatedly, or keep a static instance for a hot path (nothing
/// is retained after <see cref="HttpClientPool.SendAsync"/> returns).
///
/// <c>host</c>, <c>content-length</c> and <c>connection</c> are written by the client - don't add
/// them here. A CR, LF or NUL in the method, path or a field is refused with an ArgumentException.
/// </summary>
public sealed class HttpClientRequest
{
    /// <summary>Method token, e.g. <see cref="HttpMethods.Get"/>.</summary>
    public ReadOnlyMemory<byte> Method { get; init; } = HttpMethods.Get;

    /// <summary>Request target, e.g. <c>"/api/things?id=7"u8</c>. Must start with '/'.</summary>
    public ReadOnlyMemory<byte> Path { get; init; }

    /// <summary>Extra field lines to send. Names should be lowercase; values are raw octets.</summary>
    public KeyValueList Headers { get; } = new();

    /// <summary>Request body; empty for GET/HEAD/DELETE. content-length is emitted automatically
    /// whenever this is non-empty.</summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    public HttpClientRequest() { }

    /// <summary>Convenience for the common shape: a method and a path.</summary>
    public HttpClientRequest(ReadOnlyMemory<byte> method, ReadOnlyMemory<byte> path)
    {
        Method = method;
        Path = path;
    }

    /// <summary>Convenience for call sites that have a string path (encodes it once - prefer the
    /// byte overload with a <c>u8</c> literal on hot paths).</summary>
    public HttpClientRequest(ReadOnlyMemory<byte> method, string path)
        : this(method, System.Text.Encoding.ASCII.GetBytes(path))
    {
    }
}
