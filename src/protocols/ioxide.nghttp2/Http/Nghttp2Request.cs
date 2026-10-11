namespace ioxide.nghttp2;

/// <summary>
/// One HTTP/2 request as it arrived: pseudo-headers lifted out, field lines in order, and the body
/// once the stream ended. Bytes throughout - nothing is decoded to string on the way in, because
/// most handlers only ever compare a path or read a header.
///
/// The memories point into an arena owned by the connection and are valid for the duration of the
/// handler call. Copy anything you keep past it.
/// </summary>
public sealed class Nghttp2Request
{
    /// <summary>The stream this arrived on. Odd, client-initiated, and the id a response goes back on.</summary>
    public int StreamId { get; internal set; }

    /// <summary><c>:method</c>.</summary>
    public ReadOnlyMemory<byte> Method { get; internal set; }

    /// <summary><c>:path</c>, query string included.</summary>
    public ReadOnlyMemory<byte> Path { get; internal set; }

    /// <summary><c>:scheme</c> - http or https, per the transport the peer thinks it is on.</summary>
    public ReadOnlyMemory<byte> Scheme { get; internal set; }

    /// <summary><c>:authority</c>, HTTP/2's replacement for the Host header.</summary>
    public ReadOnlyMemory<byte> Authority { get; internal set; }

    /// <summary>Field lines in wire order, names lowercased (HTTP/2 requires it). Repeats kept.</summary>
    public KeyValueList Headers { get; } = new();

    /// <summary>Cookie pairs, which HTTP/2 peers may split across several cookie fields.</summary>
    public CookieEnumerator Cookies => new(Headers);

    /// <summary>First value for a field name, or false when absent. Names are lowercase.</summary>
    public bool TryGetHeader(ReadOnlySpan<byte> name, out ReadOnlyMemory<byte> value)
    {
        foreach (KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> field in Headers.AsSpan())
        {
            if (field.Key.Span.SequenceEqual(name))
            {
                value = field.Value;
                return true;
            }
        }
        value = default;
        return false;
    }

    /// <summary>Request body, empty when there was none - or when it is being streamed.</summary>
    public ReadOnlyMemory<byte> Body { get; internal set; }

    /// <summary>
    /// The body as it arrives, set only when <see cref="Nghttp2Options.StreamRequestBodies"/> is on;
    /// null otherwise, when <see cref="Body"/> already holds it whole. The handler runs while the
    /// body is still coming in, so reading it is what lets the peer send more.
    /// </summary>
    public Nghttp2BodyReader? BodyReader { get; internal set; }
}
