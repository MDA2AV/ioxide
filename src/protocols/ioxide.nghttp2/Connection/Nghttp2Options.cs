namespace ioxide.nghttp2;

/// <summary>Per-connection knobs for <see cref="Nghttp2Connection"/>.</summary>
public sealed record Nghttp2Options
{
    /// <summary>
    /// Ceiling on one request's headers plus body. nghttp2 enforces its own frame and header-list
    /// limits, but a body arrives as a stream of DATA frames with no length known up front, so
    /// this is what bounds the arena a single stream can grow.
    /// </summary>
    public int MaxRequestBytes { get; init; } = 8 * 1024 * 1024;

    /// <summary>
    /// Dispatch each request as soon as its HEADERS are in, with the body arriving through
    /// <see cref="Nghttp2Request.BodyReader"/> instead of assembled into
    /// <see cref="Nghttp2Request.Body"/>.
    ///
    /// The trade is what memory is bound by. Buffered holds the whole body, which suits ordinary
    /// requests and not hostile uploads; streamed holds one flow-control window, because credit is
    /// only returned to the peer as the handler reads. <see cref="MaxRequestBytes"/> stops applying
    /// to the body when this is on - there is no arena for it to bound.
    /// </summary>
    public bool StreamRequestBodies { get; init; }
}
