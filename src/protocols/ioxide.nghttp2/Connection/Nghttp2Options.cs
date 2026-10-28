namespace ioxide.nghttp2;

/// <summary>Per-connection knobs for <see cref="Nghttp2Connection"/>.</summary>
public sealed record Nghttp2Options
{
    /// <summary>
    /// Ceiling on one request's headers plus body. nghttp2 enforces its own frame and header-list
    /// limits, but a body arrives as a stream of DATA frames with no length known up front, so
    /// this is what bounds the arena a single stream can grow. It stops applying to the body when the
    /// handler takes a body reader - there is no arena for it to bound.
    /// </summary>
    public int MaxRequestBytes { get; init; } = 8 * 1024 * 1024;
}
