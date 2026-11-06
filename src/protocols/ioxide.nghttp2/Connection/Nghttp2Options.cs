namespace ioxide.nghttp2;

/// <summary>Per-connection knobs for <see cref="Nghttp2Connection"/>.</summary>
public sealed record Nghttp2Options
{
    /// <summary>
    /// Ceiling on one request's body. A body arrives as a stream of DATA frames with no length known
    /// up front, so this is what bounds the arena a single stream can grow. It stops applying when the
    /// handler takes a body reader - there is no arena for it to bound.
    /// </summary>
    public int MaxRequestBytes { get; init; } = 8 * 1024 * 1024;

    /// <summary>
    /// Ceiling on what one request's header blocks decode to, measured as RFC 9113 6.5.2 does: each
    /// field's name and value plus 32 bytes. nghttp2 bounds the blocks it reads, but one byte of HPACK can
    /// stand for a whole table entry - the HPACK bomb. Past this the stream is reset with
    /// ENHANCE_YOUR_CALM, never dispatched.
    /// </summary>
    public int MaxHeaderListSize { get; init; } = 64 * 1024;
}
