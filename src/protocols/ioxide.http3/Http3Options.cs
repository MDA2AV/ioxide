namespace ioxide.http3;

/// <summary>Per-connection knobs for <see cref="Http3Connection"/>.</summary>
public sealed record Http3Options
{
    internal static readonly Http3Options Default = new();

    /// <summary>
    /// Ceiling on one request's body when it is assembled whole. An upload arrives as DATA frames
    /// with no length known up front, so this is what bounds the buffer a single stream can grow: a
    /// body past it is reset with H3_EXCESSIVE_LOAD and never dispatched. It does not apply when the
    /// handler takes a body reader, where one flow-control window bounds the memory instead.
    /// </summary>
    public int MaxRequestBytes { get; init; } = 8 * 1024 * 1024;
}
