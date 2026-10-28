namespace ioxide.http2;

/// <summary>Per-connection knobs for <see cref="Http2Connection"/>.</summary>
public sealed record Http2Options
{
    /// <summary>
    /// Ceiling on one request's headers plus body. A body arrives as a stream of DATA frames with
    /// no length known up front, so this is what bounds the arena a single stream can grow. It stops
    /// applying to the body when the handler takes a body reader - there is no arena for it to bound.
    /// </summary>
    public int MaxRequestBytes { get; init; } = 8 * 1024 * 1024;

    /// <summary>Largest frame payload we will accept, and advertise. RFC 9113 floor is 16384.</summary>
    public int MaxFrameSize { get; init; } = 16384;

    /// <summary>Flow-control window advertised per stream.</summary>
    public int InitialWindowSize { get; init; } = 1 << 20;

    /// <summary>
    /// Streams the peer may have open at once. Advertised in SETTINGS <em>and</em> enforced: past
    /// this, a new stream is refused with REFUSED_STREAM rather than allocated. It was advisory
    /// once, which made "open a stream, reset it, repeat" (CVE-2023-44487) cost the server an
    /// arena per cycle and the peer nothing.
    /// </summary>
    public int MaxConcurrentStreams { get; init; } = 1000;

    /// <summary>
    /// Ceiling on one request's header block, accumulated across HEADERS and every CONTINUATION
    /// that follows it.
    ///
    /// <see cref="MaxFrameSize"/> bounds one frame; nothing bounds how many CONTINUATION frames a
    /// peer may send, so without this a HEADERS that never sets END_HEADERS grows the block until
    /// the process dies - the CONTINUATION flood. Exceeding it is a CONNECTION error, not a stream
    /// one, because a block that stops being decoded desynchronises HPACK for everything after it.
    /// </summary>
    public int MaxHeaderListSize { get; init; } = 64 * 1024;
}
