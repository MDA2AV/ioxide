namespace ioxide.http2;

/// <summary>Per-connection knobs for <see cref="Http2Connection"/>.</summary>
public sealed record Http2Options
{
    /// <summary>
    /// Ceiling on one request's body. A body arrives as a stream of DATA frames with no length known
    /// up front, so this is what bounds the arena a single stream can grow. It stops applying when the
    /// handler takes a body reader - there is no arena for it to bound.
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
    /// that follows it, and on what its blocks decode to.
    ///
    /// <see cref="MaxFrameSize"/> bounds one frame; nothing bounds how many CONTINUATION frames a
    /// peer may send, so without this a HEADERS that never sets END_HEADERS grows the block until
    /// the process dies - the CONTINUATION flood. Exceeding it is a CONNECTION error, not a stream
    /// one, because a block that stops being decoded desynchronises HPACK for everything after it.
    ///
    /// One byte of HPACK can stand for a whole table entry, so the size a block arrives at says little
    /// about what it costs - the HPACK bomb. What it decodes to is measured as RFC 9113 6.5.2 does:
    /// each field's name and value plus 32 bytes, across all of a request's blocks. Past that the
    /// stream is reset with ENHANCE_YOUR_CALM, as a block decoded whole leaves HPACK in step. So a
    /// connection's headers hold at most <see cref="MaxConcurrentStreams"/> times this.
    /// </summary>
    public int MaxHeaderListSize { get; init; } = 64 * 1024;

    /// <summary>
    /// Told of each request whose handler throws, with the request and what it threw. The stack
    /// still ends the request as it would without it: a 500 while its headers are unsent, a reset
    /// stream once they are out. Without one, the fault is written to stderr, as it always was.
    /// </summary>
    /// <remarks>
    /// It runs on the connection's reactor thread, so it must not block, and the request is valid
    /// only until it returns, as it is for the handler. What it throws is dropped: the request
    /// still has to be ended. A handler that cannot finish its response need not throw to have the
    /// stream reset - <see cref="Http2ResponseWriter.AbortAsync"/> does that, and is no fault.
    /// </remarks>
    public Action<Http2Request, Exception>? OnHandlerFault { get; init; }
}
