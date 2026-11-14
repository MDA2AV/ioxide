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

    /// <summary>
    /// Flow-control window advertised per stream, and enforced by nghttp2: how much of one request's
    /// body the peer may send ahead of the credit the server gives back. nghttp2 answers a DATA frame
    /// past it by ending the connection with FLOW_CONTROL_ERROR, which RFC 9113 6.9 allows as well as
    /// a stream error. A buffered body is credited as it arrives, a streamed one as its handler reads
    /// it, so a handler that stops reading holds one window and stalls only its own upload.
    ///
    /// The connection's own window is opened to 2^31-1 right behind the server's SETTINGS, and nghttp2
    /// tops it up once half of it is consumed, so what bounds a connection's request bodies in flight
    /// is <see cref="MaxConcurrentStreams"/> times this. nghttp2 holds a stream to it once the peer
    /// has acknowledged the SETTINGS, and to the RFC's 65,535 until then.
    /// </summary>
    public int InitialWindowSize { get; init; } = 256 * 1024;

    /// <summary>
    /// Streams the peer may have open at once, advertised in SETTINGS and enforced by nghttp2. It also
    /// bounds a connection's request bodies in flight: this many streams times
    /// <see cref="InitialWindowSize"/>, since the connection's window is not the limit.
    /// </summary>
    public int MaxConcurrentStreams { get; init; } = 100;
}
