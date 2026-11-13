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

    /// <summary>
    /// Flow-control window advertised per stream: how much of one request's body the peer may send
    /// ahead of the credit it gets back. A stream needs room in the connection's window too,
    /// <see cref="InitialConnectionWindowSize"/>, which at its default holds every stream to 64 KiB.
    /// </summary>
    public int InitialWindowSize { get; init; } = 1 << 20;

    /// <summary>
    /// Flow-control window for the whole connection: how much request body all its streams together
    /// may have in flight. SETTINGS cannot carry it - INITIAL_WINDOW_SIZE sizes streams only - so a
    /// size past the RFC's 65,535 is opened by a WINDOW_UPDATE on stream 0 right behind them. Floored
    /// at 65,535, which is also the default: the uploads of a connection then move 64 KiB a round trip
    /// between them, whatever <see cref="InitialWindowSize"/> says.
    ///
    /// Raise it with the transport. While the frame loop waits on a flush - a response going out to a
    /// slow peer, or a streamed writer's turn - it reads nothing, and what the peer sends meanwhile
    /// waits in the connection's receive queue: an entry per receive, and a receive can be a single
    /// segment of some 1.4 KiB. A queue that overflows closes the connection, so a window the queue
    /// cannot hold lets a peer that keeps to that window be cut off. The default
    /// <see cref="TcpOptions.RecvQueueEntries"/>, 64, holds about the RFC's window; 1 MiB needs 1024.
    /// Under <see cref="ServerConfig.Incremental"/> a connection whose ring is full parks its receive
    /// instead.
    ///
    /// A streamed body is credited only as its handler reads, so a handler that has stopped reading
    /// keeps up to one stream window of this: at twice <see cref="InitialWindowSize"/> the other
    /// streams still have a whole one, where at one they all wait for it. It is also what bounds
    /// memory: the streamed bodies of one connection hold at most this between them. A buffered body
    /// is credited as it arrives, so for one this paces the upload and bounds nothing.
    /// </summary>
    public int InitialConnectionWindowSize { get; init; } = 65535;

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
}
