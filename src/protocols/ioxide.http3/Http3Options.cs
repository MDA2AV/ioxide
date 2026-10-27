namespace ioxide.http3;

/// <summary>Per-connection knobs for <see cref="Http3Connection"/>.</summary>
public sealed record Http3Options
{
    /// <summary>
    /// Dispatch each request as soon as its HEADERS are in, with the body arriving through
    /// <see cref="Http3Request.BodyReader"/> instead of assembled into
    /// <see cref="Http3Request.Body"/>.
    ///
    /// The trade is what memory is bound by. Buffered holds the whole body; streamed holds one
    /// flow-control window, because the stream is paced and credit goes back to the peer only as
    /// the handler reads.
    /// </summary>
    public bool StreamRequestBodies { get; init; }
}
