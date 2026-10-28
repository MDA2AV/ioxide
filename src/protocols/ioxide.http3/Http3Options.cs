namespace ioxide.http3;

/// <summary>Per-connection knobs for <see cref="Http3Connection"/>.</summary>
public sealed record Http3Options
{
    internal static readonly Http3Options Default = new();

    /// <summary>
    /// Ceiling on one request's body when it is assembled whole. An upload arrives as DATA frames
    /// with no length known up front, so this is what bounds the buffer a single stream can grow: a
    /// body past it is reset with H3_EXCESSIVE_LOAD and never dispatched. It does not apply with
    /// <see cref="StreamRequestBodies"/>, where one flow-control window bounds the memory instead.
    /// </summary>
    public int MaxRequestBytes { get; init; } = 8 * 1024 * 1024;

    /// <summary>
    /// Dispatch each request as soon as its HEADERS are in, with the body arriving through
    /// <see cref="Http3Request.BodyReader"/> instead of assembled into <see cref="Http3Request.Body"/>.
    ///
    /// The trade is what memory is bound by. Buffered holds the whole body, which suits ordinary
    /// requests and not hostile uploads; streamed holds one flow-control window, because the request
    /// stream is paced and credit is only returned to the peer as the handler reads.
    ///
    /// It applies to the handlers that can await a body: the asynchronous
    /// <see cref="Http3Connection.RunBufferedAsync(Func{Http3Request, ValueTask{Http3Response}})"/> and
    /// <see cref="Http3Connection.RunStreamedResponseAsync"/>. A synchronous handler always gets the
    /// whole body.
    /// </summary>
    public bool StreamRequestBodies { get; init; }
}
