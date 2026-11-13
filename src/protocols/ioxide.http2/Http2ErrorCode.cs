namespace ioxide.http2;

/// <summary>
/// The RFC 9113 section 7 codes a handler resets its stream with, through
/// <see cref="Http2ResponseWriter.AbortAsync"/>.
/// </summary>
public static class Http2ErrorCode
{
    /// <summary>INTERNAL_ERROR: the response failed. What an abort sends unless told otherwise.</summary>
    public const uint InternalError = 0x2;

    /// <summary>REFUSED_STREAM: the request was not processed at all, so the client may send it again (RFC 9113 8.7).</summary>
    public const uint RefusedStream = 0x7;

    /// <summary>CANCEL: the response is no longer wanted.</summary>
    public const uint Cancel = 0x8;
}
