namespace ioxide.nghttp3;

/// <summary>
/// The RFC 9114 section 8.1 codes a handler resets its stream with, through
/// <see cref="Nghttp3ResponseWriter.AbortAsync"/>.
/// </summary>
public static class Nghttp3ErrorCode
{
    /// <summary>H3_INTERNAL_ERROR: the response failed. What an abort sends unless told otherwise.</summary>
    public const ulong InternalError = 0x102;

    /// <summary>H3_REQUEST_REJECTED: the request was not processed at all, so the client may send it again (RFC 9114 4.1.1).</summary>
    public const ulong RequestRejected = 0x10b;

    /// <summary>H3_REQUEST_CANCELLED: the response is no longer wanted.</summary>
    public const ulong RequestCancelled = 0x10c;
}
