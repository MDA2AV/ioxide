namespace ioxide.nghttp3;

/// <summary>
/// Tunables for one <see cref="Nghttp3Connection"/>. The defaults match nghttp3's own (dynamic
/// table off) - the benchmark-lean profile; browser-facing deployments with fat repeated headers
/// (cookies, real user-agents) should enable the dynamic table.
/// </summary>
public sealed record Nghttp3Options
{
    internal static readonly Nghttp3Options Default = new();

    /// <summary>
    /// QPACK dynamic-table capacity in bytes, advertised to the peer in SETTINGS. 0 (default)
    /// disables it: peers must encode every header with static-table references and literals -
    /// simple and stateless, but repeated custom headers resend in full every request. A nonzero
    /// capacity (4096 is the conventional choice) lets peers compress repeated headers to
    /// ~2-byte table references at the cost of that much table memory per connection plus the
    /// insert/acknowledge bookkeeping (nghttp3 handles all of it).
    /// </summary>
    public long QpackDynamicTableCapacity { get; init; }

    /// <summary>
    /// How many of the peer's header blocks may wait on a not-yet-acknowledged dynamic-table
    /// insertion (bounds the QPACK-level head-of-line blocking a nonzero capacity introduces).
    /// 0 with a nonzero capacity means peers may insert but never send a blocked reference;
    /// 100 is a conventional value when the table is on.
    /// </summary>
    public long QpackBlockedStreams { get; init; }

    /// <summary>
    /// Dispatch each request as soon as its HEADERS are in, with the body arriving through
    /// <see cref="Nghttp3Request.BodyReader"/> instead of assembled into
    /// <see cref="Nghttp3Request.Body"/>.
    ///
    /// The trade is what memory is bound by. Buffered holds the whole body; streamed holds one
    /// flow-control window, because the stream is paced and credit goes back to the peer only as
    /// the handler reads.
    /// </summary>
    public bool StreamRequestBodies { get; init; }
}
