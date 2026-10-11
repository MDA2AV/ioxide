
namespace ioxide.httpclient;

/// <summary>
/// One origin (host + port) and how many ring-native connections to keep to it. One pool per
/// reactor - create from <c>Reactor.OnStart</c> so the connections ride that reactor's ring.
/// </summary>
public sealed record HttpClientOptions
{
    /// <summary>IPv4 literal. DNS resolution would block the reactor, so resolve up front and
    /// pass the address.</summary>
    public string Host { get; init; } = "127.0.0.1";

    public ushort Port { get; init; } = 80;

    /// <summary>Connections opened to the origin. Requests round-robin across them, one request
    /// in flight each, so this is the concurrency ceiling for this reactor.</summary>
    public int PoolSize { get; init; } = 4;

    /// <summary>Per-request ceiling for headers + body; a bigger response fails the request
    /// instead of growing the buffer without bound.</summary>
    public int MaxResponseBytes { get; init; } = 8 * 1024 * 1024;

    /// <summary>Per-connection send buffer; larger request bodies are sent straight from the
    /// caller's memory instead of being copied through it.</summary>
    public int SendBufferSize { get; init; } = 16 * 1024;

    /// <summary>Per-connection receive buffer; grows (up to MaxResponseBytes) when a response
    /// needs more.</summary>
    public int ReceiveBufferSize { get; init; } = 16 * 1024;

    /// <summary>
    /// TLS context for an <c>https://</c> origin, or null for cleartext. Shared across this pool's
    /// connections - it holds no per-connection state, and the caller owns its disposal.
    /// </summary>
    public TlsClientContext? Tls { get; init; }

    /// <summary>How long a request may wait for a free connection when every one is busy.</summary>
    public int AcquireTimeoutMs { get; init; } = 10_000;

    /// <summary>A pooled connection unused this long is closed, and the pool opens a fresh one in its
    /// place. 0 keeps it for as long as the origin does.</summary>
    public int IdleTimeoutMs { get; init; } = 135_000;

    /// <summary>How often the pool looks over its idle connections - for one the origin closed, or one
    /// past <see cref="IdleTimeoutMs"/> - and opens replacements. Rounded up to the reactor's
    /// 250 ms tick. A connection the origin closes between two looks can still fail a request.</summary>
    public int SweepIntervalMs { get; init; } = 250;
}
